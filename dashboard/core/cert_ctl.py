"""Certificate (re)generation, run directly on the host via `openssl`
(not by shelling out to gen_elk_certs.sh) so individual services can be
regenerated without rotating the whole CA -- the CA private key is
reused across runs unless a full CA rotation is explicitly requested,
since every SIEM service's cert is signed by the same CA and a full
rotation invalidates all of them at once.

Mirrors the exact behavior gen_elk_certs.sh already has (same subject
format, same SAN list for the "vector" service -- see that script's own
comments for why "vector" specifically needs SANs: it's reached via
several different hostnames depending on local-vs-remote and
single-host-testing-vs-real-deployment).
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from core.paths import EDGE_SSL_CERT_DIR, EDGE_VECTOR_CERT_DIR, SIEM_DIR

CA_DIR = SIEM_DIR / "certs" / "root-ca" / "certs"
CA_KEY = CA_DIR / "rootCA.key"
CA_CRT = CA_DIR / "rootCA.crt"
DAYS_VALID = "365"

VECTOR_SAN = "DNS:vector,DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1,IP:147.175.151.193"

SIEM_SERVICES = ["es01", "vector", "kibana", "vector-agent"]

SIEM_SERVICE_TARGET_DIRS = {
    # service -> [(dest_dir, dest_filename_stem), ...] -- mirrors
    # gen_elk_certs.sh's own copy section.
    "es01": [(SIEM_DIR / "elasticsearch" / "certs" / "es01", "es01")],
    "kibana": [
        (SIEM_DIR / "elasticsearch" / "certs" / "kibana", "kibana"),
        (SIEM_DIR / "kibana" / "certs" / "kibana", "kibana"),
    ],
    "vector": [(SIEM_DIR / "vector" / "certs" / "vector", "vector")],
    "vector-agent": [(SIEM_DIR / "vector" / "certs" / "vector-agent", "vector-agent")],
}

CA_COPY_DIRS = [
    SIEM_DIR / "elasticsearch" / "certs" / "ca",
    SIEM_DIR / "kibana" / "certs" / "ca",
    SIEM_DIR / "vector" / "certs" / "ca",
]


@dataclass
class CertGroup:
    id: str
    label: str
    description: str


CERT_GROUPS: list[CertGroup] = [
    CertGroup("siem-all", "SIEM: full CA + all service certs",
              "Rotates the CA itself (new root key) and re-issues every SIEM cert. "
              "Invalidates any previously-issued vector-agent client cert on the edge host -- "
              "re-copy it after running this."),
    CertGroup("siem-es01", "SIEM: Elasticsearch (es01) only", "Reuses the existing CA."),
    CertGroup("siem-kibana", "SIEM: Kibana only", "Reuses the existing CA."),
    CertGroup("siem-vector", "SIEM: Vector aggregator only", "Reuses the existing CA. Includes the SAN list."),
    CertGroup("siem-vector-agent", "SIEM: Vector-agent client cert only",
              "Reuses the existing CA. Re-copy to the edge host's vector/certs/ afterward."),
    CertGroup("edge-nginx", "Edge: nginx/reverse-proxy self-signed SSL cert",
              "ids/ssl_certificates/server.{crt,key} -- independent of the SIEM CA entirely."),
]


class CertError(RuntimeError):
    pass


def _run(argv: list[str]) -> None:
    result = subprocess.run(argv, capture_output=True, text=True)
    if result.returncode != 0:
        raise CertError(f"{' '.join(argv)}\n{result.stderr}")


def _ensure_ca(force_new: bool) -> None:
    CA_DIR.mkdir(parents=True, exist_ok=True)
    if force_new or not (CA_KEY.exists() and CA_CRT.exists()):
        _run(["openssl", "genpkey", "-algorithm", "RSA", "-out", str(CA_KEY)])
        _run([
            "openssl", "req", "-x509", "-new", "-nodes", "-key", str(CA_KEY),
            "-sha256", "-days", DAYS_VALID, "-out", str(CA_CRT),
            "-subj", "/C=US/ST=Example/L=City/O=MyOrg/CN=RootCA",
        ])


def _gen_service_cert(service: str) -> tuple[Path, Path]:
    """Returns (key_path, crt_path) of the freshly generated cert, signed
    by the current CA (call _ensure_ca first)."""
    work_dir = CA_DIR
    key_path = work_dir / f"{service}.key"
    crt_path = work_dir / f"{service}.crt"
    csr_path = work_dir / f"{service}.csr"

    _run(["openssl", "genpkey", "-algorithm", "RSA", "-out", str(key_path)])
    _run([
        "openssl", "req", "-new", "-key", str(key_path), "-out", str(csr_path),
        "-subj", f"/C=US/ST=Example/L=City/O=MyOrg/CN={service}",
    ])

    sign_argv = [
        "openssl", "x509", "-req", "-in", str(csr_path),
        "-CA", str(CA_CRT), "-CAkey", str(CA_KEY), "-CAcreateserial",
        "-out", str(crt_path), "-days", DAYS_VALID, "-sha256",
    ]
    if service == "vector":
        # Same reasoning as gen_elk_certs.sh: this is the one server cert
        # a client might reach through several different hostnames
        # (container name, host.docker.internal for single-host testing,
        # the real remote SIEM IP for production).
        extfile = work_dir / "vector.extfile"
        extfile.write_text(f"subjectAltName={VECTOR_SAN}\n")
        sign_argv += ["-extfile", str(extfile)]
        _run(sign_argv)
        extfile.unlink(missing_ok=True)
    else:
        _run(sign_argv)

    csr_path.unlink(missing_ok=True)
    return key_path, crt_path


def _copy_service_cert(service: str, key_path: Path, crt_path: Path) -> None:
    for dest_dir, stem in SIEM_SERVICE_TARGET_DIRS.get(service, []):
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(crt_path, dest_dir / f"{stem}.crt")
        shutil.copy2(key_path, dest_dir / f"{stem}.key")


def _copy_ca() -> None:
    for dest_dir in CA_COPY_DIRS:
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(CA_CRT, dest_dir / "ca.crt")


def _copy_vector_agent_to_edge() -> None:
    EDGE_VECTOR_CERT_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(CA_CRT, EDGE_VECTOR_CERT_DIR / "ca.crt")
    va_key = CA_DIR / "vector-agent.key"
    va_crt = CA_DIR / "vector-agent.crt"
    if va_key.exists():
        shutil.copy2(va_key, EDGE_VECTOR_CERT_DIR / "vector-agent.key")
    if va_crt.exists():
        shutil.copy2(va_crt, EDGE_VECTOR_CERT_DIR / "vector-agent.crt")


def _gen_edge_nginx_cert() -> None:
    EDGE_SSL_CERT_DIR.mkdir(parents=True, exist_ok=True)
    key_path = EDGE_SSL_CERT_DIR / "server.key"
    crt_path = EDGE_SSL_CERT_DIR / "server.crt"
    _run([
        "openssl", "req", "-x509", "-nodes", "-days", DAYS_VALID, "-newkey", "rsa:2048",
        "-keyout", str(key_path), "-out", str(crt_path),
        "-subj", "/C=US/ST=State/L=City/O=HoneypotOrg/CN=localhost",
    ])
    key_path.chmod(0o600)
    crt_path.chmod(0o644)


def regenerate(group_id: str, log=lambda msg: None) -> None:
    """log: callback invoked with progress strings (for wiring into a UI
    log view); regeneration itself is synchronous -- callers should run
    this from a background thread, not the UI thread (openssl calls are
    fast individually but there are several of them for "all")."""
    if group_id == "edge-nginx":
        log("Generating edge nginx self-signed SSL cert...")
        _gen_edge_nginx_cert()
        log(f"Done: {EDGE_SSL_CERT_DIR / 'server.crt'}")
        return

    if group_id == "siem-all":
        log("Rotating SIEM root CA...")
        _ensure_ca(force_new=True)
        _copy_ca()
        for service in SIEM_SERVICES:
            log(f"Generating {service} cert...")
            key_path, crt_path = _gen_service_cert(service)
            _copy_service_cert(service, key_path, crt_path)
        _copy_vector_agent_to_edge()
        log("Done. All SIEM certs rotated; vector-agent client cert re-copied to the edge host's vector/certs/.")
        return

    if group_id.startswith("siem-"):
        service = group_id[len("siem-"):]
        if service not in SIEM_SERVICES:
            raise CertError(f"Unknown service: {service}")
        log(f"Ensuring CA exists (reusing if present)...")
        _ensure_ca(force_new=False)
        _copy_ca()
        log(f"Generating {service} cert...")
        key_path, crt_path = _gen_service_cert(service)
        _copy_service_cert(service, key_path, crt_path)
        if service == "vector-agent":
            _copy_vector_agent_to_edge()
            log("Done. Re-copied vector-agent client cert to the edge host's vector/certs/.")
        else:
            log(f"Done: {crt_path}")
        return

    raise CertError(f"Unknown cert group: {group_id}")
