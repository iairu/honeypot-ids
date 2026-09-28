"""Tests for the ids stack's honeypot layer choice (core/honeypot_layer.py):
which compose file each layer uses, that every `docker compose` call follows
it, and that the database proxy layer's override files line up.

    cd dashboard && python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

DASHBOARD_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = DASHBOARD_DIR.parent
IDS_DIR = REPO_ROOT / "ids"
sys.path.insert(0, str(DASHBOARD_DIR))

from core import honeypot_layer  # noqa: E402
from core.docker_ctl import Target  # noqa: E402
from core.exploits import EXPLOIT_PRESETS  # noqa: E402
from core.state import AppState  # noqa: E402


class LayerSelectionTests(unittest.TestCase):
    def tearDown(self):
        honeypot_layer.set_active(honeypot_layer.DEFAULT_LAYER)

    def test_default_is_reverse_proxy(self):
        self.assertEqual(AppState().honeypot_layer, "reverse_proxy")
        self.assertEqual(honeypot_layer.DEFAULT_LAYER, "reverse_proxy")
        self.assertIn("Default, Recommended", honeypot_layer.REVERSE_PROXY.label)

    def test_unknown_layer_falls_back_to_default(self):
        self.assertEqual(honeypot_layer.set_active("bogus").id, "reverse_proxy")

    def test_both_compose_files_exist(self):
        for layer in honeypot_layer.LAYERS.values():
            with self.subTest(layer=layer.id):
                self.assertTrue(layer.compose_path.is_file(), layer.compose_path)

    def test_reverse_proxy_layer_uses_default_compose_file(self):
        honeypot_layer.set_active("reverse_proxy")
        argv, _ = Target("edge").build("up", "-d")
        self.assertNotIn("-f", argv)
        argv, _ = Target("edge").build_shell("docker compose ps")
        self.assertNotIn("COMPOSE_FILE", argv[-1])
        self.assertEqual(Target("edge").label, "ids (local)")

    def test_database_layer_passes_its_compose_file_everywhere(self):
        honeypot_layer.set_active("database")
        argv, cwd = Target("edge").build("up", "-d")
        self.assertEqual(argv[:4], ["docker", "compose", "-f", "docker-compose.db-proxy.yml"])
        self.assertEqual(Path(cwd), IDS_DIR)
        argv, _ = Target("edge").build_shell("docker compose ps -q")
        self.assertTrue(argv[-1].startswith("export COMPOSE_FILE=docker-compose.db-proxy.yml; "))
        self.assertIn("database proxy level", Target("edge").label)

    def test_siem_never_follows_the_layer(self):
        honeypot_layer.set_active("database")
        argv, _ = Target("siem").build("ps")
        self.assertNotIn("-f", argv)
        argv, _ = Target("siem").build_shell("docker compose ps")
        self.assertNotIn("COMPOSE_FILE", argv[-1])


class DbProxyOverlayTests(unittest.TestCase):
    """docker-compose.db-proxy.yml bind-mounts files from ids/db_proxy/ over
    the shared copies. Each source must exist, and so must the shared file it
    replaces: mounting a file onto a missing path inside a bind-mounted
    directory makes Docker create an empty placeholder in the host checkout."""

    def _overlay_mounts(self):
        text = (IDS_DIR / "docker-compose.db-proxy.yml").read_text()
        return re.findall(r"^\s*- \./(db_proxy/\S+?):(\S+?)(?::ro)?$", text, re.M)

    def test_overlays_are_mounted(self):
        self.assertGreaterEqual(len(self._overlay_mounts()), 6)

    def test_every_overlay_has_a_source_and_a_shared_original(self):
        for src, _dst in self._overlay_mounts():
            with self.subTest(src=src):
                self.assertTrue((IDS_DIR / src).is_file(), src)
                shared = IDS_DIR / src.removeprefix("db_proxy/")
                self.assertTrue(shared.is_file(), f"{shared} missing: nothing to overlay")

    def test_db_dropin_is_gated_on_the_layer(self):
        # Shared with the default layer (and its pool copies), so it must stay
        # inert there.
        for rel in ("production_eshop_files/wp-content/db.php",
                    "production_eshop_files/wp-content/mu-plugins/honeypot-db-backend-header.php"):
            with self.subTest(file=rel):
                self.assertIn("getenv( 'HONEYPOT_LAYER' ) !== 'database'",
                              (IDS_DIR / rel).read_text())
        self.assertIn("HONEYPOT_LAYER=database",
                      (IDS_DIR / "docker-compose.db-proxy.yml").read_text())
        self.assertNotIn("HONEYPOT_LAYER", (IDS_DIR / "docker-compose.yml").read_text())

    def test_some_presets_are_marked_not_db_isolatable(self):
        blocked = [p for p in EXPLOIT_PRESETS if not p.db_isolated]
        self.assertTrue(blocked)
        for preset in blocked:
            with self.subTest(cve=preset.cve):
                self.assertTrue(preset.coverage_note)


if __name__ == "__main__":
    unittest.main()
