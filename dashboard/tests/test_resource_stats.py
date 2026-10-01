"""Tests for core/resource_stats.py's cgroup sampler: it must only trust a
PID docker reports when that PID really is the container on this host.

    cd dashboard && python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import resource_stats as rs  # noqa: E402

CID = "3f2a" + "0" * 56 + "beef"


class CgroupMatchTests(unittest.TestCase):
    def test_systemd_driver_v2(self):
        self.assertTrue(rs.cgroup_matches_container(
            f"0::/system.slice/docker-{CID}.scope\n", CID))

    def test_cgroupfs_driver_v1(self):
        cg = f"12:memory:/docker/{CID}\n11:cpu,cpuacct:/docker/{CID}\n"
        self.assertTrue(rs.cgroup_matches_container(cg, CID))

    def test_rootless_and_podman(self):
        self.assertTrue(rs.cgroup_matches_container(
            f"0::/user.slice/user-1000.slice/user@1000.service/user.slice/docker-{CID}.scope", CID))
        self.assertTrue(rs.cgroup_matches_container(
            f"0::/machine.slice/libpod-{CID}.scope/container", CID))

    def test_unrelated_host_process(self):
        # What a Docker Desktop VM PID tends to land on: some host process in
        # the user's session.
        self.assertFalse(rs.cgroup_matches_container(
            "0::/user.slice/user-1000.slice/session-2.scope\n", CID))

    def test_short_or_empty_id_never_matches(self):
        self.assertFalse(rs.cgroup_matches_container("0::/", ""))
        self.assertFalse(rs.cgroup_matches_container("0::/docker/abc", "abc"))


class _FakeTarget:
    is_remote = False

    def ps(self, timeout=10):
        return [{"ID": CID[:12], "Service": "reverse_proxy", "State": "running"}]


class FastSamplerForeignPidTests(unittest.TestCase):
    def _sampler(self, proc_cgroup: str | None):
        def fake_open(path, *a, **kw):
            if path == "/proc/4242/cgroup":
                if proc_cgroup is None:
                    raise FileNotFoundError(path)
                return mock.mock_open(read_data=proc_cgroup)()
            raise FileNotFoundError(path)

        with mock.patch.object(rs, "_run", return_value=f"{CID} 4242\n"), \
                mock.patch("builtins.open", side_effect=fake_open), \
                mock.patch("sys.stderr"):
            return rs.FastSampler(_FakeTarget())

    def test_pid_of_another_process_disables_sampler(self):
        s = self._sampler("0::/user.slice/user-1000.slice/session-2.scope\n")
        self.assertFalse(s.available)
        self.assertTrue(s.foreign)

    def test_missing_pid_disables_sampler(self):
        s = self._sampler(None)
        self.assertFalse(s.available)
        self.assertTrue(s.foreign)

    def test_foreign_sampler_ignores_later_refreshes(self):
        s = self._sampler(None)
        with mock.patch.object(rs, "_run") as run:
            s.refresh(_FakeTarget().ps())
        run.assert_not_called()
        self.assertFalse(s.available)

    def test_matching_cgroup_is_not_foreign(self):
        # Stat files don't exist in the test sandbox, so it isn't available
        # either -- but it must not be written off as foreign.
        s = self._sampler(f"0::/system.slice/docker-{CID}.scope\n")
        self.assertFalse(s.foreign)


if __name__ == "__main__":
    unittest.main()
