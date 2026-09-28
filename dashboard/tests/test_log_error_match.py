"""Tests for core/log_error_match.py: which log lines raise the Health
page's red error badge."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.log_error_match import is_error_log_line  # noqa: E402


class ErrorWordTests(unittest.TestCase):
    def assertFlags(self, *lines):
        for line in lines:
            with self.subTest(line=line):
                self.assertTrue(is_error_log_line(line))

    def assertQuiet(self, *lines):
        for line in lines:
            with self.subTest(line=line):
                self.assertFalse(is_error_log_line(line))

    def test_error_word_still_counts(self):
        self.assertFlags(
            "reverse_proxy-1  | 2026/09/28 [error] 7#7: upstream timed out",
            "es01  | ERROR: disk watermark exceeded",
        )

    def test_fail_and_fault_words_count_in_any_case(self):
        self.assertFlags(
            "mysql_production-1  | Connection FAILED for user root",
            "vector_inbound  | sink healthcheck failure",
            "honeypot_eshop_1-1  | Segmentation fault (core dumped)",
            "reverse_proxy-1  | lua entry thread aborted: Fail",
            "kibana  | Faulty plugin config",
            "suricata-1  | 3 faults while reading rules",
        )

    def test_identifiers_and_paths_do_not_count(self):
        self.assertQuiet(
            "reverse_proxy-1  | loaded default config",
            "suricata-1  | fail2ban integration disabled",
            "vector_inbound  | component_id=on_failure include=[\"/var/log/fail.log\"]",
            "vector_inbound  | component_id=nginx_error_in include=[\"/var/log/nginx/access.log\"]",
            "redis-1  | Ready to accept connections",
        )

    def test_kibana_quiet_level_is_trusted(self):
        self.assertQuiet(
            "kibana  | [2026-08-13T16:49:29.727+00:00][INFO ][plugins.notifications] "
            "Email Service Error: connector failed to load",
        )
        self.assertFlags(
            "kibana  | [2026-08-13T16:49:29.727+00:00][WARN ][plugins.x] request failed",
        )

    def test_ansi_codes_and_prefix_are_stripped(self):
        self.assertFlags("\x1b[36mreverse_proxy-1  |\x1b[0m auth failed")
        # The service name itself is not part of the message.
        self.assertQuiet("fail_service-1  | all good")


if __name__ == "__main__":
    unittest.main()
