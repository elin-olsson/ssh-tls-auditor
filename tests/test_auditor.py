"""
Unit tests for ssh-tls-auditor.

Tests cover pure logic functions that require no network access:
  - CIDR expansion
  - Hostname wildcard matching
  - IP detection
  - Legacy device fingerprinting
  - Grade computation
  - Watch-mode diff
  - CSV and JSON export format
"""

import csv
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import auditor


def _reset():
    """Reset all module-level state between tests."""
    with auditor._results_lock:
        auditor._results.clear()
    auditor._quiet  = False
    auditor._config = False
    auditor._thread_local.host     = "test.com"
    auditor._thread_local.category = "Test"
    if hasattr(auditor._thread_local, "counts"):
        del auditor._thread_local.counts
    if hasattr(auditor._thread_local, "output"):
        auditor._thread_local.output = None


# ── CIDR expansion ─────────────────────────────────────────────────────────────

class TestExpandTargets(unittest.TestCase):
    def test_hostname_passthrough(self):
        self.assertEqual(auditor._expand_targets(["example.com"]), ["example.com"])

    def test_single_ip_passthrough(self):
        self.assertEqual(auditor._expand_targets(["192.168.1.1"]), ["192.168.1.1"])

    def test_cidr_30(self):
        self.assertEqual(
            auditor._expand_targets(["192.168.1.0/30"]),
            ["192.168.1.1", "192.168.1.2"],
        )

    def test_cidr_32(self):
        self.assertEqual(auditor._expand_targets(["10.0.0.5/32"]), ["10.0.0.5"])

    def test_mixed(self):
        result = auditor._expand_targets(["example.com", "192.168.1.0/30"])
        self.assertEqual(result, ["example.com", "192.168.1.1", "192.168.1.2"])


# ── Hostname matching ──────────────────────────────────────────────────────────

class TestHostnameMatches(unittest.TestCase):
    def test_exact(self):
        self.assertTrue(auditor._hostname_matches("example.com", ["example.com"]))

    def test_no_match(self):
        self.assertFalse(auditor._hostname_matches("other.com", ["example.com"]))

    def test_wildcard_subdomain(self):
        self.assertTrue(auditor._hostname_matches("sub.example.com", ["*.example.com"]))

    def test_wildcard_does_not_match_root(self):
        self.assertFalse(auditor._hostname_matches("example.com", ["*.example.com"]))

    def test_wildcard_does_not_match_deep(self):
        self.assertFalse(auditor._hostname_matches("a.b.example.com", ["*.example.com"]))

    def test_case_insensitive(self):
        self.assertTrue(auditor._hostname_matches("EXAMPLE.COM", ["example.com"]))


# ── IP detection ───────────────────────────────────────────────────────────────

class TestIsIp(unittest.TestCase):
    def test_ipv4(self):
        self.assertTrue(auditor._is_ip("192.168.1.1"))

    def test_ipv6(self):
        self.assertTrue(auditor._is_ip("::1"))

    def test_hostname(self):
        self.assertFalse(auditor._is_ip("example.com"))

    def test_invalid(self):
        self.assertFalse(auditor._is_ip("not-an-ip"))


# ── Legacy device fingerprinting ───────────────────────────────────────────────

class TestMatchFingerprint(unittest.TestCase):
    def test_dropbear_banner(self):
        fp, method = auditor._match_fingerprint("SSH-2.0-dropbear_2019.78", [], [])
        self.assertIsNotNone(fp)
        self.assertEqual(fp["name"], "Dropbear SSH")
        self.assertEqual(method, "banner")

    def test_cisco_banner(self):
        fp, method = auditor._match_fingerprint(
            "SSH-2.0-Cisco-1.25", ["diffie-hellman-group14-sha1"], []
        )
        self.assertIsNotNone(fp)
        self.assertIn("Cisco", fp["name"])

    def test_no_match_modern_server(self):
        fp, _ = auditor._match_fingerprint(
            "SSH-2.0-OpenSSH_9.0",
            ["curve25519-sha256", "ecdh-sha2-nistp256"],
            ["aes256-gcm@openssh.com"],
        )
        self.assertIsNone(fp)

    def test_ilo_algorithm_fingerprint(self):
        fp, method = auditor._match_fingerprint(
            "SSH-2.0-OpenSSH_5.1",
            ["diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"],
            ["aes128-cbc", "3des-cbc"],
        )
        self.assertIsNotNone(fp)
        self.assertEqual(method, "fingerprint")

    def test_fortinet_banner(self):
        fp, method = auditor._match_fingerprint("SSH-2.0-FGSSH", [], [])
        self.assertIsNotNone(fp)
        self.assertIn("Fortinet", fp["name"])


# ── Grade computation ──────────────────────────────────────────────────────────

class TestComputeGrade(unittest.TestCase):
    def setUp(self):
        _reset()

    def tearDown(self):
        _reset()

    def test_grade_a_no_failures(self):
        auditor.passed("check")
        self.assertEqual(auditor.compute_grade("test.com"), "A")

    def test_grade_b_warnings_only(self):
        auditor.failed("check", severity="WARNING")
        self.assertEqual(auditor.compute_grade("test.com"), "B")

    def test_grade_c_one_critical(self):
        auditor.failed("check", severity="CRITICAL")
        self.assertEqual(auditor.compute_grade("test.com"), "C")

    def test_grade_d_two_criticals(self):
        auditor.failed("check1", severity="CRITICAL")
        auditor.failed("check2", severity="CRITICAL")
        self.assertEqual(auditor.compute_grade("test.com"), "D")

    def test_grade_d_three_criticals(self):
        for i in range(3):
            auditor.failed(f"check{i}", severity="CRITICAL")
        self.assertEqual(auditor.compute_grade("test.com"), "D")

    def test_grade_f_four_criticals(self):
        for i in range(4):
            auditor.failed(f"check{i}", severity="CRITICAL")
        self.assertEqual(auditor.compute_grade("test.com"), "F")

    def test_grade_isolated_by_host(self):
        # Failures on another host must not affect test.com's grade
        auditor._thread_local.host = "other.com"
        for i in range(4):
            auditor.failed(f"check{i}", severity="CRITICAL")
        auditor._thread_local.host = "test.com"
        self.assertEqual(auditor.compute_grade("test.com"), "A")


# ── Watch-mode diff ────────────────────────────────────────────────────────────

class TestDiffResults(unittest.TestCase):
    def _r(self, host="host", check="check", result="FAIL"):
        return {
            "host": host, "category": "Test", "check": check,
            "result": result, "detail": "", "remediation": "", "severity": "WARNING",
        }

    def test_new_failure(self):
        new, resolved = auditor._diff_results([], [self._r()])
        self.assertEqual(len(new), 1)
        self.assertEqual(len(resolved), 0)

    def test_resolved_failure(self):
        new, resolved = auditor._diff_results([self._r()], [])
        self.assertEqual(len(new), 0)
        self.assertEqual(len(resolved), 1)

    def test_no_change(self):
        r = self._r()
        new, resolved = auditor._diff_results([r], [r])
        self.assertEqual(len(new), 0)
        self.assertEqual(len(resolved), 0)

    def test_pass_results_ignored(self):
        prev = [self._r(result="PASS")]
        curr = [self._r(result="PASS")]
        new, resolved = auditor._diff_results(prev, curr)
        self.assertEqual(len(new), 0)
        self.assertEqual(len(resolved), 0)


# ── CSV export ─────────────────────────────────────────────────────────────────

class TestCsvExport(unittest.TestCase):
    def setUp(self):
        _reset()

    def tearDown(self):
        _reset()

    def test_severity_column_present(self):
        auditor.failed("check", "detail", "fix", severity="CRITICAL")
        with tempfile.NamedTemporaryFile(mode="r", suffix=".csv", delete=False) as f:
            path = f.name
        try:
            auditor.write_csv(path)
            with open(path) as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(rows[0]["severity"], "CRITICAL")
        finally:
            os.unlink(path)

    def test_all_fieldnames_present(self):
        auditor.passed("check")
        with tempfile.NamedTemporaryFile(mode="r", suffix=".csv", delete=False) as f:
            path = f.name
        try:
            auditor.write_csv(path)
            with open(path) as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames
            for field in ("host", "category", "check", "result", "severity", "detail", "remediation"):
                self.assertIn(field, fieldnames)
        finally:
            os.unlink(path)


# ── JSON export ────────────────────────────────────────────────────────────────

class TestJsonExport(unittest.TestCase):
    def setUp(self):
        _reset()

    def tearDown(self):
        _reset()

    def test_json_structure(self):
        auditor.failed("check", severity="WARNING")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            auditor.write_json(path)
            with open(path) as f:
                data = json.load(f)
            self.assertIn("generated", data)
            self.assertIn("results", data)
            self.assertEqual(data["results"][0]["severity"], "WARNING")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
