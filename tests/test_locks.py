"""Automatic checks - like a teacher's answer key.

Run them with:  python -m unittest -v
"""

import unittest

from qlock.locks import AMBER, GREEN, RED, UNKNOWN, Lock, judge_lock
from qlock.report import build_report
from qlock.sample_data import DEMO_COMPANY, DEMO_LOCKS


class TestReportWorks(unittest.TestCase):
    """These should pass right now."""

    def test_rsa_is_red(self):
        self.assertEqual(judge_lock("RSA", 2048), RED)

    def test_lowercase_works_too(self):
        self.assertEqual(judge_lock("rsa", 2048), RED)

    def test_report_mentions_every_lock(self):
        report = build_report(DEMO_COMPANY, DEMO_LOCKS)
        for lock in DEMO_LOCKS:
            self.assertIn(lock.where, report)

    def test_report_has_summary(self):
        report = build_report("Test Co", [Lock("door 1", "RSA", 2048)])
        self.assertIn("SUMMARY (1 locks found)", report)


class TestYourJudgingRules(unittest.TestCase):
    """These turn from FAIL to OK once you finish judge_lock() in qlock/locks.py."""

    def test_ec_is_red(self):
        self.assertEqual(judge_lock("EC", 256), RED)

    def test_aes_128_is_amber(self):
        self.assertEqual(judge_lock("AES", 128), AMBER)

    def test_aes_256_is_green(self):
        self.assertEqual(judge_lock("AES", 256), GREEN)

    def test_ml_kem_is_green(self):
        self.assertEqual(judge_lock("ML-KEM", 768), GREEN)

    def test_ml_dsa_is_green(self):
        self.assertEqual(judge_lock("ML-DSA", 65), GREEN)

    def test_something_strange_is_unknown(self):
        self.assertEqual(judge_lock("MYSTERY-LOCK", 99), UNKNOWN)


if __name__ == "__main__":
    unittest.main()
