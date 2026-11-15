"""Checks for ranking locks by urgency (most urgent first)."""

import unittest

from qlock.doors import inspect_door
from qlock.locks import (AMBER, CERTIFICATE, CHECK, FIX_FIRST, GREEN, HANDSHAKE, KEY, OTHER,
                         PLAN_AHEAD, RED, SAFE, STORAGE, UNKNOWN, rank_urgency)
from qlock.report import build_report
from qlock.sample_data import DEMO_COMPANY, DEMO_LOCKS


class TestReportStillWorks(unittest.TestCase):
    """These should pass right now."""

    def test_report_has_urgency_summary(self):
        self.assertIn("BY URGENCY", build_report(DEMO_COMPANY, DEMO_LOCKS))

    def test_report_still_mentions_every_lock(self):
        report = build_report(DEMO_COMPANY, DEMO_LOCKS)
        for lock in DEMO_LOCKS:
            self.assertIn(lock.where, report)

    def test_door_without_handshake_gets_a_note(self):
        def fake_openssl(args, stdin=""):
            return "Protocol: TLSv1.3" if args[0] == "s_client" else ""

        _, notes = inspect_door("quiet.example", fake_openssl)
        self.assertTrue(any("handshake" in n for n in notes))


class TestYourUrgencyRules(unittest.TestCase):
    """These turn from FAIL to OK once you write rank_urgency() in qlock/locks.py."""

    def test_broken_handshake_is_most_urgent(self):
        self.assertEqual(rank_urgency(HANDSHAKE, RED), FIX_FIRST)

    def test_broken_vault_key_is_most_urgent(self):
        self.assertEqual(rank_urgency(KEY, RED), FIX_FIRST)

    def test_broken_id_card_can_wait(self):
        self.assertEqual(rank_urgency(CERTIFICATE, RED), PLAN_AHEAD)

    def test_weakened_lock_can_wait(self):
        self.assertEqual(rank_urgency(STORAGE, AMBER), PLAN_AHEAD)

    def test_safe_lock_is_safe(self):
        self.assertEqual(rank_urgency(HANDSHAKE, GREEN), SAFE)

    def test_safe_id_card_is_safe(self):
        self.assertEqual(rank_urgency(CERTIFICATE, GREEN), SAFE)

    def test_unknown_lock_needs_a_human(self):
        self.assertEqual(rank_urgency(OTHER, UNKNOWN), CHECK)

    def test_demo_report_puts_handshake_above_id_card(self):
        report = build_report(DEMO_COMPANY, DEMO_LOCKS)
        self.assertLess(report.index("Website handshake"), report.index("Website certificate"))


if __name__ == "__main__":
    unittest.main()
