"""Checks for the door checker - using pre-written knocker answers (no real websites)."""

import unittest

from qlock.azure_scan import find_web_doors
from qlock.doors import DoorError, inspect_door, read_certificate, read_handshake, read_protocol
from qlock.locks import GREEN, RED, judge_lock

# What openssl prints, trimmed to the lines we read.
HELLO_NEW_HANDSHAKE = """
Negotiated TLS1.3 group: X25519MLKEM768
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
"""
HELLO_OLD_HANDSHAKE = """
Peer Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
"""
HELLO_TLS12 = """
Server Temp Key: ECDH, prime256v1, 256 bits
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
    Protocol  : TLSv1.2
"""
CERT_RSA = """
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
"""
CERT_EC = """
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
"""

SITES = {
    "new.example": (HELLO_NEW_HANDSHAKE, CERT_EC),
    "old.example": (HELLO_OLD_HANDSHAKE, CERT_RSA),
    "tls12.example": (HELLO_TLS12, CERT_RSA),
    "offline.example": ("connect:errno=11001", ""),
}


def fake_openssl(args, stdin=""):
    """Stunt double for openssl."""
    if args[0] == "s_client":
        host = args[args.index("-servername") + 1]
        if host == "slow.example":
            raise DoorError("no answer within 20 seconds")
        return SITES[host][0]
    # args[0] == "x509": find which site's hello was passed in
    for hello, cert in SITES.values():
        if stdin == hello:
            return cert
    return ""


class TestReadingTheKnocker(unittest.TestCase):
    """These should pass right now."""

    def test_reads_new_handshake(self):
        self.assertEqual(read_handshake(HELLO_NEW_HANDSHAKE), ("X25519MLKEM768", 0))

    def test_reads_old_handshake(self):
        self.assertEqual(read_handshake(HELLO_OLD_HANDSHAKE), ("X25519", 253))

    def test_reads_tls12_handshake_curve(self):
        self.assertEqual(read_handshake(HELLO_TLS12), ("PRIME256V1", 256))

    def test_reads_protocol_both_styles(self):
        self.assertEqual(read_protocol(HELLO_OLD_HANDSHAKE), "TLSv1.3")
        self.assertEqual(read_protocol(HELLO_TLS12), "TLSv1.2")

    def test_reads_certificates(self):
        self.assertEqual(read_certificate(CERT_RSA), ("RSA", 2048))
        self.assertEqual(read_certificate(CERT_EC), ("EC", 256))

    def test_door_gives_two_locks(self):
        locks, notes = inspect_door("old.example", fake_openssl)
        self.assertEqual([(l.kind, l.size) for l in locks], [("X25519", 253), ("RSA", 2048)])
        self.assertEqual(notes, [])

    def test_tls12_door_gets_a_note(self):
        _, notes = inspect_door("tls12.example", fake_openssl)
        self.assertTrue(any("TLSv1.2" in n for n in notes))

    def test_offline_door_is_a_note_not_a_crash(self):
        locks, notes = inspect_door("offline.example", fake_openssl)
        self.assertEqual(locks, [])
        self.assertTrue(any("offline.example" in n for n in notes))

    def test_slow_door_is_a_note_not_a_crash(self):
        locks, notes = inspect_door("slow.example", fake_openssl)
        self.assertEqual(locks, [])
        self.assertTrue(any("20 seconds" in n for n in notes))

    def test_certificate_rules_still_work(self):
        self.assertEqual(judge_lock("RSA", 2048), RED)


class TestFindingDoorsInAzure(unittest.TestCase):
    def test_reads_directory_board(self):
        answers = {
            ("resource", "list", "--resource-type", "Microsoft.App/containerApps"): [{"id": "a1"}, {"id": "a2"}],
            ("resource", "show", "--ids", "a1", "a2"): [
                {"properties": {"configuration": {"ingress": {
                    "external": True, "fqdn": "a1.azure.example",
                    "customDomains": [{"name": "app.example.com"}]}}}},
                {"properties": {"configuration": {"ingress": {
                    "external": False, "fqdn": "a2.internal.example"}}}},
            ],
            ("resource", "list", "--resource-type", "Microsoft.Web/staticSites"): [{"id": "s1"}],
            ("resource", "show", "--ids", "s1"): {"properties": {
                "defaultHostname": "s1.azurestaticapps.example", "customDomains": None}},
        }
        hosts = find_web_doors(run=lambda args: answers[tuple(args)])
        self.assertEqual(hosts, ["app.example.com", "s1.azurestaticapps.example"])


class TestYourHandshakeRules(unittest.TestCase):
    """These turn from FAIL to OK once you add the handshake rules in qlock/locks.py."""

    def test_new_hybrid_handshake_is_green(self):
        self.assertEqual(judge_lock("X25519MLKEM768", 0), GREEN)

    def test_other_hybrid_handshake_is_green(self):
        self.assertEqual(judge_lock("SECP256R1MLKEM768", 0), GREEN)

    def test_x25519_is_red(self):
        self.assertEqual(judge_lock("X25519", 253), RED)

    def test_old_curve_handshake_is_red(self):
        self.assertEqual(judge_lock("PRIME256V1", 256), RED)

    def test_ed25519_id_card_is_red(self):
        self.assertEqual(judge_lock("ED25519", 0), RED)


if __name__ == "__main__":
    unittest.main()
