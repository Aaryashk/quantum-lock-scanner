"""Checks for the VPN (IKEv2) door checker - using pre-written gateway answers."""

import socket
import struct
import unittest

from qlock.ike import (ADDKE1, COOKIE, ENCR, INVALID_KE_PAYLOAD, KE_METHOD, MAX_SENDS,
                       NO_PROPOSAL_CHOSEN, NOTIFY, SA, USE_PPK, _notify_body, _payload,
                       _proposal, build_hello, ike_group_family, inspect_vpn, read_reply)
from qlock.locks import GREEN, RED, UNKNOWN, judge_lock

# A REAL answer from a Cisco VPN gateway (Wireshark sample capture
# "ikev2_s2s_ipsec_vpn_aes_gcm.pcapng"). It picked AES-GCM-256, SHA-256 and group 19.
CISCO_REPLY = bytes.fromhex(
    "62f94c9887715a34f05534eef373dc1b2120222000000000000001762200002800000024010100030300000c01000014800e"
    "010003000008020000050000000804000013280000480013000015464f0c61c577a3765ef59cee34604a02aac46ca1c2d25e"
    "e25e3429b7a8d618865d1227f48ecd6db5bbc3869f26d31d5bba3a3f4658dddd833a07ddc63fc18f2b000044a46926fd58e1"
    "8077be46d8091789d544bcbe3c9764c77ed1ae73dee16553809f401902471b45eec289414dd75b60759b09e5702ba20e06a7"
    "7417a167f28851312b000017434953434f2d44454c4554452d524541534f4e2900003b434953434f28434f50595249474854"
    "2926436f7079726967687420286329203230303920436973636f2053797374656d732c20496e632e2900001c010040043c57"
    "c0f08a19b5f25dbf67b81226e5ae697dd5a72900001c0100400564f038668d775db0edfc2323b25b9657ba878eff2b000008"
    "0000402e000000144048b7d56ebce88525e7de7f00d6c2d3"
)


def gateway_reply(our_spi, payloads):
    """Build a gateway's answer: header + (type, body) payloads."""
    body = b""
    for i, (_, payload_body) in enumerate(payloads):
        next_type = payloads[i + 1][0] if i + 1 < len(payloads) else 0
        body += _payload(next_type, payload_body)
    header = struct.pack(">BBBBII", payloads[0][0], 0x20, 34, 0x20, 0, 28 + len(body))
    return our_spi + b"\x22" * 8 + header + body


def chose(group, addon=None):
    transforms = [(ENCR, 20, 256), (2, 5), (KE_METHOD, group)] + ([(ADDKE1, addon)] if addon else [])
    return (SA, _proposal(1, transforms, last=True))


def notify(kind, data=b""):
    return (NOTIFY, _notify_body(kind, data))


def wants(group):
    return lambda spi: gateway_reply(spi, [notify(INVALID_KE_PAYLOAD, struct.pack(">H", group))])


class FakeGateway:
    """Answers each message with the next reply in a script, and keeps what we sent."""

    def __init__(self, *script):
        self.script, self.sent = list(script), []

    def __call__(self, host, port, message):
        self.sent.append(message)
        reply = self.script.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply(message[:8]) if callable(reply) else reply


def offered_group(message):
    """Which group's key share did we send?"""
    cursor, next_type = 28, message[16]
    while next_type:
        following, _, length = struct.unpack(">BBH", message[cursor:cursor + 4])
        if next_type == 34:
            return struct.unpack(">H", message[cursor + 4:cursor + 6])[0]
        next_type, cursor = following, cursor + length


class TestReadingTheAnswer(unittest.TestCase):
    """These should pass right now."""

    def test_reads_a_real_cisco_answer(self):
        reply = read_reply(CISCO_REPLY, CISCO_REPLY[:8])
        self.assertEqual(reply.chosen, {ENCR: 20, 2: 5, KE_METHOD: 19})

    def test_answer_to_someone_else_is_ignored(self):
        locks, notes = inspect_vpn("vpn.example", 500, FakeGateway(CISCO_REPLY))
        self.assertEqual(locks, [])
        self.assertIn("not readable", notes[0])

    def test_real_cisco_answer_gives_one_handshake_lock(self):
        locks, notes = inspect_vpn("vpn.example", 500, FakeGateway(lambda spi: spi + CISCO_REPLY[8:]))
        self.assertEqual(len(locks), 1)
        self.assertEqual(locks[0].job, "handshake")
        self.assertIn("ECP-256", locks[0].where)
        self.assertIn("stranger", notes[0])

    def test_quantum_safe_addon_is_green(self):
        gateway = FakeGateway(lambda spi: gateway_reply(spi, [chose(31, addon=36)]))
        locks, _ = inspect_vpn("vpn.example", 500, gateway)
        self.assertIn("MLKEM768", locks[0].kind)
        self.assertEqual(judge_lock(locks[0].kind, locks[0].size), GREEN)

    def test_asks_again_with_the_group_the_gateway_wants(self):
        gateway = FakeGateway(wants(14), lambda spi: gateway_reply(spi, [chose(14)]))
        locks, _ = inspect_vpn("vpn.example", 500, gateway)
        self.assertEqual([offered_group(m) for m in gateway.sent], [31, 14])
        self.assertIn("MODP-2048", locks[0].where)

    def test_group_we_cannot_build_becomes_a_note(self):
        locks, notes = inspect_vpn("vpn.example", 500, FakeGateway(wants(19)))
        self.assertEqual(locks, [])
        self.assertIn("ECP-256", notes[0])

    def test_cookie_is_handed_back(self):
        gateway = FakeGateway(lambda spi: gateway_reply(spi, [notify(COOKIE, b"ticket-123")]),
                              lambda spi: gateway_reply(spi, [chose(31)]))
        locks, _ = inspect_vpn("vpn.example", 500, gateway)
        self.assertEqual(len(locks), 1)
        self.assertIn(b"ticket-123", gateway.sent[1][28:60])  # the cookie goes first

    def test_never_more_than_three_messages(self):
        gateway = FakeGateway(wants(14), wants(31), wants(14), wants(31))
        _, notes = inspect_vpn("vpn.example", 500, gateway)
        self.assertEqual(len(gateway.sent), MAX_SENDS)
        self.assertIn("gave up", notes[0])

    def test_no_match_is_a_note(self):
        gateway = FakeGateway(lambda spi: gateway_reply(spi, [notify(NO_PROPOSAL_CHOSEN)]))
        self.assertIn("turned down", inspect_vpn("vpn.example", 500, gateway)[1][0])

    def test_silence_and_closed_ports_are_notes(self):
        for reply in (None, ConnectionResetError("port closed"), socket.gaierror("no such name")):
            locks, notes = inspect_vpn("vpn.example", 500, FakeGateway(reply))
            self.assertEqual(locks, [])
            self.assertIn("vpn.example", notes[0])

    def test_post_quantum_preshared_key_is_mentioned(self):
        gateway = FakeGateway(lambda spi: gateway_reply(spi, [chose(31), notify(USE_PPK)]))
        notes = inspect_vpn("vpn.example", 500, gateway)[1]
        self.assertTrue(any("pre-shared key" in n for n in notes))

    def test_our_offer_is_well_formed_and_puts_quantum_safe_first(self):
        message = build_hello(b"\x01" * 8, 31)
        self.assertEqual((message[16], message[18], message[19]), (SA, 34, 0x08))
        self.assertEqual(struct.unpack(">I", message[24:28])[0], len(message))
        # Pretend it's a reply so our own reader walks it; the reader keeps the first offer.
        as_reply = message[:17] + bytes([0x20, 34, 0x20]) + message[20:]
        self.assertIn(ADDKE1, read_reply(as_reply, message[:8]).chosen)


class TestYourGroupNames(unittest.TestCase):
    """These turn from FAIL to OK once you write ike_group_family() in qlock/ike.py."""

    def test_curves(self):
        self.assertEqual(ike_group_family(31), "X25519")
        self.assertEqual(ike_group_family(32), "X448")

    def test_nist_curves(self):
        self.assertEqual(ike_group_family(19), "SECP256R1")
        self.assertEqual(ike_group_family(20), "SECP384R1")
        self.assertEqual(ike_group_family(21), "SECP521R1")

    def test_old_modp_groups(self):
        for group in (2, 5, 14, 15, 16):
            self.assertEqual(ike_group_family(group), "DH")

    def test_unknown_group_stays_unknown(self):
        self.assertEqual(judge_lock(ike_group_family(28), 0), UNKNOWN)  # brainpool: not in our rulebook

    def test_real_cisco_gateway_is_red_end_to_end(self):
        locks, _ = inspect_vpn("vpn.example", 500, FakeGateway(lambda spi: spi + CISCO_REPLY[8:]))
        self.assertEqual(judge_lock(locks[0].kind, locks[0].size), RED)


if __name__ == "__main__":
    unittest.main()
