"""Checks for the SSH door checker - using pre-written server answers (no real servers)."""

import socket
import struct
import unittest

from qlock.locks import GREEN, RED, judge_lock
from qlock.ssh import (NeedMoreData, NotSSH, collect, inspect_ssh, normalize_ssh_name, pick,
                       read_hello_and_menu, without_markers)

# A real menu, as GitHub's SSH server sent it on 16 Nov 2026.
GITHUB_HANDSHAKES = ["mlkem768x25519-sha256", "sntrup761x25519-sha512",
                     "sntrup761x25519-sha512@openssh.com", "curve25519-sha256",
                     "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
                     "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256",
                     "kex-strict-s-v00@openssh.com"]
GITHUB_ID_KEYS = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
OLD_HANDSHAKES = ["ext-info-s", "curve25519-sha256", "diffie-hellman-group14-sha256"]
OLD_ID_KEYS = ["rsa-sha2-512", "ssh-rsa"]


def name_list(names):
    raw = ",".join(names).encode()
    return struct.pack(">I", len(raw)) + raw


def server_answer(handshakes, id_keys, before=b""):
    """Build the bytes an SSH server sends: hello line, then the menu packet."""
    message = bytes([20]) + b"\x00" * 16 + name_list(handshakes) + name_list(id_keys)
    message += b"".join(name_list([]) for _ in range(8)) + b"\x00" + b"\x00" * 4
    padding = 4
    packet = struct.pack(">IB", 1 + len(message) + padding, padding) + message + b"\x00" * padding
    return before + b"SSH-2.0-TestServer_1.0\r\n" + packet


def fake_runner(answers):
    def run(host, port):
        reply = answers[host]
        if isinstance(reply, Exception):
            raise reply
        return read_hello_and_menu(reply)
    return run


class TestReadingTheMenu(unittest.TestCase):
    """These should pass right now."""

    def test_reads_hello_and_both_lists(self):
        hello, handshakes, id_keys = read_hello_and_menu(server_answer(GITHUB_HANDSHAKES,
                                                                       GITHUB_ID_KEYS))
        self.assertEqual(hello, "SSH-2.0-TestServer_1.0")
        self.assertEqual(handshakes, GITHUB_HANDSHAKES)
        self.assertEqual(id_keys, GITHUB_ID_KEYS)

    def test_skips_text_lines_before_hello(self):
        data = server_answer(OLD_HANDSHAKES, OLD_ID_KEYS, before=b"Welcome!\r\nNo snooping.\r\n")
        self.assertEqual(read_hello_and_menu(data)[1], OLD_HANDSHAKES)

    def test_incomplete_answer_asks_for_more(self):
        data = server_answer(GITHUB_HANDSHAKES, GITHUB_ID_KEYS)
        with self.assertRaises(NeedMoreData):
            read_hello_and_menu(data[:40])

    def test_answer_arriving_in_small_pieces(self):
        data = server_answer(GITHUB_HANDSHAKES, GITHUB_ID_KEYS)
        pieces = iter([data[i:i + 7] for i in range(0, len(data), 7)])
        self.assertEqual(collect(lambda: next(pieces, b""))[1], GITHUB_HANDSHAKES)

    def test_web_server_is_not_ssh(self):
        with self.assertRaises(NotSSH):
            read_hello_and_menu(b"SSH-2.0-x\r\n" + b"\xff\xff\xff\xff" + b"junk")

    def test_old_ssh_version_is_not_read(self):
        with self.assertRaises(NotSSH):
            read_hello_and_menu(b"SSH-1.5-ancient\r\n")

    def test_markers_are_not_locks(self):
        self.assertNotIn("kex-strict-s-v00@openssh.com", without_markers(GITHUB_HANDSHAKES))
        self.assertNotIn("ext-info-s", without_markers(OLD_HANDSHAKES))

    def test_client_wish_list_decides(self):
        # The CLIENT's order wins, not the server's.
        self.assertEqual(pick(["b", "a"], ["a", "b"]), "b")
        self.assertIsNone(pick(["x"], ["a", "b"]))

    def test_unreachable_door_is_a_note(self):
        locks, notes = inspect_ssh("down.example", 22, fake_runner({"down.example": socket.timeout("timed out")}))
        self.assertEqual(locks, [])
        self.assertIn("down.example", notes[0])

    def test_door_gives_handshake_and_id_key(self):
        run = fake_runner({"new.example": server_answer(GITHUB_HANDSHAKES, GITHUB_ID_KEYS)})
        locks, _ = inspect_ssh("new.example", 22, run)
        self.assertEqual([l.job for l in locks], ["handshake", "certificate"])
        self.assertIn("mlkem768x25519-sha256", locks[0].where)


class TestYourSshNames(unittest.TestCase):
    """These turn from FAIL to OK once you write normalize_ssh_name() in qlock/ssh.py."""

    def test_curve25519(self):
        self.assertEqual(normalize_ssh_name("curve25519-sha256"), "X25519")
        self.assertEqual(normalize_ssh_name("curve25519-sha256@libssh.org"), "X25519")

    def test_nist_curve_handshakes(self):
        self.assertEqual(normalize_ssh_name("ecdh-sha2-nistp256"), "SECP256R1")
        self.assertEqual(normalize_ssh_name("ecdh-sha2-nistp384"), "SECP384R1")
        self.assertEqual(normalize_ssh_name("ecdh-sha2-nistp521"), "SECP521R1")

    def test_diffie_hellman(self):
        self.assertEqual(normalize_ssh_name("diffie-hellman-group14-sha256"), "DH")
        self.assertEqual(normalize_ssh_name("diffie-hellman-group-exchange-sha256"), "DH")

    def test_id_keys(self):
        self.assertEqual(normalize_ssh_name("ssh-ed25519"), "ED25519")
        self.assertEqual(normalize_ssh_name("rsa-sha2-512"), "RSA")
        self.assertEqual(normalize_ssh_name("ssh-rsa"), "RSA")
        self.assertEqual(normalize_ssh_name("ecdsa-sha2-nistp256"), "EC")

    def test_hybrids_keep_their_own_name(self):
        # Contains "25519" but must NOT become plain X25519 (that would turn it RED).
        self.assertEqual(normalize_ssh_name("mlkem768x25519-sha256"), "MLKEM768X25519-SHA256")
        self.assertEqual(normalize_ssh_name("sntrup761x25519-sha512"), "SNTRUP761X25519-SHA512")

    def test_old_ssh_door_is_red_end_to_end(self):
        run = fake_runner({"old.example": server_answer(OLD_HANDSHAKES, OLD_ID_KEYS)})
        locks, _ = inspect_ssh("old.example", 22, run)
        self.assertEqual([judge_lock(l.kind, l.size) for l in locks], [RED, RED])

    def test_new_ssh_door_handshake_is_green_end_to_end(self):
        run = fake_runner({"new.example": server_answer(GITHUB_HANDSHAKES, GITHUB_ID_KEYS)})
        locks, _ = inspect_ssh("new.example", 22, run)
        self.assertEqual(judge_lock(locks[0].kind, locks[0].size), GREEN)


if __name__ == "__main__":
    unittest.main()
