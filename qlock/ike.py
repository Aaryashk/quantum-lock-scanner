"""The VPN door checker (IKEv2): which handshake lock a VPN gateway agrees to use.

Plain-language picture:
    A VPN tunnel is a private pipe between two offices (or two phone towers).
    Before the pipe opens, the two ends agree on locks, using a protocol called IKEv2.

    Unlike SSH, the gateway never shows a menu. It works like an auction the other
    way round: WE hand over a list of offers, and the gateway quietly picks the one
    it likes. So we make a wide offer - new quantum-safe add-ons first, old locks
    after - and read which one it picked.

What we send: one "let's start" message (IKE_SA_INIT), at most three times.
We stop as soon as the gateway answers. We never prove who we are, so no tunnel
opens. But unlike the other checks, the gateway may write a short "someone started
and gave up" line in its logs. Only check VPN gateways you own or may test.

Numbers below come from IANA's IKEv2 registry (checked 17 Nov 2026).
"""

import os
import socket
import struct
from dataclasses import dataclass, field

from qlock.locks import HANDSHAKE, Lock

IKE_PORT = 500
IKE_SA_INIT = 34
SA, KE, NONCE, NOTIFY = 33, 34, 40, 41  # payload types

# Transform types (what each line of an offer is about)
ENCR, PRF, INTEG, KE_METHOD, ADDKE1 = 1, 2, 3, 4, 6

# Notify numbers: messages the gateway can send back
NO_PROPOSAL_CHOSEN = 14
INVALID_KE_PAYLOAD = 17
COOKIE = 16390
USE_PPK = 16435                          # "I can mix in a post-quantum pre-shared key" (RFC 8784)
INTERMEDIATE_EXCHANGE_SUPPORTED = 16438  # needed for the ML-KEM add-on (RFC 9242 / 9370)

# The quantum-safe add-on ("Additional Key Exchange"), by IANA number.
MLKEM_ADDONS = {35: 512, 36: 768, 37: 1024}

# Old (classical) handshake groups, by IANA number - names for people to read.
GROUP_LABELS = {2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048", 15: "MODP-3072",
                16: "MODP-4096", 19: "ECP-256", 20: "ECP-384", 21: "ECP-521",
                31: "Curve25519", 32: "Curve448"}
OFFERED_GROUPS = [31, 32, 19, 20, 21, 14, 15, 16, 5, 2]

# Groups we can make a believable key share for, with the share's length in bytes.
# (Any 32 bytes is a valid Curve25519 key; the curves 19-21 need real maths, so we skip them.)
KEY_SHARE_BYTES = {31: 32, 32: 56, 2: 128, 5: 192, 14: 256, 15: 384, 16: 512}

MAX_SENDS = 3


# ---------- translating group numbers into our rulebook's names ----------

def ike_group_family(number: int) -> str:
    """Turn an IKEv2 group number into the family name our rulebook (judge_lock) knows."""
    return {31: "X25519", 32: "X448",
            19: "SECP256R1", 20: "SECP384R1", 21: "SECP521R1",
            2: "DH", 5: "DH", 14: "DH", 15: "DH", 16: "DH"}.get(number, f"IKE-GROUP-{number}")


# ---------- building the offer (pure: values in, bytes out) ----------

def _transform(kind: int, number: int, key_bits: int | None = None, last: bool = False) -> bytes:
    attributes = struct.pack(">HH", 0x800E, key_bits) if key_bits else b""  # 14 = key length
    return struct.pack(">BBHBBH", 0 if last else 3, 0, 8 + len(attributes), kind, 0, number) + attributes


def _proposal(number: int, transforms: list[tuple], last: bool) -> bytes:
    body = b"".join(_transform(*t, last=(i == len(transforms) - 1)) for i, t in enumerate(transforms))
    return struct.pack(">BBHBBBB", 0 if last else 2, 0, 8 + len(body), number, 1, 0, len(transforms)) + body


def build_offer() -> list[list[tuple]]:
    """Our offers, best first. Each offer is a list of (transform type, number[, key bits])."""
    prfs = [(PRF, 5), (PRF, 6), (PRF, 7), (PRF, 2)]
    groups = [(KE_METHOD, g) for g in OFFERED_GROUPS]
    gcm = [(ENCR, 20, 256), (ENCR, 20, 128)]                       # AES-GCM (no INTEG line)
    cbc = [(ENCR, 12, 256), (ENCR, 12, 128), (INTEG, 12), (INTEG, 13), (INTEG, 14), (INTEG, 2)]
    addons = [(ADDKE1, n) for n in (36, 37, 35)]
    # Offers with the quantum-safe add-on go first. A gateway that doesn't know
    # add-ons must skip those whole offers and fall through to the classical ones.
    return [gcm + prfs + groups + addons, cbc + prfs + groups + addons,
            gcm + prfs + groups, cbc + prfs + groups]


def _payload(next_type: int, body: bytes) -> bytes:
    return struct.pack(">BBH", next_type, 0, 4 + len(body)) + body


def _notify_body(kind: int, data: bytes = b"") -> bytes:
    return struct.pack(">BBH", 0, 0, kind) + data


def key_share(group: int) -> bytes:
    share = bytearray(os.urandom(KEY_SHARE_BYTES[group]))
    if group not in (31, 32):  # MODP: keep the number below the group's prime, and not tiny
        share[0] = (share[0] & 0x7F) | 0x40
    return bytes(share)


def build_hello(our_spi: bytes, group: int, cookie: bytes | None = None) -> bytes:
    """The IKE_SA_INIT message: [cookie] offers, key share, random nonce, two notes."""
    offers = build_offer()
    sa_body = b"".join(_proposal(i + 1, offer, last=(i == len(offers) - 1))
                       for i, offer in enumerate(offers))
    parts = []  # (type, body)
    if cookie is not None:
        parts.append((NOTIFY, _notify_body(COOKIE, cookie)))  # a cookie must come first
    parts += [(SA, sa_body), (KE, struct.pack(">HH", group, 0) + key_share(group)),
              (NONCE, os.urandom(32)),
              (NOTIFY, _notify_body(INTERMEDIATE_EXCHANGE_SUPPORTED)),
              (NOTIFY, _notify_body(USE_PPK))]
    body = b""
    for i, (_, payload_body) in enumerate(parts):
        next_type = parts[i + 1][0] if i + 1 < len(parts) else 0
        body += _payload(next_type, payload_body)
    header = our_spi + b"\x00" * 8 + struct.pack(">BBBBII", parts[0][0], 0x20, IKE_SA_INIT,
                                                 0x08, 0, 28 + len(body))
    return header + body


# ---------- reading the answer (pure: bytes in, facts out) ----------

class NotIKE(Exception):
    """The answer isn't an IKEv2 reply to our message."""


@dataclass
class Reply:
    chosen: dict[int, int] = field(default_factory=dict)   # transform type -> picked number
    notes: dict[int, bytes] = field(default_factory=dict)  # notify number -> its data


def read_reply(data: bytes, our_spi: bytes) -> Reply:
    if len(data) < 28 or data[:8] != our_spi:
        raise NotIKE("not an answer to our message")
    next_type, version, exchange, flags = data[16:20]
    if version >> 4 != 2 or exchange != IKE_SA_INIT or not flags & 0x20:
        raise NotIKE("not an IKEv2 start-up reply")
    reply, cursor = Reply(), 28
    while next_type:
        if cursor + 4 > len(data):
            raise NotIKE("reply cut short")
        following, _, length = struct.unpack(">BBH", data[cursor:cursor + 4])
        if length < 4 or cursor + length > len(data):
            raise NotIKE("strange payload size")
        body = data[cursor + 4:cursor + length]
        if next_type == SA:
            reply.chosen = _read_chosen(body)
        elif next_type == NOTIFY and len(body) >= 4:
            spi_size, kind = body[1], struct.unpack(">H", body[2:4])[0]
            reply.notes[kind] = body[4 + spi_size:]
        # Anything else (vendor IDs, NAT checks, nonces, key shares) we just step over.
        next_type, cursor = following, cursor + length
    return reply


def _read_chosen(sa_body: bytes) -> dict[int, int]:
    """The gateway answers with exactly one offer: the one it picked."""
    if len(sa_body) < 8:
        raise NotIKE("empty offer in reply")
    count, cursor, chosen = sa_body[7], 8 + sa_body[6], {}  # skip the SPI, if any
    for _ in range(count):
        if cursor + 8 > len(sa_body):
            raise NotIKE("offer cut short")
        length, kind, _, number = struct.unpack(">HBBH", sa_body[cursor + 2:cursor + 8])
        chosen.setdefault(kind, number)
        cursor += max(length, 8)
    return chosen


# ---------- talking to the gateway ----------

def make_vpn_runner(timeout: float = 4):
    """The real messenger: send one UDP message, wait for the matching answer."""

    def send(host: str, port: int, message: bytes) -> bytes | None:
        family, kind, proto, _, address = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
        with socket.socket(family, kind, proto) as sock:
            sock.settimeout(timeout)
            sock.sendto(message, address)
            try:
                while True:
                    data, _ = sock.recvfrom(65535)
                    if data[:8] == message[:8]:
                        return data
            except socket.timeout:
                return None  # silence: many gateways ignore strangers

    return send


def inspect_vpn(host: str, port: int, send) -> tuple[list[Lock], list[str]]:
    """Check one VPN door. Returns (locks found, notes for a human)."""
    door = f"VPN '{host}'" if port == IKE_PORT else f"VPN '{host}:{port}'"
    our_spi, group, cookie = os.urandom(8), 31, None
    for _ in range(MAX_SENDS):
        try:
            answer = send(host, port, build_hello(our_spi, group, cookie))
        except OSError as err:  # includes "port closed" (ConnectionResetError on Windows)
            return [], [f"Couldn't reach {door} ({err.__class__.__name__}: {err})."]
        if answer is None:
            return [], [f"{door}: no answer. Either it isn't a VPN gateway, or it ignores "
                        "strangers (many do). Check by hand."]
        try:
            reply = read_reply(answer, our_spi)
        except NotIKE as err:
            return [], [f"{door}: not readable as IKEv2 ({err})."]

        if COOKIE in reply.notes and cookie is None:
            cookie = reply.notes[COOKIE]  # "busy - come back with this ticket"
            continue
        if INVALID_KE_PAYLOAD in reply.notes and len(reply.notes[INVALID_KE_PAYLOAD]) >= 2:
            wanted = struct.unpack(">H", reply.notes[INVALID_KE_PAYLOAD][:2])[0]
            if wanted in KEY_SHARE_BYTES and wanted != group:
                group = wanted  # "I'd rather use this group" - ask again with it
                continue
            label = GROUP_LABELS.get(wanted, f"group {wanted}")
            return [], [f"{door} wants the old handshake {label}, which the scanner can't "
                        "finish yet, so we couldn't see whether it adds a quantum-safe "
                        "add-on. Check by hand."]
        if NO_PROPOSAL_CHOSEN in reply.notes:
            return [], [f"{door} turned down every modern offer. It may only speak very "
                        "old settings. Check by hand."]
        if KE_METHOD in reply.chosen:
            return _verdict(door, reply)
        errors = [n for n in reply.notes if n < 16384]
        return [], [f"{door} answered with error {errors or '?'} and no choice. Check by hand."]
    return [], [f"{door}: gave up after {MAX_SENDS} tries. Check by hand."]


def _verdict(door: str, reply: Reply) -> tuple[list[Lock], list[str]]:
    group = reply.chosen[KE_METHOD]
    label = GROUP_LABELS.get(group, f"group {group}")
    kind = ike_group_family(group)
    addon = MLKEM_ADDONS.get(reply.chosen.get(ADDKE1, 0))
    if addon:
        kind, label = f"{kind}+MLKEM{addon}", f"{label} + ML-KEM-{addon}"
    lock = Lock(where=f"{door}: handshake ({label})", kind=kind, size=0, job=HANDSHAKE)
    notes = [f"{door}: this is what a stranger is offered. Partner offices with their own "
             "settings may get a different lock. The gateway's ID card is only shown after "
             "logging in, so it isn't checked."]
    if USE_PPK in reply.notes and not addon:
        notes.append(f"{door} can mix in a post-quantum pre-shared key (RFC 8784). If its "
                     "partners use one, their tunnels are protected despite the old handshake.")
    return [lock], notes


def inspect_vpn_doors(addresses: list[str], send, show_progress=print):
    """`addresses` look like 'host' or 'host:port'."""
    locks, notes = [], []
    for number, address in enumerate(addresses, start=1):
        host, _, port = address.partition(":")
        show_progress(f"  checking VPN door {number}/{len(addresses)}: {address}")
        door_locks, door_notes = inspect_vpn(host, int(port or IKE_PORT), send)
        locks += door_locks
        notes += door_notes
    return locks, notes
