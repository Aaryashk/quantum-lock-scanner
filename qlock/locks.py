"""What a "lock" is, and how we judge whether it is quantum-safe.

Plain-language picture:
    A company's cloud is a big building. Every place that protects data is a door
    with a lock. For each lock we write down three things on an index card:
        where - which door is it on?        e.g. "Key Vault: upi-signing-key"
        kind  - what type of lock is it?    e.g. "RSA", "AES", "ML-KEM"
        size  - how thick is the key?       measured in "bits"; bigger = harder to pick
        job   - what does the lock do?      e.g. "handshake", "certificate", "storage"
"""

from dataclasses import dataclass

# The four possible verdicts, like traffic lights.
RED = "RED"          # quantum computers can break it -> replace
AMBER = "AMBER"      # quantum computers weaken it -> upgrade when convenient
GREEN = "GREEN"      # already quantum-safe
UNKNOWN = "UNKNOWN"  # we don't recognise it -> a human should look

VERDICTS = (RED, AMBER, GREEN, UNKNOWN)

# What a lock does. This decides how urgent a RED lock is.
HANDSHAKE = "handshake"      # agrees the secret for a conversation (a spy can record it today)
CERTIFICATE = "certificate"  # the ID card that proves who you are talking to
KEY = "key"                  # a key in Key Vault: may lock data or only sign - we can't tell
STORAGE = "storage"          # files locked on a disk
OTHER = "other"              # anything else

# Urgency buckets, most urgent first. The report prints them in this order.
FIX_FIRST = "MOST URGENT"
PLAN_AHEAD = "PLAN AHEAD"
SAFE = "ALREADY SAFE"
CHECK = "CHECK BY HAND"
URGENCY_ORDER = (FIX_FIRST, PLAN_AHEAD, CHECK, SAFE)


@dataclass
class Lock:
    """One index card describing one lock."""

    where: str
    kind: str
    size: int
    job: str = OTHER


def judge_lock(kind: str, size: int) -> str:
    """Look at one lock and return RED, AMBER, GREEN or UNKNOWN."""
    kind = kind.upper()  # so "rsa" and "RSA" are treated the same

    # Public-key locks: quantum computers have a shortcut (Shor's algorithm) -> broken.
    if kind == "RSA":
        return RED
    if kind == "EC":
        return RED
    if kind == "AES" and size == 128:
        return AMBER
    if kind == "AES" and size == 256:
        return GREEN
    if kind == "ML-KEM":
        return GREEN
    if kind == "ML-DSA":
        return GREEN

    # Handshakes: how a browser and a website agree on a secret before talking.
    # Any hybrid with ML-KEM inside is safe; the old ones on their own are not.
    if "MLKEM" in kind:
        return GREEN
    # SSH's other hybrid (NTRU Prime + X25519): quantum-resistant, though not a NIST standard.
    if "SNTRUP" in kind:
        return GREEN
    # SSH's hybrid ID key (ML-DSA + Ed25519).
    if "MLDSA" in kind:
        return GREEN
    if kind in ("X25519", "X448", "PRIME256V1", "SECP256R1", "SECP384R1", "SECP521R1", "ECDH", "DH"):
        return RED
    if kind == "ED25519":
        return RED
    return UNKNOWN


def rank_urgency(job: str, verdict: str) -> str:
    """Put one lock in an urgency bucket: FIX_FIRST, PLAN_AHEAD, SAFE or CHECK.

    The key idea ("harvest now, decrypt later"): a spy can record today's traffic
    and crack it later. So a broken lock that protects *secrets in transit* is more
    urgent than a broken ID card, which can only be faked in the future.
    """
    if verdict == GREEN:
        return SAFE
    if verdict == RED and job in (HANDSHAKE, KEY):
        return FIX_FIRST
    if verdict == RED and job == CERTIFICATE:
        return PLAN_AHEAD
    if verdict == AMBER:
        return PLAN_AHEAD
    # Anything else (unknown, or a broken lock with an unclear job) -> a human decides.
    return CHECK
