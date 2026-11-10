"""What a "lock" is, and how we judge whether it is quantum-safe.

Plain-language picture:
    A company's cloud is a big building. Every place that protects data is a door
    with a lock. For each lock we write down three things on an index card:
        where - which door is it on?        e.g. "Key Vault: upi-signing-key"
        kind  - what type of lock is it?    e.g. "RSA", "AES", "ML-KEM"
        size  - how thick is the key?       measured in "bits"; bigger = harder to pick
"""

from dataclasses import dataclass

# The four possible verdicts, like traffic lights.
RED = "RED"          # quantum computers can break it -> replace
AMBER = "AMBER"      # quantum computers weaken it -> upgrade when convenient
GREEN = "GREEN"      # already quantum-safe
UNKNOWN = "UNKNOWN"  # we don't recognise it -> a human should look

VERDICTS = (RED, AMBER, GREEN, UNKNOWN)


@dataclass
class Lock:
    """One index card describing one lock."""

    where: str
    kind: str
    size: int


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
    if kind in ("X25519", "X448", "PRIME256V1", "SECP256R1", "SECP384R1", "ECDH", "DH"):
        return RED
    if kind == "ED25519":
        return RED
    return UNKNOWN
