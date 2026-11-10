"""The door checker: knocks on a website's door and reads two locks.

Every time a browser connects to a website, two things happen:
    1. The website shows its ID card (the "certificate"). The ID card has a lock type,
       e.g. RSA 2048. That's the same kind of lock we judge in Key Vault.
    2. Browser and website do a secret "handshake" to agree on a shared key for the
       conversation. Old handshakes (X25519, ECDH) can be broken by quantum computers;
       the new hybrid one (X25519MLKEM768) cannot.

We use the "openssl" tool to do the knocking. It must be version 3.5 or newer to know
the new handshake - otherwise we'd wrongly report every door as old (a false alarm).

Nothing is changed on the website. We only connect, look, and hang up - like a
visitor who rings the bell, glances at the name plate, and leaves.
"""

import os
import re
import shutil
import subprocess

from qlock.locks import Lock

# Handshakes the knocker offers, best first. Offering old ones too means a website that
# doesn't know the new handshake still answers (instead of looking like it's down).
OFFERED_HANDSHAKES = "X25519MLKEM768:X25519:secp256r1:secp384r1"

GIT_OPENSSL_PATHS = [
    r"C:\Program Files\Git\usr\bin\openssl.exe",
    r"C:\Program Files\Git\mingw64\bin\openssl.exe",
]

# Names openssl uses for ID-card locks -> names our rulebook knows.
CERT_ALGORITHMS = {"RSAENCRYPTION": "RSA", "ID-ECPUBLICKEY": "EC"}


class DoorError(Exception):
    """Couldn't reach the door, or the knocker tool is missing."""


# ---------- finding and running the knocker (openssl) ----------

def find_openssl() -> str | None:
    """Find an openssl that's new enough (3.5+). Returns its path, or None."""
    candidates = [shutil.which("openssl")] + GIT_OPENSSL_PATHS
    for path in candidates:
        if path and os.path.exists(path) and openssl_is_new_enough(path):
            return path
    return None


def openssl_is_new_enough(path: str) -> bool:
    try:
        out = subprocess.run([path, "version"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return False
    match = re.search(r"OpenSSL (\d+)\.(\d+)", out)
    return bool(match) and (int(match[1]), int(match[2])) >= (3, 5)


def make_runner(openssl_path: str):
    """Build the real messenger: runs one openssl command, returns everything it printed."""

    def run(args: list[str], stdin: str = "") -> str:
        try:
            result = subprocess.run(
                [openssl_path, *args],
                input=stdin,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
            )
        except subprocess.TimeoutExpired:
            raise DoorError("no answer within 20 seconds")
        return result.stdout + "\n" + result.stderr

    return run


# ---------- reading what the knocker saw ----------

def read_protocol(text: str) -> str | None:
    """Which connection version was used, e.g. 'TLSv1.3'."""
    match = re.search(r"Protocol\s*:\s*(\S+)", text)
    return match[1] if match else None


def read_handshake(text: str) -> tuple[str, int] | None:
    """Which handshake was used, and its size in bits (0 if not shown)."""
    match = re.search(r"Negotiated TLS1\.3 group:\s*(\S+)", text)
    if match:
        return match[1].upper(), 0
    match = re.search(r"(?:Server|Peer) Temp Key:\s*(.+)", text)
    if not match:
        return None
    parts = [p.strip() for p in match[1].split(",")]
    bits = re.search(r"(\d+) bits", match[1])
    size = int(bits[1]) if bits else 0
    # TLS 1.2 style: "ECDH, prime256v1, 256 bits" -> the curve name is the useful part.
    name = parts[1] if parts[0] in ("ECDH",) and len(parts) > 2 else parts[0]
    return name.upper(), size


def read_certificate(text: str) -> tuple[str, int] | None:
    """The ID card's lock type and size, from `openssl x509 -text` output."""
    match = re.search(r"Public Key Algorithm:\s*(\S+)", text)
    if not match:
        return None
    raw = match[1].upper()
    if raw.startswith("ML-DSA"):
        kind = "ML-DSA"
    else:
        kind = CERT_ALGORITHMS.get(raw, raw)
    bits = re.search(r"Public-Key:\s*\((\d+) bit\)", text)
    return kind, int(bits[1]) if bits else 0


# ---------- checking one door ----------

def inspect_door(host: str, run) -> tuple[list[Lock], list[str]]:
    """Knock on one website. Returns (locks found, notes for a human)."""
    locks: list[Lock] = []
    notes: list[str] = []
    try:
        hello = run(["s_client", "-connect", f"{host}:443", "-servername", host,
                     "-groups", OFFERED_HANDSHAKES])
    except DoorError as err:
        return [], [f"Couldn't reach door '{host}' ({err})."]

    protocol = read_protocol(hello)
    if not protocol:
        return [], [f"Couldn't connect to door '{host}' - it may be offline or blocked."]

    handshake = read_handshake(hello)
    if handshake:
        locks.append(Lock(where=f"Door '{host}': handshake", kind=handshake[0], size=handshake[1]))
    if protocol != "TLSv1.3":
        notes.append(f"Door '{host}' uses {protocol}. It can't use the new quantum-safe "
                     "handshake until it's upgraded to TLSv1.3.")

    certificate = read_certificate(run(["x509", "-noout", "-text"], stdin=hello))
    if certificate:
        locks.append(Lock(where=f"Door '{host}': ID card (certificate)",
                          kind=certificate[0], size=certificate[1]))
    return locks, notes


def inspect_doors(hosts: list[str], run, show_progress=print) -> tuple[list[Lock], list[str]]:
    locks: list[Lock] = []
    notes: list[str] = []
    for number, host in enumerate(hosts, start=1):
        show_progress(f"  checking door {number}/{len(hosts)}: {host}")
        door_locks, door_notes = inspect_door(host, run)
        locks += door_locks
        notes += door_notes
    return locks, notes
