"""Writes the findings as a CBOM: a Cryptography Bill of Materials.

Plain-language picture:
    A food packet has an ingredients list in a standard format, so anyone can read
    it - a shopper, a regulator, an allergy app. A CBOM is the same thing for
    encryption: a standard list of every lock a company uses. Other security tools
    (dashboards, compliance checkers) can read it without knowing our scanner exists.

We use the CycloneDX 1.6 format (https://cyclonedx.org), the most widely used CBOM
standard. Each lock becomes one "component" of type "cryptographic-asset".
"""

import uuid
from datetime import datetime, timezone

from qlock import __version__
from qlock.locks import CERTIFICATE, HANDSHAKE, KEY, Lock, judge_lock, rank_urgency

# CycloneDX's names for what a lock does mathematically ("primitive").
# key-agree = two sides agree a secret; kem = the new way of doing that;
# signature = proves identity; pke = public-key encryption; block-cipher = e.g. AES.


def primitive_for(lock: Lock) -> str:
    kind = lock.kind.upper()
    if "MLKEM" in kind or kind == "ML-KEM" or "SNTRUP" in kind:
        return "kem"
    if kind == "ML-DSA" or "MLDSA" in kind or kind == "ED25519":
        return "signature"
    if kind in ("AES", "3DES"):
        return "block-cipher"
    if lock.job == HANDSHAKE:
        return "key-agree"
    if lock.job == CERTIFICATE:
        return "signature"
    if lock.job == KEY and kind == "RSA":
        return "pke"
    if lock.job == KEY and kind == "EC":
        return "signature"
    return "unknown"


def quantum_level(kind: str, size: int) -> int | None:
    """NIST's quantum security level for a lock: 0 (broken) up to 5 (strongest).

    Think of it as a star rating that every security team in the world understands.
    Return None if we don't know - then the CBOM simply leaves the rating out.
    """
    kind = kind.upper()
    # The hybrid handshake (e.g. X25519MLKEM768) is rated by its ML-KEM half.
    if "MLKEM1024" in kind:
        return 5
    if "MLKEM" in kind:
        return 3
    if kind == "ML-KEM":
        return {512: 1, 768: 3, 1024: 5}.get(size)
    if kind == "AES" and size == 128:
        return 1
    if kind == "AES" and size == 256:
        return 5
    if kind in ("RSA", "EC", "X25519", "X448", "PRIME256V1", "SECP256R1", "SECP384R1", "SECP521R1",
                "ECDH", "DH", "ED25519"):
        return 0
    return None


def lock_to_component(number: int, lock: Lock) -> dict:
    verdict = judge_lock(lock.kind, lock.size)
    algorithm = {"primitive": primitive_for(lock)}
    level = quantum_level(lock.kind, lock.size)
    if level is not None:
        algorithm["nistQuantumSecurityLevel"] = level
    name = f"{lock.kind}-{lock.size}" if lock.size else lock.kind
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"lock-{number}",
        "name": name,
        "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": algorithm},
        "properties": [
            {"name": "qlock:where", "value": lock.where},
            {"name": "qlock:job", "value": lock.job},
            {"name": "qlock:verdict", "value": verdict},
            {"name": "qlock:urgency", "value": rank_urgency(lock.job, verdict)},
        ],
    }


def build_cbom(company: str, locks: list[Lock]) -> dict:
    """Return the CBOM as a Python dictionary (save it with json.dump)."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "quantum-lock-scanner",
                                      "version": __version__}]},
            "component": {"type": "application", "name": company, "bom-ref": "scanned-system"},
        },
        "components": [lock_to_component(n, lock) for n, lock in enumerate(locks, start=1)],
    }
