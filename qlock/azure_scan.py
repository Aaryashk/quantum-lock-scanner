"""The inspector's walk through an Azure account.

It visits three kinds of rooms:
    1. Key Vaults - the safe rooms, holding keys and certificates
    2. Storage accounts - the filing rooms, whose files are locked with AES
It reads the label on every lock and fills in one index card (a Lock) for each.

Azure's answers are long forms. The small "translator" functions below copy only
the three things we care about - where, kind, size - onto our index cards.
"""

import base64

from qlock.azure_cli import AzureError, run_az
from qlock.locks import Lock

# Elliptic-curve ("EC") locks are named by their curve. The number is the key size.
CURVE_SIZES = {"P-256": 256, "P-256K": 256, "P-384": 384, "P-521": 521}


def normalize_key_type(kty: str) -> str:
    """Turn Azure's name for a lock type into the simple name our rulebook knows."""
    kty = (kty or "").upper()

    # "-HSM" only means the key lives in a tamper-proof box; the lock itself is the same.
    # Azure calls AES keys "oct" (octet = byte).
    if kty == "RSA-HSM":
        return "RSA"
    if kty == "EC-HSM":
        return "EC"
    if kty == "OCT":
        return "AES"
    if kty == "OCT-HSM":
        return "AES"
    return kty


def rsa_size_from_modulus(n: str) -> int:
    """Work out an RSA key's size (bits) from its public number 'n'.

    Azure sends 'n' in a compact text format (base64url) with the padding removed,
    so we put the padding back before decoding it.
    """
    padded = n + "=" * (-len(n) % 4)
    return len(base64.urlsafe_b64decode(padded)) * 8


# ---------- translators: one Azure form -> one index card ----------

def lock_from_vault_key(vault: str, key_doc: dict) -> Lock:
    key = key_doc.get("key") or {}
    # A key's address looks like: https://<vault>.vault.azure.net/keys/<NAME>/<version>
    parts = (key.get("kid") or "").split("/")
    name = parts[parts.index("keys") + 1] if "keys" in parts else "?"
    kind = normalize_key_type(key.get("kty", ""))
    if key.get("crv"):
        size = CURVE_SIZES.get(key["crv"], 0)
    elif key.get("n"):
        size = rsa_size_from_modulus(key["n"])
    else:
        size = 0
    return Lock(where=f"Key Vault '{vault}': key '{name}'", kind=kind, size=size)


def lock_from_vault_certificate(vault: str, cert_doc: dict) -> Lock:
    props = (cert_doc.get("policy") or {}).get("keyProperties") or {}
    kind = normalize_key_type(props.get("keyType", ""))
    size = props.get("keySize") or CURVE_SIZES.get(props.get("curve") or "", 0)
    name = cert_doc.get("name", "?")
    return Lock(where=f"Key Vault '{vault}': certificate '{name}'", kind=kind, size=size)


def lock_from_storage_account(account: dict) -> Lock:
    # Azure always locks stored files with AES-256 (whether Microsoft or the
    # customer holds the key), so every storage account gets the same card.
    return Lock(where=f"Storage account '{account.get('name', '?')}'", kind="AES", size=256)


# ---------- the walk itself ----------

def scan_azure(run=run_az) -> tuple[list[Lock], list[str]]:
    """Walk the signed-in Azure subscription. Returns (locks found, notes for a human).

    `run` is the messenger. Real runs use the real one; tests pass in a stand-in
    ("stunt double") that returns pre-written answers, so tests never touch Azure.
    """
    locks: list[Lock] = []
    notes: list[str] = []

    # Room type 1: Key Vaults
    vaults = run(["keyvault", "list"]) or []
    if not vaults:
        notes.append("No Key Vaults found in this subscription.")
    for vault in vaults:
        vname = vault.get("name", "?")
        try:
            for item in run(["keyvault", "key", "list", "--vault-name", vname]) or []:
                key_doc = run(["keyvault", "key", "show", "--id", item["kid"]])
                locks.append(lock_from_vault_key(vname, key_doc))
            for item in run(["keyvault", "certificate", "list", "--vault-name", vname]) or []:
                cert_doc = run(["keyvault", "certificate", "show", "--id", item["id"]])
                locks.append(lock_from_vault_certificate(vname, cert_doc))
        except AzureError as err:
            # One locked door must not stop the whole inspection.
            notes.append(f"Couldn't look inside Key Vault '{vname}' ({err}).")

    # Room type 2: Storage accounts
    accounts = run(["storage", "account", "list"]) or []
    if not accounts:
        notes.append("No storage accounts found in this subscription.")
    for account in accounts:
        locks.append(lock_from_storage_account(account))

    return locks, notes


# ---------- finding the doors (public web addresses) ----------

def _details(run, resource_type: str) -> list[dict]:
    """Full details of every resource of one type (e.g. every Container App)."""
    ids = [r["id"] for r in run(["resource", "list", "--resource-type", resource_type]) or []]
    if not ids:
        return []
    shown = run(["resource", "show", "--ids", *ids])
    return shown if isinstance(shown, list) else [shown]  # one id -> Azure returns one form


def find_web_doors(run=run_az) -> list[str]:
    """Read the building's directory board: every public web address in the subscription.

    Uses the custom address (e.g. app.example.com) when there is one - that's the door
    real visitors use - otherwise Azure's own default address.
    """
    hosts: list[str] = []

    for app in _details(run, "Microsoft.App/containerApps"):
        ingress = (app.get("properties") or {}).get("configuration", {}).get("ingress") or {}
        if not ingress.get("external"):
            continue  # internal-only app: no door to the street
        custom = [d["name"] for d in ingress.get("customDomains") or []]
        hosts += custom or [ingress.get("fqdn")]

    for site in _details(run, "Microsoft.Web/staticSites"):
        props = site.get("properties") or {}
        hosts += props.get("customDomains") or [props.get("defaultHostname")]

    # Remove blanks and repeats, keep the order.
    return list(dict.fromkeys(h for h in hosts if h))
