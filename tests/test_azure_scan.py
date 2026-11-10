"""Checks for the Azure walk - using a "stunt double" instead of real Azure.

The fake messenger below returns pre-written answers, shaped exactly like real
Azure answers, so these checks never touch a real account.
"""

import base64
import unittest

from qlock.azure_cli import AzureError
from qlock.azure_scan import normalize_key_type, rsa_size_from_modulus, scan_azure

# A pretend RSA public number that is 256 bytes long -> a 2048-bit key.
FAKE_RSA_N = base64.urlsafe_b64encode(b"\x01" * 256).rstrip(b"=").decode()

KID_RSA = "https://payvault.vault.azure.net/keys/signing-key/abc123"
KID_EC = "https://payvault.vault.azure.net/keys/token-key/def456"
KID_HSM = "https://payvault.vault.azure.net/keys/hsm-key/ghi789"
CERT_ID = "https://payvault.vault.azure.net/certificates/www-cert/jkl012"

FAKE_ANSWERS = {
    ("keyvault", "list"): [{"name": "payvault"}, {"name": "lockedvault"}],
    ("keyvault", "key", "list", "--vault-name", "payvault"): [
        {"kid": KID_RSA}, {"kid": KID_EC}, {"kid": KID_HSM},
    ],
    ("keyvault", "key", "show", "--id", KID_RSA): {"key": {"kid": KID_RSA, "kty": "RSA", "n": FAKE_RSA_N}},
    ("keyvault", "key", "show", "--id", KID_EC): {"key": {"kid": KID_EC, "kty": "EC", "crv": "P-256"}},
    ("keyvault", "key", "show", "--id", KID_HSM): {"key": {"kid": KID_HSM, "kty": "EC-HSM", "crv": "P-384"}},
    ("keyvault", "certificate", "list", "--vault-name", "payvault"): [{"id": CERT_ID}],
    ("keyvault", "certificate", "show", "--id", CERT_ID): {
        "name": "www-cert",
        "policy": {"keyProperties": {"keyType": "RSA", "keySize": 4096}},
    },
    ("storage", "account", "list"): [{"name": "customerdocs"}],
}


def fake_az(args):
    """Stunt double for the real messenger."""
    if args[:4] == ["keyvault", "key", "list", "--vault-name"] and args[4] == "lockedvault":
        raise AzureError("Forbidden: caller is not authorized")
    return FAKE_ANSWERS[tuple(args)]


class TestAzureWalk(unittest.TestCase):
    """These should pass right now."""

    def setUp(self):
        self.locks, self.notes = scan_azure(run=fake_az)
        self.by_place = {lock.where: lock for lock in self.locks}

    def test_finds_every_lock(self):
        self.assertEqual(len(self.locks), 5)  # 3 keys + 1 certificate + 1 storage account

    def test_rsa_key_size_is_worked_out(self):
        lock = self.by_place["Key Vault 'payvault': key 'signing-key'"]
        self.assertEqual((lock.kind, lock.size), ("RSA", 2048))

    def test_ec_key_size_comes_from_curve(self):
        lock = self.by_place["Key Vault 'payvault': key 'token-key'"]
        self.assertEqual((lock.kind, lock.size), ("EC", 256))

    def test_certificate_is_read(self):
        lock = self.by_place["Key Vault 'payvault': certificate 'www-cert'"]
        self.assertEqual((lock.kind, lock.size), ("RSA", 4096))

    def test_storage_is_aes_256(self):
        lock = self.by_place["Storage account 'customerdocs'"]
        self.assertEqual((lock.kind, lock.size), ("AES", 256))

    def test_locked_vault_becomes_a_note_not_a_crash(self):
        self.assertTrue(any("lockedvault" in note for note in self.notes))

    def test_rsa_size_helper(self):
        self.assertEqual(rsa_size_from_modulus(FAKE_RSA_N), 2048)

    def test_rsa_hsm_becomes_rsa(self):
        self.assertEqual(normalize_key_type("RSA-HSM"), "RSA")


class TestYourTranslatorRules(unittest.TestCase):
    """These turn from FAIL to OK once you finish normalize_key_type() in qlock/azure_scan.py."""

    def test_ec_hsm_becomes_ec(self):
        self.assertEqual(normalize_key_type("EC-HSM"), "EC")

    def test_oct_becomes_aes(self):
        self.assertEqual(normalize_key_type("oct"), "AES")

    def test_oct_hsm_becomes_aes(self):
        self.assertEqual(normalize_key_type("oct-HSM"), "AES")

    def test_plain_names_stay_the_same(self):
        self.assertEqual(normalize_key_type("RSA"), "RSA")
        self.assertEqual(normalize_key_type("EC"), "EC")

    def test_hsm_key_found_in_walk_is_ec(self):
        locks, _ = scan_azure(run=fake_az)
        hsm = next(l for l in locks if "hsm-key" in l.where)
        self.assertEqual((hsm.kind, hsm.size), ("EC", 384))


if __name__ == "__main__":
    unittest.main()
