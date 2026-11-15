"""Checks for the CBOM (Cryptography Bill of Materials) writer."""

import json
import unittest

from qlock.cbom import build_cbom, quantum_level
from qlock.sample_data import DEMO_COMPANY, DEMO_LOCKS

# Allowed "primitive" names, copied from the official CycloneDX 1.6 schema.
CYCLONEDX_PRIMITIVES = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
                        "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other",
                        "unknown"}


def property_value(component, name):
    return next(p["value"] for p in component["properties"] if p["name"] == name)


class TestCbomFormat(unittest.TestCase):
    """These should pass right now."""

    def setUp(self):
        self.cbom = build_cbom(DEMO_COMPANY, DEMO_LOCKS)

    def test_has_required_header(self):
        self.assertEqual(self.cbom["bomFormat"], "CycloneDX")
        self.assertEqual(self.cbom["specVersion"], "1.6")

    def test_one_component_per_lock(self):
        self.assertEqual(len(self.cbom["components"]), len(DEMO_LOCKS))

    def test_every_component_is_a_crypto_asset(self):
        for component in self.cbom["components"]:
            self.assertEqual(component["type"], "cryptographic-asset")
            self.assertEqual(component["cryptoProperties"]["assetType"], "algorithm")

    def test_primitives_use_official_names(self):
        for component in self.cbom["components"]:
            primitive = component["cryptoProperties"]["algorithmProperties"]["primitive"]
            self.assertIn(primitive, CYCLONEDX_PRIMITIVES)

    def test_handshake_is_key_agreement(self):
        handshake = next(c for c in self.cbom["components"]
                         if property_value(c, "qlock:job") == "handshake")
        self.assertEqual(handshake["cryptoProperties"]["algorithmProperties"]["primitive"],
                         "key-agree")

    def test_keeps_where_and_verdict(self):
        first = self.cbom["components"][0]
        self.assertEqual(property_value(first, "qlock:where"), DEMO_LOCKS[0].where)
        self.assertEqual(property_value(first, "qlock:verdict"), "RED")

    def test_bom_refs_are_unique(self):
        refs = [c["bom-ref"] for c in self.cbom["components"]]
        self.assertEqual(len(refs), len(set(refs)))

    def test_can_be_saved_as_json(self):
        json.loads(json.dumps(self.cbom))  # would raise if something can't be saved

    def test_unknown_lock_has_no_rating(self):
        self.assertIsNone(quantum_level("MYSTERY-LOCK", 99))


class TestYourQuantumLevels(unittest.TestCase):
    """These turn from FAIL to OK once you write quantum_level() in qlock/cbom.py."""

    def test_rsa_is_zero(self):
        self.assertEqual(quantum_level("RSA", 2048), 0)

    def test_old_handshake_is_zero(self):
        self.assertEqual(quantum_level("X25519", 253), 0)

    def test_aes_128_is_one(self):
        self.assertEqual(quantum_level("AES", 128), 1)

    def test_aes_256_is_five(self):
        self.assertEqual(quantum_level("AES", 256), 5)

    def test_ml_kem_768_is_three(self):
        self.assertEqual(quantum_level("ML-KEM", 768), 3)

    def test_hybrid_handshake_is_three(self):
        self.assertEqual(quantum_level("X25519MLKEM768", 0), 3)

    def test_rating_appears_in_cbom(self):
        cbom = build_cbom("Test Co", DEMO_LOCKS[:1])  # the RSA key
        algorithm = cbom["components"][0]["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(algorithm.get("nistQuantumSecurityLevel"), 0)


if __name__ == "__main__":
    unittest.main()
