"""A pretend company, used for practice. Nothing here is real.

"Demo Payments Pvt Ltd" is a made-up fintech. These are the locks our
inspector would find if it walked through their (imaginary) Azure cloud.
"""

from qlock.locks import CERTIFICATE, HANDSHAKE, KEY, OTHER, STORAGE, Lock

DEMO_COMPANY = "Demo Payments Pvt Ltd (pretend)"

DEMO_LOCKS = [
    Lock(where="Key Vault: upi-signing-key", kind="RSA", size=2048, job=KEY),
    Lock(where="Website certificate: www.demopay.example", kind="EC", size=256, job=CERTIFICATE),
    Lock(where="Website handshake: www.demopay.example", kind="X25519", size=253, job=HANDSHAKE),
    Lock(where="Storage account: customer-documents", kind="AES", size=256, job=STORAGE),
    Lock(where="Old backup disk: backup-2019", kind="AES", size=128, job=STORAGE),
    Lock(where="Test key: pqc-pilot", kind="ML-KEM", size=768, job=KEY),
    Lock(where="Legacy partner link: bank-sftp", kind="3DES", size=168, job=OTHER),
]
