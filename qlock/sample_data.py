"""A pretend company, used for practice. Nothing here is real.

"Demo Payments Pvt Ltd" is a made-up fintech. These are the locks our
inspector would find if it walked through their (imaginary) Azure cloud.
"""

from qlock.locks import Lock

DEMO_COMPANY = "Demo Payments Pvt Ltd (pretend)"

DEMO_LOCKS = [
    Lock(where="Key Vault: upi-signing-key", kind="RSA", size=2048),
    Lock(where="Website certificate: www.demopay.example", kind="EC", size=256),
    Lock(where="Storage account: customer-documents", kind="AES", size=256),
    Lock(where="Old backup disk: backup-2019", kind="AES", size=128),
    Lock(where="Test key: pqc-pilot", kind="ML-KEM", size=768),
    Lock(where="Legacy partner link: bank-sftp", kind="3DES", size=168),
]
