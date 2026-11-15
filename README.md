# Quantum Lock Scanner

A free, open-source tool that checks a company's **Microsoft Azure** cloud and public
websites for encryption ("locks") that future quantum computers could break.

Think of it as a building inspector. It walks every corridor, reads the label on every
lock, and writes a report. **It only looks. It never changes anything.**

Each lock gets a traffic-light verdict:

| Verdict | Meaning |
|---|---|
| **RED** | Quantum computers can break this lock. Plan to replace it. |
| **AMBER** | Quantum computers weaken this lock. Upgrade when convenient. |
| **GREEN** | Already quantum-safe. |
| **UNKNOWN** | The scanner doesn't recognise it yet. A human should look. |

The report is sorted by urgency: **MOST URGENT** (data that can be recorded today and
cracked later, like old website handshakes), then **PLAN AHEAD** (risks that only matter
later, like RSA certificates), then **CHECK BY HAND**, then **ALREADY SAFE**.

## Why this matters

Attackers can record encrypted traffic today and decrypt it years later, once quantum
computers are strong enough ("harvest now, decrypt later"). India's DST task force
roadmap expects critical infrastructure to start moving to post-quantum cryptography
around 2027. The first step for any organisation is knowing *where* its old locks are.
This tool does that step.

## What it checks

| Where | What it reads |
|---|---|
| Azure Key Vault | Every key and certificate: RSA, EC, AES and their sizes |
| Azure Storage | Data-at-rest encryption (AES-256) |
| Public websites | The certificate ("ID card") and the TLS handshake each site uses |

For websites it can tell the old handshake (`X25519`) from the new hybrid quantum-safe
one (`X25519MLKEM768`).

## Requirements

- Python 3.10 or newer. No extra Python packages are needed.
- For Azure scans: the [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli),
  signed in with `az login`. The scanner can see only what your login is allowed to read.
- For website checks: **OpenSSL 3.5 or newer**. On Windows, Git for Windows already
  includes it, and the scanner finds it automatically.

## Try it

A pretend company, with no Azure account needed:

```
python -m qlock --demo
```

Any public website:

```
python -m qlock --host example.com
```

Your own Azure subscription (read-only), including every public web address found in it:

```
python -m qlock --azure
```

Add `--cbom` to any of these to also save a **CBOM** (Cryptography Bill of Materials):
a standard "ingredients list" of every lock found, in the CycloneDX 1.6 format that
other security tools can read.

```
python -m qlock --azure --cbom reports/cbom.json
```

The `reports/` folder is ignored by git, so real scan results are never published by accident.

## Run the automatic checks

```
python -m unittest -v
```

The checks use stand-in answers, so they never touch real Azure or real websites.

## Status

Early but working (v0.0.1). Planned next:
- more Azure services (App Service, Front Door, SQL)

## Licence

[Apache-2.0](LICENSE). Free to use, change and share, including in commercial work.
