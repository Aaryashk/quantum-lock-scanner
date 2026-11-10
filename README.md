# Quantum Lock Scanner

A free, open-source tool that walks through a company's **Microsoft Azure** cloud
and lists every "lock" (encryption) it finds, marking each one:

- **RED**    - future quantum computers can break this lock. Replace it.
- **AMBER**  - quantum computers weaken this lock. Upgrade when convenient.
- **GREEN**  - this lock is already quantum-safe.
- **UNKNOWN** - the scanner does not recognise this lock yet. A human should look.

Think of it as a building inspector who checks every door and writes a report.

## Try it (no Azure account needed)

```
python -m qlock --demo
```

This runs the scanner on a pretend company so you can see what a report looks like.

## Run the automatic checks

```
python -m unittest -v
```

## Status

Early work in progress. Connecting to a real Azure account comes in a later step.

## Licence

Apache-2.0. The full licence text will be added when the project is published on
GitHub (GitHub inserts it automatically when you pick the licence).
