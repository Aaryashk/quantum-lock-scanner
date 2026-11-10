"""Turns a pile of lock index-cards into a readable report."""

from collections import Counter

from qlock.locks import VERDICTS, Lock, judge_lock

ADVICE = {
    "RED": "Quantum computers could break this. Plan to replace it.",
    "AMBER": "Quantum computers weaken this. Upgrade when convenient.",
    "GREEN": "Already quantum-safe. No action needed.",
    "UNKNOWN": "Not recognised by the scanner. A human should check it.",
}


def build_report(company: str, locks: list[Lock], notes: list[str] | None = None) -> str:
    """Return the full report as text. `notes` are messages for a human (e.g. a locked room)."""
    lines = []
    lines.append("=" * 70)
    lines.append(f"QUANTUM LOCK REPORT for {company}")
    lines.append("=" * 70)

    counts = Counter()
    for lock in locks:
        verdict = judge_lock(lock.kind, lock.size)
        counts[verdict] += 1
        lines.append("")
        lines.append(f"[{verdict:<7}] {lock.where}")
        lines.append(f"          lock type: {lock.kind}, key size: {lock.size} bits")
        lines.append(f"          {ADVICE[verdict]}")

    lines.append("")
    lines.append("-" * 70)
    summary = ", ".join(f"{v}: {counts[v]}" for v in VERDICTS)
    lines.append(f"SUMMARY ({len(locks)} locks found)  {summary}")
    lines.append("-" * 70)
    if notes:
        lines.append("NOTES FOR A HUMAN:")
        lines.extend(f"  - {note}" for note in notes)
    return "\n".join(lines)
