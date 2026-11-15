"""Turns a pile of lock index-cards into a readable report, most urgent first."""

from collections import Counter

from qlock.locks import (CHECK, FIX_FIRST, KEY, PLAN_AHEAD, SAFE, URGENCY_ORDER, VERDICTS,
                         Lock, judge_lock, rank_urgency)

ADVICE = {
    "RED": "Quantum computers could break this. Plan to replace it.",
    "AMBER": "Quantum computers weaken this. Upgrade when convenient.",
    "GREEN": "Already quantum-safe. No action needed.",
    "UNKNOWN": "Not recognised by the scanner. A human should check it.",
}

# One line under each section heading, saying why it's in that section.
WHY = {
    FIX_FIRST: "Secrets protected by these locks can be recorded today and cracked later.",
    PLAN_AHEAD: "Real risk, but only in the future. Include these in your upgrade plan.",
    CHECK: "The scanner doesn't recognise these. A human should look.",
    SAFE: "Nothing to do.",
}

KEY_CAVEAT = ("(The scanner can't tell whether this key locks data or only signs it, "
              "so it assumes the riskier case.)")


def build_report(company: str, locks: list[Lock], notes: list[str] | None = None) -> str:
    """Return the full report as text. `notes` are messages for a human (e.g. a locked room)."""
    lines = []
    lines.append("=" * 70)
    lines.append(f"QUANTUM LOCK REPORT for {company}")
    lines.append("=" * 70)

    # Sort every lock into its urgency bucket (keeping the order they were found in).
    buckets: dict[str, list[tuple[Lock, str]]] = {name: [] for name in URGENCY_ORDER}
    counts = Counter()
    for lock in locks:
        verdict = judge_lock(lock.kind, lock.size)
        counts[verdict] += 1
        buckets[rank_urgency(lock.job, verdict)].append((lock, verdict))

    for name in URGENCY_ORDER:
        if not buckets[name]:
            continue
        lines.append("")
        lines.append(f"### {name} ({len(buckets[name])}) - {WHY[name]}")
        for lock, verdict in buckets[name]:
            lines.append("")
            lines.append(f"[{verdict:<7}] {lock.where}")
            lines.append(f"          lock type: {lock.kind}, key size: {lock.size} bits")
            lines.append(f"          {ADVICE[verdict]}")
            if lock.job == KEY and name == FIX_FIRST:
                lines.append(f"          {KEY_CAVEAT}")

    lines.append("")
    lines.append("-" * 70)
    summary = ", ".join(f"{v}: {counts[v]}" for v in VERDICTS)
    lines.append(f"SUMMARY ({len(locks)} locks found)  {summary}")
    urgency = ", ".join(f"{name}: {len(buckets[name])}" for name in URGENCY_ORDER)
    lines.append(f"BY URGENCY  {urgency}")
    lines.append("-" * 70)
    if notes:
        lines.append("NOTES FOR A HUMAN:")
        lines.extend(f"  - {note}" for note in notes)
    return "\n".join(lines)
