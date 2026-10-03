"""
statistics.py - Calculates dashboard statistics from the scan history.

Uses collections.Counter, a dictionary subclass that counts how many times
each item appears.
"""

from collections import Counter

from core.risk_calculator import get_risk_level_names


def calculate_statistics(records):
    """Summarise a list of ScanRecord objects.

    Args:
        records (list): list of ScanRecord objects.

    Returns:
        dict: totals, counts per risk level, average score, etc.
    """
    level_names = get_risk_level_names()
    level_counts = {}
    for name in level_names:
        level_counts[name] = 0

    indicator_counter = Counter()
    unique_domains = set()
    total_score = 0
    highest_record = None

    for record in records:
        total_score += record.risk_score

        if record.risk_level in level_counts:
            level_counts[record.risk_level] += 1

        for rule_name in record.get_rule_names():
            indicator_counter[rule_name] += 1

        domain = record.features.get("domain", "")
        if domain:
            unique_domains.add(domain)

        if highest_record is None or record.risk_score > highest_record.risk_score:
            highest_record = record

    total_scans = len(records)
    if total_scans > 0:
        average_score = round(total_score / total_scans, 1)
    else:
        average_score = 0.0

    return {
        "total_scans": total_scans,
        "level_counts": level_counts,
        "average_score": average_score,
        "unique_domains": len(unique_domains),
        "top_indicators": indicator_counter.most_common(10),   # list of (name, count)
        "highest_record": highest_record,
    }
