"""
risk_calculator.py - Turns rule results into a final score and risk level.

Scoring method (weighted rules):
    1. Add up the points of every triggered rule.
    2. Limit the total to the range 0 - MAX_RISK_SCORE (100).
    3. Look up the risk level using the thresholds in config.RISK_LEVELS.
"""

import config


def calculate_score(rule_results):
    """Add the points of all triggered rules and cap the total at 100.

    Args:
        rule_results (list): list of RuleResult objects.

    Returns:
        int: the final risk score (0 - 100).
    """
    total = 0
    for rule in rule_results:
        if rule.triggered:
            total += rule.score

    if total > config.MAX_RISK_SCORE:
        total = config.MAX_RISK_SCORE
    if total < 0:
        total = 0
    return total


def classify_risk(score):
    """Return the risk level label for a score, e.g. 'Suspicious'.

    The levels are checked in ascending order; the first level whose upper
    limit is greater than or equal to the score is chosen.
    """
    for upper_limit, label, colour, description in config.RISK_LEVELS:
        if score <= upper_limit:
            return label
    # Only reached if the score is above every limit (should not happen).
    return config.RISK_LEVELS[-1][1]


def get_level_details(label):
    """Return (colour, description) for a risk level label."""
    for upper_limit, level_label, colour, description in config.RISK_LEVELS:
        if level_label == label:
            return colour, description
    return "#94a3b8", "Unknown risk level."


def get_risk_level_names():
    """Return a list of all risk level labels in order (low -> high)."""
    names = []
    for level in config.RISK_LEVELS:
        names.append(level[1])
    return names
