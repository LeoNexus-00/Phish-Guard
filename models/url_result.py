"""
url_result.py - Classes that describe the outcome of an analysis.

RuleResult : the outcome of ONE security check (e.g. "HTTPS Check").
URLResult  : the complete outcome of analysing ONE URL.
"""


class RuleResult:
    """Stores the outcome of a single rule (security check)."""

    def __init__(self, rule_id, name, triggered, detected, reason, score):
        """Create a rule result.

        Args:
            rule_id (str): short identifier, e.g. "https_check".
            name (str): readable name, e.g. "HTTPS Check".
            triggered (bool): True if the warning sign was found.
            detected (str): what was detected (shown to the user).
            reason (str): plain-English explanation.
            score (int): risk points added (0 if not triggered).
        """
        self.rule_id = rule_id
        self.name = name
        self.triggered = triggered
        self.detected = detected
        self.reason = reason
        self.score = score

    def get_status(self):
        """Return 'Flagged' if the rule was triggered, otherwise 'Passed'."""
        if self.triggered:
            return "Flagged"
        return "Passed"

    def to_dict(self):
        """Convert the object into a dictionary (so it can be saved as JSON)."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "detected": self.detected,
            "reason": self.reason,
            "score": self.score,
        }

    def __repr__(self):
        return f"RuleResult({self.name!r}, triggered={self.triggered}, score={self.score})"


class URLResult:
    """Stores the complete result of analysing one URL."""

    def __init__(self, url, risk_score, risk_level, features, rule_results, notes=None):
        self.url = url
        self.risk_score = risk_score
        self.risk_level = risk_level
        self.features = features
        self.rule_results = rule_results          # list of RuleResult (all checks)
        self.notes = notes if notes is not None else []

    def get_triggered_rules(self):
        """Return only the rules that found a warning sign."""
        triggered = []
        for rule in self.rule_results:
            if rule.triggered:
                triggered.append(rule)
        return triggered

    def get_raw_score(self):
        """Return the sum of all rule scores BEFORE the 0-100 cap is applied."""
        total = 0
        for rule in self.get_triggered_rules():
            total += rule.score
        return total

    def __repr__(self):
        return f"URLResult({self.url!r}, score={self.risk_score}, level={self.risk_level!r})"
