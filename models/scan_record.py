"""
scan_record.py - The ScanRecord class represents one saved scan in the history.

A URLResult (see url_result.py) contains Python objects for every check.
A ScanRecord contains only simple data (strings, numbers, lists, dicts) so
that it can be written to and read from a JSON file.
"""

from datetime import datetime

from utils.helpers import get_timestamp


class ScanRecord:
    """One entry of the scan history."""

    def __init__(self, url, risk_score, risk_level, features, detected_rules,
                 timestamp=None, scan_id=None):
        """Create a scan record.

        If timestamp or scan_id are not given (a brand-new scan), they are
        generated automatically.
        """
        self.url = url
        self.risk_score = risk_score
        self.risk_level = risk_level
        self.features = features
        self.detected_rules = detected_rules       # list of dicts
        self.timestamp = timestamp if timestamp else get_timestamp()
        # A unique id based on the exact time, e.g. "20261004014512345678".
        self.scan_id = scan_id if scan_id else datetime.now().strftime("%Y%m%d%H%M%S%f")

    @classmethod
    def from_result(cls, result):
        """Create a ScanRecord from a URLResult (only triggered rules are kept)."""
        detected_rules = []
        for rule in result.get_triggered_rules():
            detected_rules.append(rule.to_dict())

        return cls(
            url=result.url,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            features=result.features,
            detected_rules=detected_rules,
        )

    @classmethod
    def from_dict(cls, data):
        """Create a ScanRecord from a dictionary loaded from JSON.

        Raises:
            KeyError: if a required field is missing.
            ValueError: if the risk score is not a number.
        """
        features = data.get("features", {})
        if not isinstance(features, dict):
            features = {}

        detected_rules = []
        for rule in data.get("detected_rules", []):
            if isinstance(rule, dict):
                detected_rules.append(rule)

        return cls(
            url=str(data["url"]),
            risk_score=int(data["risk_score"]),
            risk_level=str(data["risk_level"]),
            features=features,
            detected_rules=detected_rules,
            timestamp=data.get("timestamp"),
            scan_id=data.get("scan_id"),
        )

    def to_dict(self):
        """Convert the record into a dictionary for saving as JSON."""
        return {
            "scan_id": self.scan_id,
            "url": self.url,
            "timestamp": self.timestamp,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "features": self.features,
            "detected_rules": self.detected_rules,
        }

    def get_rule_names(self):
        """Return the names of the rules that were triggered in this scan."""
        names = []
        for rule in self.detected_rules:
            names.append(rule.get("name", "Unknown"))
        return names

    def __repr__(self):
        return f"ScanRecord({self.url!r}, {self.risk_score}, {self.timestamp!r})"
