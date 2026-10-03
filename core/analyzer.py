"""
analyzer.py - The main entry point of the analysis logic.

URLAnalyzer connects all the steps of the pipeline:

    raw text --> validate --> extract features --> evaluate rules
             --> calculate score --> classify risk --> URLResult

Design note (future ML support):
    The feature dictionary produced by FeatureExtractor is independent of the
    rules. A machine-learning classifier could later receive the same feature
    dictionary and its prediction could be shown next to (or combined with)
    the rule-based score, without rewriting the rest of the application.
"""

import config
from core.feature_extractor import FeatureExtractor
from core.risk_calculator import calculate_score, classify_risk
from core.rule_engine import RuleEngine
from models.url_result import URLResult
from utils.helpers import load_json_file
from utils.validators import validate_url


class URLAnalyzer:
    """Performs static (text-only) analysis of URLs."""

    def __init__(self):
        """Load the reference lists from the data folder and build the components."""
        keyword_categories = load_json_file(config.KEYWORDS_FILE, {})
        shortener_domains = load_json_file(config.SHORTENERS_FILE, [])
        tld_data = load_json_file(config.SUSPICIOUS_TLDS_FILE, {})

        # Guard against files with the wrong structure.
        if not isinstance(keyword_categories, dict):
            keyword_categories = {}
        if not isinstance(shortener_domains, list):
            shortener_domains = []
        suspicious_tlds = []
        if isinstance(tld_data, dict):
            suspicious_tlds = tld_data.get("tlds", [])

        self.extractor = FeatureExtractor(keyword_categories, shortener_domains, suspicious_tlds)
        self.rule_engine = RuleEngine()

    def validate_url(self, raw_url):
        """Validate the user's input. Returns (normalised_url, notes).

        Raises:
            InvalidURLError: if the input is not a usable URL.
        """
        return validate_url(raw_url)

    def extract_features(self, url):
        """Return the feature dictionary for a validated URL."""
        return self.extractor.extract(url)

    def analyze(self, raw_url):
        """Run the full analysis on the user's input.

        Args:
            raw_url (str): text entered by the user.

        Returns:
            URLResult: score, level, features and explanations.

        Raises:
            InvalidURLError: if the input is not a usable URL.
        """
        url, notes = self.validate_url(raw_url)
        features = self.extract_features(url)
        rule_results = self.rule_engine.evaluate_rules(features)
        score = calculate_score(rule_results)
        level = classify_risk(score)
        return URLResult(url, score, level, features, rule_results, notes)
