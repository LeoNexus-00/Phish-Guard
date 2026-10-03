"""
rule_engine.py - Applies security rules to the extracted URL features.

Each rule is a small method that looks at the feature dictionary and returns
a RuleResult describing:
    - whether the warning sign was found (triggered or not)
    - what was detected
    - WHY it matters (the explanation shown to the user)
    - how many risk points it adds

The weights (points) come from config.RULE_WEIGHTS so they can be tuned
without changing this code.
"""

import config
from models.url_result import RuleResult

# rule_id -> (readable name, one-line description used on the About page)
RULE_INFO = {
    "https_check": ("HTTPS Check", "Flags URLs that use HTTP instead of encrypted HTTPS."),
    "ip_address": ("IP Address Hostname", "Flags URLs that use a raw IP address instead of a domain name."),
    "at_symbol": ("@ Symbol in Address", "Flags an '@' in the address part, which hides the real destination."),
    "suspicious_keywords": ("Suspicious Keywords", "Flags credential, payment and urgency words (scored per category)."),
    "keyword_in_domain": ("Keyword in Domain Name", "Flags sensitive words placed inside the registered domain name."),
    "url_length": ("URL Length", "Flags unusually long URLs that can hide the real destination."),
    "subdomains": ("Excessive Subdomains", "Flags hostnames with many subdomain levels."),
    "embedded_domain": ("Domain Name Inside Subdomain", "Flags a trusted-looking domain (e.g. 'bank.com') placed in front of the real domain."),
    "hyphens": ("Hyphenated Hostname", "Flags hostnames that contain many hyphens."),
    "special_characters": ("Special Character Patterns", "Flags unusual symbols or '//' inside the path."),
    "url_shortener": ("URL Shortener", "Flags known link-shortening services that hide the final address."),
    "punycode": ("Punycode / Look-alike Characters", "Flags punycode (xn--) or non-ASCII letters in the hostname."),
    "url_encoding": ("URL Encoding", "Flags percent-encoding in the hostname or excessive encoding elsewhere."),
    "suspicious_tld": ("Suspicious TLD", "Flags top-level domains often reported as abused (weak indicator)."),
    "non_standard_port": ("Non-standard Port", "Flags URLs that specify an unusual port number."),
    "hostname_digits": ("Digits in Hostname", "Flags hostnames containing many digits."),
}


class RuleEngine:
    """Evaluates all security rules against a feature dictionary."""

    def __init__(self, weights=None):
        """Create the engine.

        Args:
            weights (dict, optional): rule_id -> points. Defaults to
                config.RULE_WEIGHTS. Passing custom weights is useful for testing.
        """
        if weights is None:
            weights = config.RULE_WEIGHTS
        self.weights = weights

        # The list of checks that evaluate_rules() runs, in display order.
        self.rule_checks = [
            self.check_https,
            self.check_ip_address,
            self.check_at_symbol,
            self.check_keywords,
            self.check_keyword_in_domain,
            self.check_url_length,
            self.check_subdomains,
            self.check_embedded_domain,
            self.check_hyphens,
            self.check_special_characters,
            self.check_url_shortener,
            self.check_punycode,
            self.check_url_encoding,
            self.check_suspicious_tld,
            self.check_non_standard_port,
            self.check_hostname_digits,
        ]

    # ------------------------------------------------------------------
    # Main method
    # ------------------------------------------------------------------
    def evaluate_rules(self, features):
        """Run every rule and return a list of RuleResult objects (all checks)."""
        results = []
        for check in self.rule_checks:
            results.append(check(features))
        return results

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------
    def _result(self, rule_id, triggered, detected, reason, points=None):
        """Build a RuleResult. If points is None, the configured weight is used."""
        name = RULE_INFO[rule_id][0]
        if points is None:
            points = self.weights.get(rule_id, 0)
        score = points if triggered else 0
        return RuleResult(rule_id, name, triggered, detected, reason, score)

    # ------------------------------------------------------------------
    # Individual rules
    # ------------------------------------------------------------------
    def check_https(self, features):
        if features["uses_https"]:
            return self._result("https_check", False, "https",
                                "The URL uses HTTPS (an encrypted connection). Note that HTTPS "
                                "alone does not prove a site is trustworthy.")
        return self._result("https_check", True, features["scheme"],
                            "The URL uses HTTP rather than HTTPS, so information sent to the "
                            "site would not be encrypted. Legitimate login pages use HTTPS.")

    def check_ip_address(self, features):
        if features["has_ip_address"]:
            return self._result("ip_address", True, features["hostname"],
                                "The site is addressed by a raw IP address instead of a domain "
                                "name. Legitimate public websites almost always use domain names.")
        return self._result("ip_address", False, "Domain name used",
                            "The URL uses a domain name, not a raw IP address.")

    def check_at_symbol(self, features):
        if features["has_at_symbol"]:
            return self._result("at_symbol", True, "@ in address",
                                "Browsers ignore everything before '@' in the address, so "
                                "'http://trusted.com@other.example' really opens 'other.example'.")
        return self._result("at_symbol", False, "None",
                            "No '@' symbol was found in the address part of the URL.")

    def check_keywords(self, features):
        matches = features["keyword_matches"]          # {category: [keywords]}
        if not matches:
            return self._result("suspicious_keywords", False, "None",
                                "No common phishing-related keywords were found.")

        all_keywords = []
        for keyword_list in matches.values():
            all_keywords.extend(keyword_list)
        quoted = ", ".join(f'"{word}"' for word in all_keywords)
        categories = ", ".join(matches.keys())

        points = len(matches) * config.KEYWORD_SCORE_PER_CATEGORY
        points = min(points, config.KEYWORD_MAX_SCORE)

        return self._result("suspicious_keywords", True, f"{quoted} ({categories})",
                            "These words are frequently used in URLs that try to collect "
                            "passwords, account details or payments. Points are given per "
                            f"category ({config.KEYWORD_SCORE_PER_CATEGORY} each, maximum "
                            f"{config.KEYWORD_MAX_SCORE}).",
                            points)

    def check_keyword_in_domain(self, features):
        found = features["keywords_in_domain"]
        if found:
            quoted = ", ".join(f'"{word}"' for word in found)
            return self._result("keyword_in_domain", True, f"{quoted} in '{features['domain']}'",
                                "Sensitive words inside the domain name itself (e.g. "
                                "'secure-login-example.com') are a common trick to make a fake "
                                "domain look official.")
        return self._result("keyword_in_domain", False, "None",
                            "The registered domain name does not contain sensitive keywords.")

    def check_url_length(self, features):
        length = features["url_length"]
        if length > config.VERY_LONG_URL_LENGTH:
            return self._result("url_length", True, f"{length} characters (very long)",
                                f"The URL is longer than {config.VERY_LONG_URL_LENGTH} characters. "
                                "Very long URLs can hide the real destination from the user.",
                                self.weights.get("url_length_very_long", 0))
        if length > config.LONG_URL_LENGTH:
            return self._result("url_length", True, f"{length} characters",
                                f"The URL is longer than {config.LONG_URL_LENGTH} characters, "
                                "which makes it harder to inspect. Many normal URLs are also "
                                "long, so this is only a minor indicator.")
        return self._result("url_length", False, f"{length} characters",
                            "The URL length is within the normal range.")

    def check_subdomains(self, features):
        count = features["subdomain_count"]
        if count > config.MAX_NORMAL_SUBDOMAINS:
            return self._result("subdomains", True, f"{count} levels ({features['subdomain']})",
                                "Many subdomain levels can place a trusted-looking name at the "
                                "start of an unrelated domain, e.g. 'bank.com.secure.example.net'.")
        return self._result("subdomains", False, f"{count} levels",
                            "The number of subdomains is normal.")

    def check_embedded_domain(self, features):
        embedded = features["embedded_domains"]
        if embedded:
            shown = ", ".join(f"'{item}'" for item in embedded)
            return self._result("embedded_domain", True,
                                f"{shown} before real domain '{features['domain']}'",
                                "A familiar-looking domain name appears in the subdomain part. "
                                "The website actually belongs to the domain at the END of the "
                                "hostname, not the one at the start.")
        return self._result("embedded_domain", False, "None",
                            "No domain-like text was found inside the subdomain.")

    def check_hyphens(self, features):
        count = features["hostname_hyphen_count"]
        if count > config.MAX_NORMAL_HOSTNAME_HYPHENS:
            return self._result("hyphens", True, f"{count} hyphens",
                                "Hostnames with many hyphens (e.g. 'secure-account-update-example') "
                                "are often used to imitate legitimate brands.")
        return self._result("hyphens", False, f"{count} hyphens",
                            "The hostname does not contain an unusual number of hyphens.")

    def check_special_characters(self, features):
        count = features["special_char_count"]
        double_slash = features["has_double_slash_in_path"]
        if count > config.MAX_NORMAL_SPECIAL_CHARS or double_slash:
            details = []
            if count > config.MAX_NORMAL_SPECIAL_CHARS:
                details.append(f"{count} unusual symbols")
            if double_slash:
                details.append("'//' inside the path")
            return self._result("special_characters", True, ", ".join(details),
                                "Unusual symbols or a '//' inside the path are sometimes used to "
                                "confuse users or hide an embedded second address.")
        return self._result("special_characters", False, f"{count} unusual symbols",
                            "No unusual special-character patterns were found.")

    def check_url_shortener(self, features):
        if features["is_url_shortener"]:
            return self._result("url_shortener", True, features["hostname"],
                                "URL shorteners hide the final destination, so the real website "
                                "cannot be seen from the link itself.")
        return self._result("url_shortener", False, "No",
                            "The domain is not in the local list of URL shorteners.")

    def check_punycode(self, features):
        if features["is_punycode"] or features["has_non_ascii_hostname"]:
            if features["is_punycode"]:
                detected = "Punycode (xn--) in hostname"
            else:
                detected = "Non-ASCII letters in hostname"
            return self._result("punycode", True, detected,
                                "Punycode or non-English letters can create look-alike domains "
                                "(homograph attacks), e.g. a Cyrillic letter that looks exactly "
                                "like the English 'a'.")
        return self._result("punycode", False, "No",
                            "The hostname uses only standard ASCII characters.")

    def check_url_encoding(self, features):
        encoded_count = features["encoded_char_count"]
        if features["has_encoded_hostname"]:
            return self._result("url_encoding", True, "Encoded characters in hostname",
                                "Percent-encoding (%xx) in the hostname is never needed by normal "
                                "websites and is used to disguise the real domain.")
        if encoded_count > config.MAX_NORMAL_ENCODED_CHARS:
            return self._result("url_encoding", True, f"{encoded_count} encoded sequences",
                                "A large amount of percent-encoding (%xx) can be used to hide "
                                "words or addresses inside the URL.")
        return self._result("url_encoding", False, f"{encoded_count} encoded sequences",
                            "No suspicious URL encoding was found.")

    def check_suspicious_tld(self, features):
        if features["has_suspicious_tld"]:
            return self._result("suspicious_tld", True, "." + features["tld"],
                                "This top-level domain is frequently listed in public abuse "
                                "reports, often because it is free or very cheap. Many legitimate "
                                "sites use it too, so it is a weak indicator.")
        return self._result("suspicious_tld", False, "." + features["tld"] if features["tld"] else "-",
                            "The top-level domain is not in the local suspicious-TLD list.")

    def check_non_standard_port(self, features):
        if features["has_non_standard_port"]:
            return self._result("non_standard_port", True, f"Port {features['port']}",
                                "Normal websites use the default ports (80/443). A custom port "
                                "may indicate a temporary or improperly hosted site.")
        return self._result("non_standard_port", False, "Default port",
                            "The URL uses the default port.")

    def check_hostname_digits(self, features):
        count = features["hostname_digit_count"]
        if count > config.MAX_NORMAL_HOSTNAME_DIGITS:
            return self._result("hostname_digits", True, f"{count} digits",
                                "Many digits in a domain name can indicate an automatically "
                                "generated or look-alike domain (e.g. 'paypa1-0921.example').")
        return self._result("hostname_digits", False, f"{count} digits",
                            "The hostname does not contain an unusual number of digits.")
