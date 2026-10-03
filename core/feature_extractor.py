"""
feature_extractor.py - Converts a URL into measurable "features".

A feature is a simple fact about the URL, for example its length or whether
it uses HTTPS. The rule engine later looks at these facts to decide which
warning signs are present. Keeping features separate from rules means a
machine-learning model could use the same feature dictionary in the future.

IMPORTANT: this module only looks at the URL TEXT. It never connects to the
website.
"""

import re

import config
from core.url_parser import parse_url
from utils.validators import is_ip_address

# Regular expression for a percent-encoded character such as %2F or %40.
PERCENT_ENCODING_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")


class FeatureExtractor:
    """Extracts features from a URL using locally stored reference lists."""

    def __init__(self, keyword_categories, shortener_domains, suspicious_tlds):
        """Store the reference data used during extraction.

        Args:
            keyword_categories (dict): category name -> list of keywords.
            shortener_domains (list): known URL-shortener domains.
            suspicious_tlds (list): TLDs frequently reported as abused.
        """
        self.keyword_categories = keyword_categories
        # Sets give fast "is this item present?" checks.
        self.shortener_domains = set(shortener_domains)
        self.suspicious_tlds = set(suspicious_tlds)

    # ------------------------------------------------------------------
    # Small counting helpers
    # ------------------------------------------------------------------
    @staticmethod
    def count_digits(text):
        """Count how many characters in the text are digits."""
        count = 0
        for character in text:
            if character.isdigit():
                count += 1
        return count

    @staticmethod
    def count_special_characters(text):
        """Count characters that belong to config.SPECIAL_CHARACTERS."""
        count = 0
        for character in text:
            if character in config.SPECIAL_CHARACTERS:
                count += 1
        return count

    @staticmethod
    def count_subdomains(subdomain):
        """Count subdomain levels, ignoring a leading 'www'."""
        if subdomain == "":
            return 0
        labels = subdomain.split(".")
        if labels[0] == "www":
            labels = labels[1:]
        return len(labels)

    # ------------------------------------------------------------------
    # Keyword / list based checks
    # ------------------------------------------------------------------
    def find_keywords(self, text):
        """Return {category: [matched keywords]} for keywords found in text."""
        text = text.lower()
        matches = {}
        for category, keywords in self.keyword_categories.items():
            found = []
            for keyword in keywords:
                if keyword in text and keyword not in found:
                    found.append(keyword)
            if found:
                matches[category] = found
        return matches

    def find_keywords_in_domain(self, domain, tld):
        """Return keywords that appear inside the registered domain name itself.

        Example: for 'example-login.com' the name part is 'example-login',
        which contains the keyword 'login'.
        """
        name_part = domain
        if tld and domain.endswith("." + tld):
            name_part = domain[: -(len(tld) + 1)]

        found = []
        for keywords in self.keyword_categories.values():
            for keyword in keywords:
                if keyword in name_part and keyword not in found:
                    found.append(keyword)
        return found

    def is_url_shortener(self, hostname, domain):
        """Return True if the hostname belongs to a known URL shortener."""
        if hostname.startswith("www."):
            hostname = hostname[4:]
        return hostname in self.shortener_domains or domain in self.shortener_domains

    @staticmethod
    def find_embedded_domains(subdomain):
        """Return subdomain parts that look like another domain name.

        Example: in 'paypal.com.secure.example.net' the subdomain is
        'paypal.com.secure'. The label 'com' is a common TLD, so the text
        'paypal.com' is returned: a trusted name placed in front of the
        real domain to fool the reader.
        """
        if subdomain == "":
            return []
        labels = subdomain.split(".")
        embedded = []
        for position in range(1, len(labels)):          # skip the first label
            if labels[position] in config.COMMON_TLDS:
                embedded.append(labels[position - 1] + "." + labels[position])
        return embedded

    # ------------------------------------------------------------------
    # Main method
    # ------------------------------------------------------------------
    def extract(self, url):
        """Extract all features from a validated URL.

        Args:
            url (str): a URL that has passed validation.

        Returns:
            dict: feature name -> value.
        """
        components = parse_url(url)
        hostname = components["hostname"]
        path = components["path"]
        query = components["query"]

        has_ip = is_ip_address(hostname)
        searchable_text = hostname + path + query

        query_parameters = []
        for item in query.split("&"):
            if item != "":
                query_parameters.append(item)

        features = {
            # --- components ---
            "url": url,
            "scheme": components["scheme"],
            "hostname": hostname,
            "subdomain": components["subdomain"],
            "domain": components["domain"],
            "tld": components["tld"],
            "port": components["port"],
            "path": path,
            "query": query,
            "fragment": components["fragment"],
            # --- lengths and counts ---
            "url_length": len(url),
            "hostname_length": len(hostname),
            "path_length": len(path),
            "dot_count": url.count("."),
            "hyphen_count": url.count("-"),
            "hostname_hyphen_count": hostname.replace("xn--", "").count("-"),
            "subdomain_count": self.count_subdomains(components["subdomain"]),
            "digit_count": self.count_digits(url),
            "hostname_digit_count": 0 if has_ip else self.count_digits(hostname),
            "special_char_count": self.count_special_characters(url),
            "query_param_count": len(query_parameters),
            "encoded_char_count": len(PERCENT_ENCODING_PATTERN.findall(url)),
            # --- true/false indicators ---
            "uses_https": components["scheme"] == "https",
            "has_ip_address": has_ip,
            "has_at_symbol": "@" in components["netloc"],
            "has_double_slash_in_path": "//" in path,
            "has_encoded_hostname": "%" in hostname,
            "is_punycode": "xn--" in hostname,
            "has_non_ascii_hostname": not hostname.isascii(),
            "is_url_shortener": self.is_url_shortener(hostname, components["domain"]),
            "has_suspicious_tld": components["tld"] in self.suspicious_tlds,
            "has_non_standard_port": (components["port"] is not None
                                      and components["port"] not in config.STANDARD_PORTS),
            # --- pattern and keyword information ---
            "embedded_domains": self.find_embedded_domains(components["subdomain"]),
            "keyword_matches": self.find_keywords(searchable_text),
            "keywords_in_domain": ([] if has_ip else
                                   self.find_keywords_in_domain(components["domain"],
                                                                components["tld"])),
        }
        return features
