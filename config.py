"""
config.py - Central configuration for PhishGuard.

Every "magic number" used by the analyzer lives in this file so that
the behaviour of the system can be tuned in ONE place without touching
the logic. For example, to make the HTTPS rule stricter you only need
to change RULE_WEIGHTS["https_check"].
"""

import os

# ----------------------------------------------------------------------
# File paths (built relative to this file, so no absolute paths are used)
# ----------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

HISTORY_FILE = os.path.join(DATA_DIR, "scan_history.json")
KEYWORDS_FILE = os.path.join(DATA_DIR, "suspicious_keywords.json")
SHORTENERS_FILE = os.path.join(DATA_DIR, "url_shorteners.json")
SUSPICIOUS_TLDS_FILE = os.path.join(DATA_DIR, "suspicious_tlds.json")

# Maximum number of scans kept in the history file (oldest are removed).
MAX_HISTORY_ENTRIES = 500

# ----------------------------------------------------------------------
# Input validation settings
# ----------------------------------------------------------------------
MAX_INPUT_LENGTH = 2048            # characters; longer input is rejected
MAX_HOSTNAME_LENGTH = 253          # limit defined by the DNS standard
MAX_LABEL_LENGTH = 63              # each part between dots in a hostname

ALLOWED_SCHEMES = ("http", "https")            # tuple: never changes at runtime
DEFAULT_SCHEME = "http"                        # used when the user omits it

# Schemes that are recognised but NOT supported (they are not web pages,
# or can be dangerous, e.g. "javascript:").
UNSUPPORTED_SCHEMES = ("ftp", "file", "mailto", "javascript", "data",
                       "vbscript", "tel", "ssh", "telnet")

# Characters that are never allowed to appear in a URL (RFC 3986).
INVALID_URL_CHARACTERS = set('<>"{}|\\^`')

# ----------------------------------------------------------------------
# Feature extraction settings
# ----------------------------------------------------------------------
# Characters that are uncommon in normal URLs. Ordinary URL characters such
# as / . - _ ? = & # : are deliberately NOT included.
SPECIAL_CHARACTERS = set("@~!$*()+[],;'")

# Public suffixes that consist of two labels. Used to find the
# "registered domain" (e.g. example.co.uk instead of co.uk).
# This is a small, simplified list for educational purposes.
TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "co.in", "org.in", "net.in", "ac.in", "edu.in", "gov.in", "res.in",
    "com.au", "net.au", "org.au", "edu.au",
    "co.jp", "co.nz", "co.za", "com.br", "com.cn", "com.sg",
}

# ----------------------------------------------------------------------
# Rule thresholds
# ----------------------------------------------------------------------
LONG_URL_LENGTH = 75               # URL length that is considered "long"
VERY_LONG_URL_LENGTH = 150         # URL length that is considered "very long"
MAX_NORMAL_SUBDOMAINS = 2          # more than this is flagged ("www" ignored)
MAX_NORMAL_HOSTNAME_HYPHENS = 2    # more than this is flagged
MAX_NORMAL_SPECIAL_CHARS = 3       # more than this is flagged
MAX_NORMAL_ENCODED_CHARS = 4       # more %XX sequences than this is flagged
MAX_NORMAL_HOSTNAME_DIGITS = 4     # more digits than this in hostname is flagged
STANDARD_PORTS = (80, 443)

# ----------------------------------------------------------------------
# Rule weights (risk points added when a rule is triggered)
# Set a weight to 0 to effectively disable a rule.
# ----------------------------------------------------------------------
RULE_WEIGHTS = {
    "https_check": 10,
    "ip_address": 25,
    "at_symbol": 20,
    "keyword_in_domain": 10,
    "url_length": 10,
    "url_length_very_long": 15,
    "subdomains": 10,
    "hyphens": 10,
    "special_characters": 10,
    "url_shortener": 10,
    "punycode": 20,
    "url_encoding": 10,
    "suspicious_tld": 10,
    "non_standard_port": 10,
    "hostname_digits": 5,
    "embedded_domain": 15,
}

# Common top-level domains. If one of these appears as a SUBDOMAIN label
# (e.g. "paypal.com.example.net"), a trusted domain name is being imitated.
COMMON_TLDS = ("com", "net", "org", "in", "co", "gov", "edu", "info", "biz")

# The keyword rule is scored per category, with an upper limit.
KEYWORD_SCORE_PER_CATEGORY = 10
KEYWORD_MAX_SCORE = 30

# ----------------------------------------------------------------------
# Risk classification
# ----------------------------------------------------------------------
MAX_RISK_SCORE = 100

# Each tuple is: (upper score limit, label, colour, short description).
# The list is checked from top to bottom, so it must be in ascending order.
RISK_LEVELS = (
    (20, "Low Risk", "#22c55e",
     "Few or no common phishing indicators were found."),
    (50, "Suspicious", "#f59e0b",
     "Some characteristics often seen in phishing URLs were found. Be careful."),
    (100, "High Suspicion", "#ef4444",
     "Potentially phishing: several strong warning signs were found."),
)

DISCLAIMER = (
    "This result is a risk assessment based only on the characteristics of "
    "the URL text. It does not prove that a website is malicious or safe."
)
