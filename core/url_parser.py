"""
url_parser.py - Splits a URL into its components.

Example:
    https://login.secure.example.co.uk:8080/path/page?id=5#top

    scheme    -> https
    hostname  -> login.secure.example.co.uk
    subdomain -> login.secure
    domain    -> example.co.uk   (the "registered" domain)
    tld       -> co.uk
    port      -> 8080
    path      -> /path/page
    query     -> id=5
    fragment  -> top

The heavy lifting is done by urllib.parse.urlsplit from the standard library,
which follows the official URL standard. We only add the domain/subdomain split.
"""

from urllib.parse import urlsplit

import config
from utils.validators import is_ip_address


def split_hostname(hostname):
    """Split a hostname into (subdomain, domain, tld).

    For an IP address there is no domain structure, so the whole IP is
    returned as the domain.

    >>> split_hostname("mail.google.com")
    ('mail', 'google.com', 'com')
    """
    if is_ip_address(hostname):
        return "", hostname, ""

    hostname = hostname.rstrip(".")
    labels = hostname.split(".")

    # Decide how many labels belong to the public suffix (e.g. "com" or "co.uk").
    last_two = ".".join(labels[-2:])
    if len(labels) >= 3 and last_two in config.TWO_LEVEL_SUFFIXES:
        suffix_size = 2
    else:
        suffix_size = 1

    tld = ".".join(labels[-suffix_size:])
    domain = ".".join(labels[-(suffix_size + 1):])        # suffix + one more label
    subdomain = ".".join(labels[: -(suffix_size + 1)])    # everything before that
    return subdomain, domain, tld


def parse_url(url):
    """Break a (validated) URL into a dictionary of components.

    Args:
        url (str): a URL that has already passed validation.

    Returns:
        dict: the URL components.
    """
    parts = urlsplit(url)
    hostname = parts.hostname or ""
    subdomain, domain, tld = split_hostname(hostname)

    return {
        "scheme": parts.scheme.lower(),
        "netloc": parts.netloc,
        "hostname": hostname,
        "subdomain": subdomain,
        "domain": domain,
        "tld": tld,
        "port": parts.port,
        "path": parts.path,
        "query": parts.query,
        "fragment": parts.fragment,
    }
