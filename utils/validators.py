"""
validators.py - Input validation for URLs entered by the user.

The goal of this module is simple: never let bad input crash the program.
Instead of crashing, we raise our own InvalidURLError with a friendly message
that the user interface can display.
"""

import ipaddress
from urllib.parse import urlsplit

import config


class InvalidURLError(ValueError):
    """Raised when the user's input cannot be analysed as a web URL.

    It inherits from ValueError, so it is a normal Python exception that
    carries a human-readable message.
    """


def is_ip_address(hostname):
    """Return True if the hostname is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _check_basic_text(raw_url):
    """Check the raw text (type, emptiness, length, characters).

    Returns the text with surrounding whitespace removed.
    """
    if raw_url is None or not isinstance(raw_url, str):
        raise InvalidURLError("Please enter a URL.")

    url = raw_url.strip()   # remove spaces/newlines at both ends

    if url == "":
        raise InvalidURLError("The URL cannot be empty. Please type or paste a URL.")

    if len(url) > config.MAX_INPUT_LENGTH:
        raise InvalidURLError(
            f"The input is too long ({len(url)} characters). "
            f"The maximum allowed length is {config.MAX_INPUT_LENGTH} characters."
        )

    for character in url:
        if character.isspace():
            raise InvalidURLError(
                "URLs cannot contain spaces. If a space is needed it must be written as %20."
            )
        if ord(character) < 32 or ord(character) == 127:
            raise InvalidURLError("The URL contains invisible control characters.")

    bad_characters = sorted(set(url) & config.INVALID_URL_CHARACTERS)   # set intersection
    if bad_characters:
        shown = " ".join(bad_characters)
        raise InvalidURLError(f"The URL contains characters that are not allowed: {shown}")

    return url


def _add_or_check_scheme(url, notes):
    """Make sure the URL has a supported scheme (http or https).

    If the scheme is missing, DEFAULT_SCHEME is added and a note is recorded.
    """
    if "://" in url:
        scheme = url.split("://", 1)[0].lower()
        if scheme == "":
            raise InvalidURLError("The URL is malformed: it starts with '://' but has no scheme.")
        if scheme not in config.ALLOWED_SCHEMES:
            raise InvalidURLError(
                f"Unsupported scheme '{scheme}'. Only http:// and https:// URLs can be analysed."
            )
        return url

    # No "://" - check for schemes such as "mailto:" or "javascript:".
    lowered = url.lower()
    for scheme in config.UNSUPPORTED_SCHEMES:
        if lowered.startswith(scheme + ":"):
            raise InvalidURLError(
                f"Unsupported scheme '{scheme}'. Only http:// and https:// URLs can be analysed."
            )

    if url.startswith("//"):
        url = url[2:]

    notes.append(
        f"No scheme (http/https) was given, so '{config.DEFAULT_SCHEME}://' was assumed. "
        "HTTPS could therefore not be confirmed."
    )
    return config.DEFAULT_SCHEME + "://" + url


def _check_hostname(hostname):
    """Check that the hostname is a valid IP address or domain name."""
    if is_ip_address(hostname):
        return

    if hostname.endswith("."):          # "example.com." is a valid full domain
        hostname = hostname[:-1]

    if len(hostname) > config.MAX_HOSTNAME_LENGTH:
        raise InvalidURLError("The hostname is too long to be a valid domain name.")

    labels = hostname.split(".")
    if len(labels) < 2:
        raise InvalidURLError(
            f"The hostname '{hostname}' has no domain extension (for example '.com')."
        )

    for label in labels:
        if label == "":
            raise InvalidURLError(
                f"The hostname '{hostname}' is malformed (it contains empty parts, e.g. '..')."
            )
        if len(label) > config.MAX_LABEL_LENGTH:
            raise InvalidURLError(f"The hostname part '{label[:20]}...' is too long.")
        if label.startswith("-") or label.endswith("-"):
            raise InvalidURLError(
                f"The hostname part '{label}' cannot start or end with a hyphen."
            )
        for character in label:
            # Letters, digits and hyphens are normal. Non-ASCII letters (IDN)
            # and '%' (encoding) are allowed here so the analyser can FLAG them.
            allowed = character.isalnum() or character in "-%"
            if not allowed:
                raise InvalidURLError(
                    f"The hostname contains an invalid character: '{character}'."
                )

    if labels[-1].isdigit():
        raise InvalidURLError(
            f"'{hostname}' looks like an IP address but is not a valid one."
        )


def validate_url(raw_url):
    """Validate and normalise a URL typed by the user.

    Args:
        raw_url (str): the text entered by the user.

    Returns:
        tuple: (normalised_url, notes) where notes is a list of strings
        describing any automatic changes (e.g. an added scheme).

    Raises:
        InvalidURLError: if the input cannot be analysed.
    """
    notes = []
    url = _check_basic_text(raw_url)
    url = _add_or_check_scheme(url, notes)

    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        port = parts.port          # accessing .port raises ValueError if invalid
    except ValueError as error:
        raise InvalidURLError(f"The URL is malformed and could not be parsed ({error}).")

    if not hostname:
        raise InvalidURLError("The URL does not contain a hostname (for example 'example.com').")

    if port is not None and port == 0:
        raise InvalidURLError("Port 0 is not a valid port number.")

    _check_hostname(hostname)
    return url, notes
