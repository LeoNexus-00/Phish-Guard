"""
helpers.py - General helper functions used across the project.
"""

import json
from datetime import datetime

import config


def load_json_file(file_path, default_value):
    """Read a JSON file and return its contents.

    If the file is missing or contains invalid JSON, the default value is
    returned instead of crashing the program.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"[PhishGuard] Warning: file not found: {file_path}")
    except json.JSONDecodeError:
        print(f"[PhishGuard] Warning: file contains invalid JSON: {file_path}")
    except OSError as error:
        print(f"[PhishGuard] Warning: could not read {file_path}: {error}")
    return default_value


def get_timestamp():
    """Return the current local date and time as a readable string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def shorten_text(text, max_length=60):
    """Shorten long text for display, adding '...' at the end."""
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def format_text_report(result):
    """Build a plain-text report for a URLResult (used by the CLI and download).

    Args:
        result (URLResult): the analysis result.

    Returns:
        str: a multi-line report.
    """
    line = "-" * 52
    report_lines = [
        line,
        "PHISHGUARD ANALYSIS",
        line,
        "",
        "URL:",
        result.url,
        "",
        "Risk Score:",
        f"{result.risk_score} / {config.MAX_RISK_SCORE}",
        "",
        "Risk Level:",
        result.risk_level.upper(),
        "",
    ]

    for note in result.notes:
        report_lines.append(f"Note: {note}")
    if result.notes:
        report_lines.append("")

    triggered = result.get_triggered_rules()
    if triggered:
        report_lines.append("Detected Indicators:")
        report_lines.append("")
        for rule in triggered:
            report_lines.append(f"[!] {rule.name:<40} +{rule.score}")
            report_lines.append(f"    Detected: {rule.detected}")
            report_lines.append(f"    Reason:   {rule.reason}")
    else:
        report_lines.append("No suspicious indicators were detected.")

    report_lines.extend([
        "",
        line,
        "IMPORTANT:",
        config.DISCLAIMER,
        line,
    ])
    return "\n".join(report_lines)
