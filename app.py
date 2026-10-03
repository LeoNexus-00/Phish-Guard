"""
app.py - Streamlit web interface for PhishGuard.

Run with:
    streamlit run app.py

This file only handles the USER INTERFACE. All analysis logic lives in the
core/, models/ and services/ packages, so it can be tested without the UI.

Security note: any text that comes from the user (such as the URL) is passed
through html.escape() before being placed inside custom HTML, so that a URL
containing HTML code cannot change the page (Cross-Site Scripting protection).
"""

import html
import json

import pandas as pd
import streamlit as st

import config
from core.analyzer import URLAnalyzer
from core.risk_calculator import get_level_details, get_risk_level_names
from core.rule_engine import RULE_INFO
from models.scan_record import ScanRecord
from services.history_manager import HistoryManager
from services.statistics import calculate_statistics
from utils.helpers import format_text_report, shorten_text
from utils.validators import InvalidURLError

# ----------------------------------------------------------------------
# Constants used by the interface
# ----------------------------------------------------------------------
PAGES = ("🔍 Scanner", "🗂️ Scan History", "📊 Dashboard", "ℹ️ About")

# Safe, synthetic sample URLs (no real malicious sites).
SAMPLE_URLS = (
    "https://www.example.com/about",
    "http://example-login.com/verify-account",
    "http://198.51.100.7/secure/login.php",
    "https://paypal.com.secure-account.example.net/update",
    "https://bit.ly/3abcXYZ",
    "https://xn--pple-43d.com/signin",
)

# (feature key, readable label) groups for the technical details section.
COMPONENT_FEATURES = (
    ("scheme", "Scheme / protocol"), ("hostname", "Hostname"), ("subdomain", "Subdomain"),
    ("domain", "Registered domain"), ("tld", "Top-level domain"), ("port", "Port"),
    ("path", "Path"), ("query", "Query"), ("fragment", "Fragment"),
)
MEASUREMENT_FEATURES = (
    ("url_length", "URL length"), ("hostname_length", "Hostname length"),
    ("path_length", "Path length"), ("dot_count", "Dots"), ("hyphen_count", "Hyphens (URL)"),
    ("hostname_hyphen_count", "Hyphens (hostname)"), ("subdomain_count", "Subdomain levels"),
    ("digit_count", "Digits (URL)"), ("hostname_digit_count", "Digits (hostname)"),
    ("special_char_count", "Unusual special characters"), ("encoded_char_count", "%-encoded sequences"),
    ("query_param_count", "Query parameters"),
)
INDICATOR_FEATURES = (
    ("uses_https", "Uses HTTPS"), ("has_ip_address", "IP address hostname"),
    ("has_at_symbol", "@ in address"), ("has_double_slash_in_path", "'//' in path"),
    ("has_encoded_hostname", "Encoded hostname"), ("is_punycode", "Punycode (xn--)"),
    ("has_non_ascii_hostname", "Non-ASCII hostname"), ("is_url_shortener", "URL shortener"),
    ("has_suspicious_tld", "Suspicious TLD"), ("has_non_standard_port", "Non-standard port"),
    ("embedded_domains", "Domain inside subdomain"), ("keyword_matches", "Keyword matches"),
    ("keywords_in_domain", "Keywords in domain"),
)

CUSTOM_CSS = """
<style>
.block-container {padding-top: 2rem; max-width: 1200px;}
.pg-hero {background: linear-gradient(135deg, #0f1b33 0%, #0b1220 60%);
          border: 1px solid #1e3a5f; border-radius: 14px; padding: 22px 26px; margin-bottom: 18px;}
.pg-hero h1 {margin: 0; font-size: 2.1rem; color: #e2e8f0;}
.pg-hero p {margin: 6px 0 0 0; color: #94a3b8;}
.pg-accent {color: #22d3ee;}
.pg-card {background: #111a2e; border: 1px solid #1e293b; border-radius: 12px;
          padding: 18px 20px; margin-bottom: 12px;}
.pg-label {color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.06em;}
.pg-score {font-size: 3rem; font-weight: 700; line-height: 1.1;}
.pg-score small {font-size: 1.1rem; color: #64748b; font-weight: 500;}
.pg-badge {display: inline-block; padding: 4px 14px; border-radius: 999px;
           font-weight: 700; color: #0b1220; font-size: 0.95rem;}
.pg-bar-bg {background: #1e293b; height: 12px; border-radius: 6px; overflow: hidden; margin-top: 10px;}
.pg-bar {height: 12px; border-radius: 6px;}
.pg-url {font-family: Consolas, monospace; word-break: break-all; color: #cbd5e1;
         background: #0b1220; border: 1px solid #1e293b; border-radius: 8px; padding: 8px 10px;}
.pg-indicator {background: #111a2e; border: 1px solid #1e293b; border-left: 4px solid #f59e0b;
               border-radius: 10px; padding: 12px 16px; margin-bottom: 10px;}
.pg-indicator-head {display: flex; justify-content: space-between; font-weight: 600;}
.pg-points {color: #f87171; font-family: Consolas, monospace;}
.pg-detected {color: #fbbf24; font-family: Consolas, monospace; font-size: 0.9rem; word-break: break-all;}
.pg-reason {color: #cbd5e1; font-size: 0.92rem; margin-top: 4px;}
.pg-level-row {margin-bottom: 12px;}
</style>
"""


# ----------------------------------------------------------------------
# Shared helpers
# ----------------------------------------------------------------------
@st.cache_resource
def get_analyzer():
    """Create ONE URLAnalyzer and reuse it (data files are read only once)."""
    return URLAnalyzer()


def escape(text):
    """Escape user-provided text before inserting it into HTML."""
    return html.escape(str(text))


def format_value(value):
    """Convert a feature value into readable text for tables."""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if value is None or value == "" or value == [] or value == {}:
        return "-"
    if isinstance(value, dict):
        parts = []
        for key, items in value.items():
            parts.append(f"{key}: {', '.join(items)}")
        return "; ".join(parts)
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)


def features_to_table(features, feature_list):
    """Build a two-column DataFrame (Feature, Value) for a group of features."""
    rows = []
    for key, label in feature_list:
        rows.append({"Feature": label, "Value": format_value(features.get(key))})
    return pd.DataFrame(rows)


def set_flash(message):
    """Store a success message to show after the page reloads."""
    st.session_state["flash_message"] = message


def show_flash():
    """Show (and remove) a stored success message, if any."""
    message = st.session_state.pop("flash_message", None)
    if message:
        st.success(message)


def render_hero(title, subtitle):
    st.markdown(
        f'<div class="pg-hero"><h1>{title}</h1><p>{subtitle}</p></div>',
        unsafe_allow_html=True,
    )


def render_sidebar():
    """Draw the sidebar navigation and return the selected page name."""
    with st.sidebar:
        st.markdown("## 🛡️ Phish<span class='pg-accent'>Guard</span>", unsafe_allow_html=True)
        st.caption("Phishing & Scam URL Detection System")
        page = st.radio("Navigation", PAGES, label_visibility="collapsed")
        st.divider()
        st.caption("🔒 **Static analysis only.** Submitted URLs are never opened, "
                   "visited or downloaded.")
        st.caption("Semester 3 · Introduction to Python Programming mini-project")
    return page


# ----------------------------------------------------------------------
# Scanner page
# ----------------------------------------------------------------------
def use_sample(url):
    """Button callback: copy a sample URL into the input box."""
    st.session_state["url_input"] = url


def page_scanner():
    render_hero("🛡️ Phish<span class='pg-accent'>Guard</span>",
                "Paste a URL to check it for characteristics commonly seen in phishing and "
                "scam links. The URL is analysed as text only and is never visited.")

    with st.expander("Need an example? Try a safe sample URL"):
        columns = st.columns(3)
        for index, sample in enumerate(SAMPLE_URLS):
            columns[index % 3].button(shorten_text(sample, 42), key=f"sample_{index}",
                                      on_click=use_sample, args=(sample,), width="stretch")

    with st.form("scan_form"):
        st.text_input("URL to analyse", key="url_input",
                      placeholder="e.g. https://www.example.com/login")
        left, right = st.columns([3, 1])
        save_scan = left.checkbox("Save this scan to history", value=True)
        submitted = right.form_submit_button("🔍 Analyze URL", type="primary", width="stretch")

    if submitted:
        run_scan(st.session_state.get("url_input", ""), save_scan)

    result = st.session_state.get("last_result")
    if result is not None:
        render_result(result)


def run_scan(raw_url, save_scan):
    """Analyse the URL, store the result in the session and optionally save it."""
    try:
        result = get_analyzer().analyze(raw_url)
    except InvalidURLError as error:
        st.session_state["last_result"] = None
        st.error(f"**Invalid URL:** {error}")
        return
    except Exception as error:              # safety net: never show a crash page
        st.session_state["last_result"] = None
        st.error(f"An unexpected error occurred while analysing the URL: {error}")
        return

    st.session_state["last_result"] = result
    if save_scan:
        manager = HistoryManager()
        if not manager.save_scan(ScanRecord.from_result(result)):
            st.warning(f"The result could not be saved to history. {manager.last_warning}")


def render_result(result):
    """Show the full analysis report for a URLResult."""
    colour, description = get_level_details(result.risk_level)
    triggered = result.get_triggered_rules()

    st.markdown("### Scan Result")
    left, right = st.columns([1, 2])
    with left:
        st.markdown(
            f"""<div class="pg-card">
                <div class="pg-label">Risk score</div>
                <div class="pg-score" style="color:{colour}">{result.risk_score}
                    <small>/ {config.MAX_RISK_SCORE}</small></div>
                <div class="pg-bar-bg"><div class="pg-bar"
                    style="width:{result.risk_score}%; background:{colour}"></div></div>
            </div>""",
            unsafe_allow_html=True,
        )
    with right:
        st.markdown(
            f"""<div class="pg-card">
                <div class="pg-label">Risk level</div>
                <span class="pg-badge" style="background:{colour}">{escape(result.risk_level.upper())}</span>
                <span style="color:#94a3b8; margin-left:10px">{len(triggered)} of
                    {len(result.rule_results)} checks flagged</span>
                <p style="margin:10px 0 8px 0">{escape(description)}</p>
                <div class="pg-url">{escape(result.url)}</div>
            </div>""",
            unsafe_allow_html=True,
        )

    for note in result.notes:
        st.info(note, icon="ℹ️")
    st.warning(config.DISCLAIMER, icon="⚠️")

    st.markdown("#### Detected Indicators")
    if not triggered:
        st.success("No common phishing indicators were found in this URL. "
                   "Remember: this does not guarantee the website is safe.")
    for rule in triggered:
        st.markdown(
            f"""<div class="pg-indicator">
                <div class="pg-indicator-head"><span>⚠️ {escape(rule.name)}</span>
                    <span class="pg-points">+{rule.score}</span></div>
                <div class="pg-detected">Detected: {escape(rule.detected)}</div>
                <div class="pg-reason">{escape(rule.reason)}</div>
            </div>""",
            unsafe_allow_html=True,
        )
    raw_score = result.get_raw_score()
    if raw_score > config.MAX_RISK_SCORE:
        st.caption(f"The indicators add up to {raw_score} points; the score is capped "
                   f"at {config.MAX_RISK_SCORE}.")

    with st.expander(f"✅ All security checks ({len(result.rule_results)})"):
        rows = []
        for rule in result.rule_results:
            status = "⚠️ Flagged" if rule.triggered else "✅ Passed"
            rows.append({"Check": rule.name, "Status": status, "Detected": rule.detected,
                         "Points": rule.score, "Explanation": rule.reason})
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")

    with st.expander("🔬 Technical URL features"):
        first, second = st.columns(2)
        with first:
            st.markdown("**URL components**")
            st.dataframe(features_to_table(result.features, COMPONENT_FEATURES),
                         hide_index=True, width="stretch")
            st.markdown("**Indicators**")
            st.dataframe(features_to_table(result.features, INDICATOR_FEATURES),
                         hide_index=True, width="stretch")
        with second:
            st.markdown("**Measurements**")
            st.dataframe(features_to_table(result.features, MEASUREMENT_FEATURES),
                         hide_index=True, width="stretch")

    with st.expander("📄 Text report"):
        report = format_text_report(result)
        st.code(report, language=None)
        st.download_button("Download report (.txt)", report, file_name="phishguard_report.txt",
                           mime="text/plain")


# ----------------------------------------------------------------------
# History page
# ----------------------------------------------------------------------
def sort_records(records, order):
    """Return the records sorted according to the selected option."""
    if order == "Oldest first":
        return list(reversed(records))
    if order == "Highest score":
        return sorted(records, key=lambda record: record.risk_score, reverse=True)
    if order == "Lowest score":
        return sorted(records, key=lambda record: record.risk_score)
    return records                              # "Newest first" (file order)


def page_history():
    render_hero("🗂️ Scan History", "Previously analysed URLs stored in a local JSON file.")
    show_flash()

    manager = HistoryManager()
    all_records = manager.load_history()
    if manager.last_warning:
        st.warning(manager.last_warning)
    if not all_records:
        st.info("No scans have been saved yet. Analyse a URL on the Scanner page to start.")
        return

    col_search, col_levels, col_sort = st.columns([2, 2, 1])
    search_text = col_search.text_input("Search URL", placeholder="e.g. login or example.com")
    levels = col_levels.multiselect("Risk level", get_risk_level_names(),
                                    default=get_risk_level_names())
    order = col_sort.selectbox("Sort", ("Newest first", "Oldest first",
                                        "Highest score", "Lowest score"))

    records = sort_records(manager.search(search_text, levels), order)
    st.caption(f"Showing {len(records)} of {len(all_records)} saved scans.")

    if records:
        rows = []
        for record in records:
            rows.append({"Timestamp": record.timestamp, "URL": record.url,
                         "Risk Score": record.risk_score, "Risk Level": record.risk_level,
                         "Indicators": len(record.detected_rules)})
        st.dataframe(
            pd.DataFrame(rows), hide_index=True, width="stretch",
            column_config={
                "Risk Score": st.column_config.ProgressColumn(
                    "Risk Score", min_value=0, max_value=config.MAX_RISK_SCORE, format="%d"),
            },
        )
        render_history_details(manager, records)
    else:
        st.info("No scans match the current filters.")

    render_history_management(manager, all_records)


def render_history_details(manager, records):
    """Let the user inspect or delete a single saved scan."""
    st.markdown("#### Scan details")
    options = {}
    for record in records:
        label = f"{record.timestamp} | {record.risk_score:>3} | {shorten_text(record.url, 70)}"
        options[label] = record
    choice = st.selectbox("Select a scan", list(options.keys()))
    record = options[choice]

    colour, description = get_level_details(record.risk_level)
    st.markdown(
        f"""<div class="pg-card">
            <span class="pg-badge" style="background:{colour}">{escape(record.risk_level.upper())}</span>
            <span style="margin-left:10px; font-weight:600">{record.risk_score} / {config.MAX_RISK_SCORE}</span>
            <span style="color:#94a3b8; margin-left:10px">{escape(record.timestamp)}</span>
            <div class="pg-url" style="margin-top:10px">{escape(record.url)}</div>
        </div>""",
        unsafe_allow_html=True,
    )
    if record.detected_rules:
        rule_rows = []
        for rule in record.detected_rules:
            rule_rows.append({"Indicator": rule.get("name", ""), "Detected": rule.get("detected", ""),
                              "Points": rule.get("score", 0), "Reason": rule.get("reason", "")})
        st.dataframe(pd.DataFrame(rule_rows), hide_index=True, width="stretch")
    else:
        st.success("No indicators were detected in this scan.")

    if st.button("🗑️ Delete this scan", key=f"delete_{record.scan_id}"):
        if manager.delete_scan(record.scan_id):
            set_flash("The scan was deleted.")
            st.rerun()
        else:
            st.error(f"The scan could not be deleted. {manager.last_warning}")


def render_history_management(manager, all_records):
    """Download or clear the whole history."""
    with st.expander("⚙️ Manage history"):
        data = []
        for record in all_records:
            data.append(record.to_dict())
        st.download_button("⬇️ Download history (JSON)", json.dumps(data, indent=4),
                           file_name="phishguard_history.json", mime="application/json")
        st.markdown("---")
        confirm = st.checkbox("I understand that clearing the history cannot be undone.")
        if st.button("Clear all history", type="primary", disabled=not confirm):
            if manager.clear_history():
                set_flash("The scan history was cleared.")
                st.rerun()
            else:
                st.error(f"The history could not be cleared. {manager.last_warning}")


# ----------------------------------------------------------------------
# Dashboard page
# ----------------------------------------------------------------------
def render_level_bars(level_counts, total):
    """Draw one coloured progress bar per risk level."""
    for label, count in level_counts.items():
        colour, description = get_level_details(label)
        percent = round(count * 100 / total) if total else 0
        st.markdown(
            f"""<div class="pg-level-row">
                <div style="display:flex; justify-content:space-between">
                    <span>{escape(label)}</span><span style="color:#94a3b8">{count} ({percent}%)</span>
                </div>
                <div class="pg-bar-bg"><div class="pg-bar"
                    style="width:{percent}%; background:{colour}"></div></div>
            </div>""",
            unsafe_allow_html=True,
        )


def page_dashboard():
    render_hero("📊 Dashboard", "Statistics calculated from your saved scan history.")

    manager = HistoryManager()
    records = manager.load_history()
    if manager.last_warning:
        st.warning(manager.last_warning)
    stats = calculate_statistics(records)
    counts = stats["level_counts"]

    columns = st.columns(5)
    columns[0].metric("Total URLs scanned", stats["total_scans"], border=True)
    columns[1].metric("🟢 Low Risk", counts.get("Low Risk", 0), border=True)
    columns[2].metric("🟠 Suspicious", counts.get("Suspicious", 0), border=True)
    columns[3].metric("🔴 High Suspicion", counts.get("High Suspicion", 0), border=True)
    columns[4].metric("Average risk score", stats["average_score"], border=True)

    if stats["total_scans"] == 0:
        st.info("No data yet. Analyse a few URLs on the Scanner page to see statistics.")
        return

    left, right = st.columns(2)
    with left:
        st.markdown("#### Risk level distribution")
        with st.container(border=True):
            render_level_bars(counts, stats["total_scans"])
            st.caption(f"Unique registered domains scanned: {stats['unique_domains']}")
    with right:
        st.markdown("#### Most common indicators")
        if stats["top_indicators"]:
            indicator_rows = []
            for name, count in stats["top_indicators"]:
                indicator_rows.append({"Indicator": name, "Times detected": count})
            st.dataframe(
                pd.DataFrame(indicator_rows), hide_index=True, width="stretch",
                column_config={"Times detected": st.column_config.ProgressColumn(
                    "Times detected", min_value=0, max_value=stats["total_scans"], format="%d")},
            )
        else:
            st.success("No indicators have been detected in any saved scan.")

    st.markdown("#### Risk scores of the 20 most recent scans")
    recent = list(reversed(records[:20]))           # oldest -> newest, left to right
    chart_rows = []
    for number, record in enumerate(recent, start=1):
        chart_rows.append({"Scan": number, "Risk Score": record.risk_score})
    st.bar_chart(pd.DataFrame(chart_rows), x="Scan", y="Risk Score", color="#22d3ee")

    highest = stats["highest_record"]
    if highest is not None:
        colour, description = get_level_details(highest.risk_level)
        st.markdown("#### Highest-risk scan")
        st.markdown(
            f"""<div class="pg-card">
                <span class="pg-badge" style="background:{colour}">{highest.risk_score} / {config.MAX_RISK_SCORE}</span>
                <span style="color:#94a3b8; margin-left:10px">{escape(highest.timestamp)}</span>
                <div class="pg-url" style="margin-top:10px">{escape(highest.url)}</div>
            </div>""",
            unsafe_allow_html=True,
        )


# ----------------------------------------------------------------------
# About page
# ----------------------------------------------------------------------
def build_rules_table():
    """Create a table of all rules and their points (read from config)."""
    rows = []
    for rule_id, (name, description) in RULE_INFO.items():
        if rule_id == "suspicious_keywords":
            points = (f"+{config.KEYWORD_SCORE_PER_CATEGORY} per category "
                      f"(max {config.KEYWORD_MAX_SCORE})")
        elif rule_id == "url_length":
            points = (f"+{config.RULE_WEIGHTS['url_length']} (> {config.LONG_URL_LENGTH} chars), "
                      f"+{config.RULE_WEIGHTS['url_length_very_long']} "
                      f"(> {config.VERY_LONG_URL_LENGTH} chars)")
        else:
            points = f"+{config.RULE_WEIGHTS.get(rule_id, 0)}"
        rows.append({"Rule": name, "Points": points, "What it checks": description})
    return pd.DataFrame(rows)


def page_about():
    render_hero("ℹ️ About PhishGuard",
                "An educational, rule-based system for static analysis of URLs.")

    st.markdown("""
#### What is phishing?
Phishing is a type of online fraud in which an attacker pretends to be a trusted
organisation (a bank, a college portal, a delivery company, a social network...) to
trick people into revealing passwords, OTPs, card numbers or other personal data.
Phishing links are usually delivered by e-mail, SMS, WhatsApp or social media, and often
lead to fake login pages that look exactly like the real ones.

#### What does this project do?
PhishGuard examines **only the text of a URL** and looks for characteristics that are
common in phishing and scam links:
""")
    st.markdown("""
1. **Validation** – checks that the input is a proper `http`/`https` URL.
2. **Parsing** – splits the URL into scheme, hostname, domain, path, query, etc.
   using Python's `urllib.parse`.
3. **Feature extraction** – measures lengths, counts characters and detects patterns.
4. **Rule engine** – applies the weighted rules below; each rule explains *why* it matters.
5. **Risk scoring** – adds the points (capped at 100) and assigns a risk level.
6. **History & dashboard** – stores scans in a JSON file and shows statistics.
""")

    st.markdown("#### Scoring rules")
    st.dataframe(build_rules_table(), hide_index=True, width="stretch")

    level_rows = []
    lower_limit = 0
    for upper_limit, label, colour, description in config.RISK_LEVELS:
        level_rows.append({"Score range": f"{lower_limit} – {upper_limit}",
                           "Risk level": label, "Meaning": description})
        lower_limit = upper_limit + 1
    st.markdown("#### Risk levels")
    st.dataframe(pd.DataFrame(level_rows), hide_index=True, width="stretch")

    st.markdown("""
#### Limitations
- **False positives:** a legitimate URL can be flagged (for example a real bank whose
  domain contains the word *bank*, or a long tracking link).
- **False negatives:** a phishing URL can look completely normal, e.g. a short HTTPS
  address on a newly registered domain, or a page hosted on a compromised legitimate site.
- The keyword, URL-shortener and TLD lists are small local lists and can never be complete.
- The registered-domain detection uses a simplified list of public suffixes.
- Redirects, page content, domain age and SSL certificate details are **not** checked,
  because doing so would require visiting the website.

#### Why static URL analysis cannot guarantee safety
The system never connects to the website, so it cannot see what the page actually
contains or where it redirects. Attackers can also deliberately choose URLs that avoid
every warning sign. A **Low Risk** result therefore means *"no common warning signs were
found in the URL text"* – **not** *"this website is safe"*. Always verify the sender,
type important addresses yourself, and never enter passwords from a link you did not expect.

#### Safety by design
- URLs are **never** opened, fetched, downloaded or executed.
- No external APIs or online services are contacted.
- All data (reference lists and history) is stored locally in JSON files.
- User input is escaped before being displayed to prevent HTML/script injection.
""")
    st.info("**Academic disclaimer:** PhishGuard is a Semester 3 educational mini-project for the "
            "course *Introduction to Python Programming*. It is not a commercial security product "
            "and must not be relied upon as the only protection against phishing.", icon="🎓")


# ----------------------------------------------------------------------
# Main program
# ----------------------------------------------------------------------
def main():
    st.set_page_config(page_title="PhishGuard – URL Risk Analysis", page_icon="🛡️",
                       layout="wide")
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

    page = render_sidebar()
    if page == PAGES[0]:
        page_scanner()
    elif page == PAGES[1]:
        page_history()
    elif page == PAGES[2]:
        page_dashboard()
    else:
        page_about()


if __name__ == "__main__":
    main()
