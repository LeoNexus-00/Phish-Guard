# PhishGuard 🛡️

**PhishGuard** is an educational, rule-based static URL analysis system designed to detect common characteristics of phishing and scam links. 

This is a Semester 3 B.Tech mini-project for the *Introduction to Python Programming* course.

## Features

- **Static Analysis:** Evaluates URLs safely without visiting them or executing malicious code.
- **Rule Engine:** Applies 15 weighted security checks (e.g., HTTPS usage, IP addresses, suspicious keywords, embedded domains, punycode).
- **Risk Scoring:** Computes a configurable risk score (0-100) and categorizes URLs as *Low Risk*, *Suspicious*, or *High Suspicion*.
- **Detailed Explanations:** Explains exactly which indicators triggered and why they are dangerous.
- **Persistent History:** Saves scan records locally in a robust JSON format.
- **Interactive UI:** Built with Streamlit, featuring a scanner, a searchable history table, and an analytics dashboard.
- **CLI Mode:** Includes a simple command-line interface for quick testing.

## Academic Context
This project deliberately avoids opaque libraries or external API calls to fulfill its purpose: demonstrating the core Python concepts covered in the Semester 3 syllabus.
- Employs **Object-Oriented Programming (OOP)** for the analysis engine and data models.
- Uses `urllib.parse` and regular expressions for robust string manipulation.
- Implements comprehensive exception handling for input validation and file I/O operations.
- Adheres to clean architecture (separated core logic, UI, and data models).

## Installation

1. **Clone the repository** (or download the source):
   ```bash
   git clone https://github.com/yourusername/phishguard.git
   cd phishguard
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   python -m venv .venv
   
   # Windows:
   .\.venv\Scripts\activate
   # macOS/Linux:
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Streamlit Web Interface
Run the full graphical application:
```bash
streamlit run app.py
```
This will open the PhishGuard dashboard in your default web browser (usually at `http://localhost:8501`).

### Command-Line Interface (CLI)
Run the lightweight CLI version to scan URLs directly from the terminal:
```bash
python cli.py "http://example-login.com/verify"
```
Or start the interactive CLI loop:
```bash
python cli.py
```

## Running Tests
PhishGuard includes a full test suite built with Python's standard `unittest` framework.

Run all tests from the root directory:
```bash
python -m unittest discover -s tests -v
```

## Disclaimer
> **⚠️ Academic Disclaimer:** PhishGuard is an educational project. It performs static analysis of URL strings and cannot verify the true intent or safety of the server hosting the URL. A "Low Risk" result means no common warning signs were detected in the string; it does **not** guarantee the website is safe. Do not use this as your only defense against phishing.
