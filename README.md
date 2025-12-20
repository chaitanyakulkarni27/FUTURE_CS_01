# WASTF — Web Application Security Testing Framework

WASTF is a comprehensive framework for testing web application security, offering automated scans, vulnerability grading, risk scoring, and multiple report formats. Built with both CLI and optional GUI (PySimpleGUI) interfaces, it empowers security engineers and developers to efficiently analyze targets for modern threats.

---

## Features
- Automated vulnerability scanning with categorized severity (Critical, High, Medium, Low, Info)
- Flexible reporting: generate HTML, JSON, or CSV summaries
- Risk scoring and vulnerability breakdown
- Colored CLI output for clear, actionable results
- Optional GUI with PySimpleGUI
- Integrates: Selenium (web automation), Nmap (network scans), DNS lookups, cryptography, and more
- Extensible with modern Python libraries and plugins

---

## Installation

**Requirements:** Python 3.7+

1. Clone/download the repo and enter the directory:
    ```bash
    cd 'FUTURE_CS_01'
    ```
2. Install all dependencies:
    ```bash
    pip install -r requirements.txt
    ```
   _or, for only core CLI:_
    ```bash
    pip install requests beautifulsoup4 PySimpleGUI colorama
    ```

_Optional: For advanced scans, ensure Nmap, ChromeDriver/geckodriver, etc. are accessible for your OS._

---

## Usage

### CLI Example
Run a scan on a target URL:
```bash
python3 wastf.py --url https://target.com --output html
```

- Use `--help` to view all CLI arguments and options.

### GUI Launch
If you have PySimpleGUI installed, open the GUI:
```bash
python3 wastf.py --gui
```

### Reports
- **HTML**: User-friendly overview (default)
- **JSON**: Data for integrations/automation
- **CSV**: Spreadsheets or custom analysis

---

## Configuration
Configuration (such as API keys, scan tuning) can be managed through `config.yaml`.

---

## Dependencies
A few highlights (full list in `requirements.txt`):
- Core: requests, beautifulsoup4, colorama, PySimpleGUI
- Security: python-nmap, dnspython, pyopenssl, cryptography
- Web automation: selenium, webdriver-manager
- Reporting: jinja2, markdown, xlsxwriter

Development, testing, and advanced utilities are also included for contributors.

---

## Development
- Lint: `flake8 wastf.py`
- Format: `black wastf.py`
- Test: `pytest`

---

## Credits
BY CHAITANYA KULKARNI

---

## License
MIT (or as specified)

## Acknowledgements
Thanks to the maintainers of DNSpython, Selenium, Nmap, PySimpleGUI, and all open-source dependencies.
