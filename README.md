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

## Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/yourusername/wastf.git
cd wastf
python -m venv venv

# Activate virtual environment
# On Windows: venv\Scripts\activate
# On Linux/Mac: source venv/bin/activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Format code
black wastf.py

```

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
### Test a Website
```bash
# Basic scan
python wastf.py https://yourwebsite.com

# Quick scan (limited payloads)
python wastf.py https://yourwebsite.com --quick
# Test specific vulnerabilities
python wastf.py https://yourwebsite.com -t sql xss auth

# Generate JSON report for automation
python wastf.py https://yourwebsite.com -o json
```

### Basic Usage
```bash
# GUI Mode (Recommended for beginners)
python wastf.py

# CLI Mode (For automation)
python wastf.py http://example.com

# Run specific tests
python wastf.py http://example.com -t sql xss

# Generate HTML report
python wastf.py http://example.com -o html
```
### Issue: GUI not opening
```bash
# Solution: Install PySimpleGUI
pip install PySimpleGUI
# Or use CLI mode
python wastf.py http://example.com --no-gui
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
