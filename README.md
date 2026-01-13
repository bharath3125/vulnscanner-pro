# VulnScanner Pro 🛡️

A professional, enterprise-grade Web Vulnerability Scanner built with **FastAPI** and **Python**. Featuring a modern, "Cyber Security Dark Mode" UI and comprehensive scanning capabilities based on **OWASP Top 10** standards.

## 🚀 Features

- **Professional UI/UX**:
  - **Dark Mode Dashboard**: Sleek, glassmorphic interface designed for security professionals.
  - **Live Scanning Overlay**: Real-time feedback and status updates.
  - **Interactive Reporting**: Dynamic cards, severity counters, and collapsible findings.

- **Scanning Modes**:
  - **Full Deep Scan**: Runs all available modules for maximum coverage.
  - **OWASP Top 10 Scan**: Targeted checks for critical web application risks.

- **Vulnerability Modules**:
  - 💉 **Injection (A03)**: Advanced SQL Injection (Error-based) and XSS (Reflected) detection.
  - 📦 **Vulnerable Components (A06)**: Detection of outdated libraries (jQuery, Bootstrap, etc.) and server version leakage.
  - � **Broken Access Control (A01)**: Directory enumeration and forbidden resource checking.
  - �️ **Security Misconfiguration (A05)**: Missing security headers and open port scanning (Nmap integration).
  - 🔑 **Identification Failures (A07)**: Checks for weak cookie attributes (HttpOnly, Secure).
  - 🕵️ **Sensitive Data Exposure (A04)**: Scans for leaked emails, API keys, and private keys.

## 🛠️ Tech Stack

- **Backend**: FastAPI, Uvicorn, Python 3.9+
- **Frontend**: HTML5, Modern CSS3 (Variables, Glassmorphism), Vanilla JS
- **Scanning Engine**: HTTPX (Async), BeautifulSoup4, Python-Nmap, Regex
- **Styling**: Bootstrap 5 (Structure) + Custom "Cyber Sec" Theme

## 📂 Project Structure

```
web-vulnerability-scanner/
├── app/
│   ├── main.py                # Application entry point
│   ├── api/                   # API Routes and logic
│   ├── models/                # Pydantic data models
│   ├── scanner/               # Vulnerability scanning modules
│   │   ├── sqli.py            # SQL Injection logic
│   │   ├── xss.py             # XSS logic
│   │   ├── outdated_components.py # A06 Scanner
│   │   └── ...
│   ├── templates/             # HTML Templates (Index, Report)
│   └── static/                # Custom CSS and assets
├── requirements.txt           # Python dependencies
└── README.md                  # Documentation
```

## 🔧 Installation

1. **Clone the repository**:
   ```bash
   git clone <repo-url>
   cd "web vul scanner"
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Nmap** (Optional but recommended):
   - **Windows**: [Download Nmap](https://nmap.org/download.html)
   - **Linux**: `sudo apt install nmap`
   *Note: If Nmap is not found, the port scan module will safely skip.*

## 🏃 Usage

1. **Start the Server**:
   ```bash
   uvicorn app.main:app --reload
   ```

2. **Access the Web Interface**:
   Open your browser and navigate to: "https://vulnscanner-pro.onrender.com"

3. **Run a Scan**:
   - **Target Endpoint**: Enter the URL you want to test (e.g., `http://testphp.vulnweb.com`).
   - **Scan Mode**: Choose between "Full Deep Scan" or "OWASP Top 10".
   - **Launch**: Click "Launch Scanner" and watch the real-time analysis.

## ⚠️ Ethical Disclaimer

**This tool is strictly for educational and authorized testing purposes.** 

- Do **NOT** scan targets you do not own or have explicit written permission to test.
- Unauthorized scanning is illegal and unethical.
- The developers assume no liability for misuse of this tool.

