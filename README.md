<div align="center">

# Bugscope Security Proxy

### Educational MITM Security Proxy — v2.0

[![Typing SVG](https://readme-typing-svg.demolab.com/?font=Fira+Code&size=22&duration=3000&pause=1000&color=00FF41&background=0D1117&center=true&vCenter=true&width=600&lines=Multi-threaded+MITM+Proxy+in+Python;SQLite+%2B+Flask+Live+Dashboard;Built+for+Educational+Security+Research)](https://git.io/typing-svg)

![Python](https://img.shields.io/badge/Python-3.x-000000?style=for-the-badge&logo=python&logoColor=00FF41&color=0D1117&labelColor=0D1117)
![Flask](https://img.shields.io/badge/Flask-Dashboard-000000?style=for-the-badge&logo=flask&logoColor=00FF41&color=0D1117&labelColor=0D1117)
![SQLite](https://img.shields.io/badge/SQLite-Database-000000?style=for-the-badge&logo=sqlite&logoColor=00FF41&color=0D1117&labelColor=0D1117)
![License](https://img.shields.io/badge/License-MIT-000000?style=for-the-badge&logoColor=00FF41&color=0D1117&labelColor=0D1117)

</div>

---

## About

Bugscope v2.0 is a custom-built, multi-threaded Man-in-the-Middle (MITM) proxy developed in Python. It is designed for educational purposes and Final Year Projects (FYP), intercepting, analyzing, and verifying web application vulnerabilities using a relational database and a live web dashboard.

---

## What's New in Version 2.0 (The FYP Upgrade)

- **Relational Database (SQLite)** — Replaced volatile JSON logging with a persistent, ACID-compliant SQLite database (`bugscope.db`) for historical auditing.
- **Live Web Dashboard (Flask)** — Real-time web UI to visualize intercepted traffic and highlight vulnerabilities instantly.
- **Intelligent Noise Filter** — Regex-based engine that automatically ignores background telemetry (Mozilla, Google, Microsoft) so analysts can focus on actual targets.
- **Robust Core Engine** — Proxy refactored to use the `requests` library, fixing outbound firewall blocks and 502 Bad Gateway errors.

---

## Tech Stack

- Python 3.x
- Flask (dashboard / web UI)
- SQLite (persistent storage via `db_manager.py`)
- `requests` (core proxy engine)

---

## Installation & Setup

### 1. Clone & Prepare the Environment

Requires Python 3.x and Git.

```bash
git clone https://github.com/AqibTayyab/Bugscope-Security-Proxy.git
cd Bugscope-Security-Proxy
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Trust the Certificate (Essential for HTTPS)

1. Locate `certificates/ca-cert.p12` in the cloned folder.
2. In Firefox: **Settings → Privacy & Security → View Certificates → Import**.
3. Select the `.p12` file and check **"Trust this CA to identify websites"**.

---

## Usage

Bugscope v2.0 uses a decoupled, two-process architecture. Run the proxy engine and the dashboard in separate terminal windows.

### Windows

**Window 1 — Proxy Engine** (captures traffic and logs to the database)

```
python proxies\main_educational.py
```

Set Firefox's manual proxy to `127.0.0.1` on port `8080`, and ensure **"Also use this proxy for HTTPS"** is checked.

**Window 2 — Admin Dashboard**

```
python dashboard.py
```

Open Chrome or Edge (without proxy settings) and navigate to `http://127.0.0.1:5000` to view live traffic and vulnerabilities as you browse.

### Kali Linux / Debian

**Terminal 1 — Proxy Engine**

```bash
python3 proxies/main_educational.py
```

**Terminal 2 — Admin Dashboard**

```bash
python3 dashboard.py
```

Open your browser (without proxy settings) and navigate to `http://127.0.0.1:5000`.

### Generate Final Report

When your testing session is complete, stop the proxy (`Ctrl+C`) and generate a Markdown summary:

```bash
python report.py
```

The report is saved to the `reports/` directory.

---

## Project Architecture

```
Bugscope-Security-Proxy/
├── dashboard.py               # Web UI Dashboard (Flask)
├── db_manager.py              # SQLite Database Logic
├── report.py                  # Markdown Report Generator
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation
├── proxies/
│   └── main_educational.py    # Main proxy server engine
├── analysis/
│   └── explainer_db.py        # Vulnerability signature database
├── certificates/
│   ├── ca-cert.p12            # Root certificate for browser
│   └── ca-key.pem             # Private key
├── data/                      # Contains bugscope.db (SQLite)
└── reports/                   # Generated security reports
```

---

## Legal & Ethical Use (Mandatory)

This software, Bugscope, is developed and provided strictly for educational, ethical hacking, and authorized security research purposes only.

By downloading and using this tool, the user agrees to:

- Use Bugscope only on systems they own (e.g., localhost labs like OWASP Juice Shop).
- Use Bugscope only on test targets where they have explicit, written permission to conduct security testing.
- Comply with all applicable laws and regulations.

The author is not responsible for any misuse or illegal activity resulting from the use of this software.

---

## Author

**Project Author:** Muhammad Aqib Tayyab

- GitHub: [AqibTayyab](https://github.com/AqibTayyab)
- LinkedIn: [Muhammad Aqib Tayyab](https://www.linkedin.com/in/muhammad-aqib-tayyab-ethical-hacker/)

---

## License

This project is licensed under the MIT License.
