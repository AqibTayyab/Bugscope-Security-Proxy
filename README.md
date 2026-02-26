# 🔥 Bugscope: Educational MITM Security Proxy (v2.0)

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Database](https://img.shields.io/badge/Database-SQLite-informational?style=for-the-badge)
![UI](https://img.shields.io/badge/UI-Flask_Dashboard-success?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Bugscope v2.0** is a custom-built, multi-threaded Man-in-the-Middle (MITM) proxy developed in Python. Designed for educational purposes and Final Year Projects (FYP), it intercepts, analyzes, and verifies web application vulnerabilities using a Relational Database and a live Web Dashboard.

---

## 🚀 What's New in Version 2.0 (The FYP Upgrade)

* **Relational Database (SQLite):** Replaced volatile JSON logging with a persistent, ACID-compliant SQLite database (`bugscope.db`) for historical auditing.
* **Live Web Dashboard (Flask):** Added a real-time web UI to visualize intercepted traffic and highlight vulnerabilities instantly.
* **Intelligent Noise Filter:** Implemented a Regex-based engine to automatically ignore background telemetry (Mozilla, Google, Microsoft) so analysts can focus on actual targets.
* **Robust Core Engine:** Refactored the proxy to use the `requests` library, fixing outbound firewall blocks and 502 Bad Gateway errors.

---
## 🛠️ Installation & Setup

### 1. Clone & Prepare the Environment
Assuming you have Python 3.x and Git installed:
```cmd
git clone https://github.com/AqibTayyab/Bugscope-Security-Proxy.git
cd Bugscope-Security-Proxy
```
### 2. Install Dependencies
Install the required networking, cryptography, and web framework libraries:
```cmd
pip install -r requirements.txt
```
### 3. Trust the Certificate (Essential for HTTPS)
1. Locate ```certificates/ca-cert.p12``` in the cloned folder.
2. In Firefox: Go to **Settings → Privacy & Security → View Certificates → Import.**
3. Select the ```.p12``` file and check "Trust this CA to identify websites".

---
## 💻 How to Run the System (Dual-Window Setup)
Bugscope v2.0 uses a decoupled, professional architecture. You need two Command Prompts running simultaneously.

### Window 1: Start the Proxy Engine
This captures the traffic and logs it to the database.
```cmd
python proxies\main_educational.py
```
Browser Configuration: Set your Firefox manual proxy to ```127.0.0.1``` on Port ```8080```. Ensure "Also use this proxy for HTTPS" is checked.

### Window 2: Start the Admin Dashboard
This provides the live graphical interface.
```cmd
python dashboard.py
```
Open Chrome or Edge (without proxy settings) and navigate to ```http://127.0.0.1:5000``` to view live traffic and vulnerabilities as you browse.

## 🐉 For Kali Linux / Debian Users
### Terminal 1: Start the Proxy Engine
This captures the traffic and logs it to the database.
```Bash
python3 proxies/main_educational.py
```
Browser Configuration: Set your Firefox manual proxy to ```127.0.0.1``` on Port ```8080```. Ensure "Also use this proxy for HTTPS" is checked.

## Terminal 2: Start the Admin Dashboard
This provides the live graphical interface.
```Bash
python3 dashboard.py
```
Open your web browser (without proxy settings) and navigate to ```http://127.0.0.1:5000``` to view live traffic.

---
## 📊 Generate Final Report
When your testing session is complete, stop the proxy (Ctrl+C) and generate a professional Markdown summary:
```cmd
python report.py
```
The final report will be saved in the ```reports/``` directory.

---
## 📁 Project Architecture (v2.0)
```Plaintext
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

## ⚠️ Legal & Ethical Use (MANDATORY)
This software, Bugscope, is developed and provided strictly for educational, ethical hacking, and authorized security research purposes only.

By downloading and using this tool, the user agrees to:

1. **Use Bugscope only on systems they own** (e.g., localhost labs like OWASP Juice Shop).

2. **Use Bugscope only on test targets where they have explicit, written permission** to conduct security testing.

3. Comply with all applicable laws and regulations.

**The author is not responsible for any misuse or illegal activity resulting from the use of this software.**

---
## 🙋‍♂️ Author
**Project Author: Muhammad Aqib Tayyab**

**LinkedIn: [Muhammad Aqib Tayyab](https://www.linkedin.com/in/muhammad-aqib-tayyab-ethical-hacker/)**

**GitHub: [AqibTayyab](https://github.com/AqibTayyab)**

---
