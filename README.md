# 🔥 Bugscope: Educational MITM Security Proxy (Python)

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Focus](https://img.shields.io/badge/Focus-Network%20Security%20&%20Pentesting-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Project%20Complete-success?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Bugscope** is a custom-built, highly robust, multi-threaded Man-in-the-Middle (MITM) proxy developed in Python to intercept, analyze, and verify web application vulnerabilities (SQL Injection, XSS, etc.) for ethical security education.

---

## 🧠 Technical Case Study: Key Challenges Solved

The core value of this project is overcoming complex, non-intuitive networking and data challenges that are often the hardest part of building custom security tools.

### 1. The Outbound Firewall Bypass (Fixing 502 Errors)

| Challenge | Technical Implementation | Outcome |
| :--- | :--- | :--- |
| **Raw Socket Blocking** | Local security firewalls blocked raw Python sockets, causing persistent `502 Bad Gateway` errors for external targets. | **Fixed:** Refactored the HTTP forwarding core to use the high-level **`requests` library**, which successfully bypassed the firewall's aggressive socket block. |

### 2. Intelligent Report Filtering (Cleaning Telemetry Noise)

| Challenge | Technical Implementation | Outcome |
| :--- | :--- | :--- |
| **Report Data Overload** | Browser telemetry requests (containing unique GUIDs) masked the actual security findings in the reports. | **Fixed:** Implemented **Intelligent Path Cleaning** using **Regular Expressions (Regex)** to replace unique IDs with a standardized token (`[GUID]`). Reports are now clean and focused. |

### 3. Vulnerability Verification (The Final Proof)

* **Finding:** Bugscope flagged the `/login.php` endpoint on a test site as **🔥 Critical Severity**.
* **Action:** Executed the suggested **SQL Injection payload (`' OR '1'='1`)**.
* **Result:** **SUCCESS.** Gained unauthorized access, verifying the Broken Authentication flaw and validating the tool's effectiveness.

---

# 🛠️ Installation & Usage Guide

## 1. Clone & Prepare the Environment
 Assuming you have Python 3.x and Git installed, use these commands:
```bash
git clone https://github.com/AqibTayyab/Bugscope-Security-Proxy.git
```
```bash
cd Bugscope-Security-Proxy
```
```bash
pip install cryptography requests
```

## 2. Set Up Test Target
**Option A: Local Lab (Recommended)**
```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
```
Visit: http://localhost:3000

**Option B: External Target**
Simply browse to your authorized target's URL.

**⚠️ CRITICAL:** Ensure you have explicit, written permission to test the target website.

## 3. Certificate Setup (Essential for HTTPS)
1. Locate certificates/ca-cert.p12 in the cloned folder
2. In Firefox: Settings → Privacy & Security → View Certificates → Import
3. Select the .p12 file and check "Trust this CA to identify websites"


## 4.  Run Proxy & Configure Browser
 Bugscope is ready to test any authorized web application.
```bash
python proxies/main_educational.py
```
**Browser Configuration:**
1. Set manual proxy to your system's IP address (e.g., 192.168.1.5)
2. Port: 8080
3. ✅ Also use this proxy for HTTPS

## 5. Capture Traffic & Generate Report
1. **Perform your security testing**
2. **Stop the proxy** by pressing Ctrl+C
 If program doesn't stop, close and reopen Firefox
3. **Generate analysis report:**
```bash
python analysis/report.py
```
4. **View Report**: Terminal provides the exact command to open the final, filtered security report

## 📊 Sample Terminal Output
```text
🔓 [HTTPS] POST testphp.vulnweb.com/login.php
   📚 Authentication endpoint detected
   💡 Try: Test SQL injection: ' OR '1'='1
   🔥 Severity: Critical
   ✅ Response: 200
```

## 📁 Project Architecture
```text
Bugscope-Security-Proxy/
├── proxies/
│   └── main_educational.py    # Main proxy server
├── analysis/
│   ├── report.py              # Report generator
│   └── explainer_db.py        # Vulnerability database (15+ patterns)
├── certificates/
│   ├── ca-cert.p12            # Root certificate
│   └── ca-key.pem             # Private key
├── data/                      # Session logs
├── reports/                   # Generated security reports
└── requirements.txt           # Python dependencies
```
## 🔧 Key Features

✅ HTTPS Interception & Decryption - Full MITM capability

✅ Real-Time Vulnerability Detection - SQLi, XSS, authentication flaws

✅ Educational Explanations - Learn as you test

✅ Intelligent Filtering - Clean reports focused on security findings

✅ Multi-Threaded Architecture - Handle concurrent connections

✅ Professional Reporting - Generate actionable security reports

## 🎓 Learning Outcomes
By using Bugscope, you'll understand:

1. **How MITM proxies work** at the protocol level
2. **HTTPS decryption** and certificate trust chains
3. **Common vulnerability patterns** in web applications
4. **Professional security assessment** workflow
5. **Traffic analysis** and pattern recognition


## ⚠️ Legal & Ethical Use (MANDATORY)
**This software, Bugscope, is developed and provided strictly for educational, ethical hacking, and authorized security research purposes only.**

By downloading and using this tool, the user agrees to:

1. **Use Bugscope only on systems they own** (e.g., localhost)

2. **Use Bugscope only on test targets where they have explicit, written permission** to conduct security testing (e.g., platforms like OWASP Juice Shop, or authorized Bug Bounty programs)

3. Comply with all applicable laws and regulations

**The author is not responsible for any misuse or illegal activity resulting from the use of this software**.

## 🛠️ Prerequisites Installation
### Python 3.x Installation
If you don't have Python installed, use the commands below for your operating system.

**Windows**
```bash
winget install Python.Python.3.11
```
**Kali Linux / Debian**
```bash
sudo apt update && sudo apt install python3 python3-pip -y
```

## 🤝 Contributing
Feel free to fork, star, and contribute to this educational tool. Areas for improvement:

1. Additional vulnerability patterns
2. Enhanced reporting features
3. User interface improvements
4. Documentation updates

## 🙋‍♂️ Author & Contribution

**Project Author:** **Muhammad Aqib Tayyab**

**LinkedIn Profile:** https://www.linkedin.com/in/muhammad-aqib-tayyab-815499348/

**GitHub Profile:** https://github.com/AqibTayyab
