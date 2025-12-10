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

## 1.Clone & Prepare the Environment
 Assuming you have Python 3.x and Git installed, use these commands:
```bash
git clone https://github.com/AqibTayyab/Bugscope-Security-Proxy.git
```
```bash
cd Bugscope-Security-Proxy
```

## 2.Install Dependencies (Networking and Cryptography)
```bash
pip install cryptography requests
```

## 3.Python 3.x Installation
 If you don't have Python installed, use the commands below for your operating system.
### Windows
```bash
winget install Python.Python.3.11
```
### Kali Linux / Debian
```bash
sudo apt update && sudo apt install python3 python3-pip -y
```

## 3. Set Up a Target (Choose Your Lab)
 Bugscope is ready to test any authorized web application.
### Local Lab:
```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
```
### External Target
```text
 No specific command needed; simply browse to the target's URL
```
## CRITICAL: Ensure you have explicit, written permission to test the target website.

## 4.Trust the Certificate (Essential for HTTPS)
Import the root certificate to avoid security warnings:

 Locate certificates/ca-cert.p12 in the cloned folder.

 In Firefox, go to Settings > Privacy & Security > View Certificates > Import.

 Select the .p12 file and check "Trust this CA to identify websites."

## 5.Run the Proxy and Configure Browser
```Bash
### Start the Bugscope Proxy
python proxies/main_educational.py
```
 Browser Configuration: Set your manual proxy to your system's IP address (e.g., 192.168.1.5) on port 8080.

## 6. Capture Traffic & Generate Report (The Final Phase)
Once your assessment is complete, generate the analysis report:

```Bash

## 1. Stop the proxy by pressing Ctrl+C
## If Program doesnt stop by pressing Ctrl+C , then close and reopen firefox, It will stop the program.

## 2. Run the analysis script
python analysis/report.py

```
## View Report:
 The terminal will provide the exact notepad command needed to open the final, filtered security report.

## ⚠️ Disclaimer (MANDATORY)
This software, **Bugscope**, is developed and provided strictly for **educational, ethical hacking, and authorized security research purposes only**.

By downloading and using this tool, the user agrees to:

Use Bugscope only on systems they own (e.g., localhost).

Use Bugscope only on test targets where they have explicit, **written permission to conduct security testing** (e.g., platforms like OWASP Juice Shop, or authorized Bug Bounty programs).

The author is **not responsible** for any misuse or illegal activity resulting from the use of this software.

## 🙋‍♂️ Author & Contribution

**Project Author:** **Muhammad Aqib Tayyab**

**LinkedIn Profile:** https://www.linkedin.com/in/muhammad-aqib-tayyab-815499348/

**GitHub Profile:** https://github.com/AqibTayyab

Feel free to fork, star, and contribute to this educational tool.
