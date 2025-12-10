# 🔥 Bugscope: Educational MITM Security Proxy (Python)

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.com/badge/Focus-Network%20Security%20%26%20Pentesting-red?style=for-the-badge)
![Status](https://img.shields.com/badge/Status-Project%20Complete-success?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Bugscope** is a custom-built, highly robust, multi-threaded Man-in-the-Middle (MITM) proxy developed in Python. The project's primary goal was to create a stable, educational tool for capturing, analyzing, and verifying web application vulnerabilities (like SQLi and XSS) on authorized test targets.

---

## 🧠 Technical Case Study: Key Challenges & Solutions

The core value of this project is demonstrated by solving complex, real-world networking and data analysis problems that often plague custom proxy tools.

### 1. The Outbound Firewall Bypass (Fixing 502 Errors)

* **Problem:** Local security software (Windows Defender, Antivirus) aggressively blocked the Python process when it attempted to make an outbound connection using raw sockets (`socket` library), resulting in persistent `502 Bad Gateway` errors.
* **Solution:** Refactored the HTTP forwarding logic to use the high-level **`requests` library** instead of raw sockets. This change utilizes standard, reliable HTTP connection methods recognized as safer by the firewall, successfully bypassing the block.

### 2. Intelligent Report Filtering (Handling Telemetry Noise)

* **Problem:** High-volume browser telemetry (e.g., Mozilla) and background checks contained unique GUIDs (e.g., `.../1/a15ebdad-...`), causing the report to incorrectly list dozens of identical security risks.
* **Solution:** Implemented **Intelligent Path Cleaning** in the reporting engine using **Regular Expressions (`re`)**. This logic identifies the GUIDs and replaces them with a standardized placeholder (`[GUID]`) before deduplication. This ensures the final report focuses exclusively on actionable user-driven findings.

### 3. Vulnerability Verification (SQL Injection)

* **Achievement:** Bugscope successfully flagged the `/login.php` endpoint as **Critical Severity**. The flaw was actively verified by executing the suggested **SQL Injection payload (`' OR '1'='1`)**, proving a Broken Authentication vulnerability on the test target.

---

## 🛠️ Installation & Setup Guide

### 1. Prerequisites (Python & Docker)

| Operating System | Python Installation Command | Docker Setup |
| :--- | :--- | :--- |
| **Windows** | `winget install Python.Python.3.11` | Install [Docker Desktop](https://www.docker.com/products/docker-desktop/). |
| **Kali Linux** | `sudo apt install python3 python3-pip -y` | `sudo apt install docker.io -y` |

### 2. Clone Repository & Install Dependencies

Open your terminal, navigate to your projects directory, and execute:

```bash
# Clone the repository
git clone [https://github.com/YOUR_USERNAME/Bugscope-Educational-Proxy.git](https://github.com/YOUR_USERNAME/Bugscope-Educational-Proxy.git)
cd Bugscope-Educational-Proxy

# Install necessary Python libraries
pip install -r requirements.txt