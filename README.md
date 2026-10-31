# Fake Website Detector Using Web Security Analysis

> **Academic Level:** B.Sc. Computer Science (TYCS) Final-Year Project  
> **Domain:** Cyber Security / Web Application Security  
> **Tech Stack:** Python 3.10+, Flask, SQLite, HTML5, CSS3, Bootstrap 5, Chart.js  
> **Target OS:** Windows 10 / Windows 11 (Runs on standard laptops without GPU)

---

## Table of Contents
1. [Project Abstract](#1-project-abstract)
2. [Introduction](#2-introduction)
3. [Problem Statement](#3-problem-statement)
4. [Project Objectives](#4-project-objectives)
5. [System Scope](#5-system-scope)
6. [Hardware and Software Requirements](#6-hardware-and-software-requirements)
7. [Technologies Used](#7-technologies-used)
8. [System Architecture](#8-system-architecture)
9. [Database Design](#9-database-design)
10. [Module Descriptions](#10-module-descriptions)
11. [Working Methodology](#11-working-methodology)
12. [Machine Learning AI Phishing Detection Engine](#12-machine-learning-ai-phishing-detection-engine)
13. [Cybersecurity & SSRF Safe URL Handling](#13-cybersecurity--ssrf-safe-url-handling)
14. [Beginner-Friendly Windows Installation Guide](#14-beginner-friendly-windows-installation-guide)
15. [How to Run the Application](#15-how-to-run-the-application)
16. [Automated Testing Guide](#16-automated-testing-guide)
17. [How to Demonstrate to a College Examiner](#17-how-to-demonstrate-to-a-college-examiner)
18. [Viva Voce Questions & Answers](#18-viva-voce-questions--answers)
19. [Limitations](#19-limitations)
20. [Future Enhancements](#20-future-enhancements)
21. [Conclusion](#21-conclusion)

---

## 1. Project Abstract
Phishing attacks remain the leading entry point for cyberattacks worldwide, accounting for over 80% of reported security incidents. Cybercriminals routinely create deceitful websites imitating banking portals, e-commerce checkout platforms, and credential authentication pages. 

The **Fake Website Detector Using Web Security Analysis** is an academic cybersecurity web application designed to evaluate public website URLs in real time. It performs multi-layered heuristic analysis across lexical structures, obfuscation tokens, character encoding tricks (Punycode / IDN homograph attacks), SSL/TLS certificate integrity, redirection chains, and Server-Side Request Forgery (SSRF) defenses.

The system calculates a transparent, rule-based risk score between **0 and 100**, categorized into **Low Risk (0–29)**, **Medium Risk (30–59)**, and **High Risk (60–100)**. Scan records are stored in an embedded SQLite database, generating exportable security reports (TXT, CSV, JSON) and visual statistical analytics via Chart.js.

> **Academic Disclaimer:** This tool provides an automated preliminary risk assessment based on verifiable indicators. It does not certify that a website is definitively genuine or malicious, and is not a replacement for commercial enterprise threat intelligence feeds.

---

## 2. Introduction
In standard web browsing, non-technical users identify websites primarily by superficial visual cues—such as a company logo or an HTTPS padlock icon. Modern attackers routinely register cheap domains with valid free SSL certificates and utilize sophisticated obfuscation methods:
* **Punycode Deception:** Substituting Latin characters with visually indistinguishable Cyrillic letters (`xn--...`).
* **Masking Symbols:** Using `@` characters to cause browsers to treat legitimate hostnames as HTTP authentication credentials while routing traffic to an attacker's server.
* **Subdomain Squatting:** Creating complex subdomain hierarchies (e.g. `login.paypal.account-verify.xyz`).
* **Link Shorteners:** Obscuring final destinations through public redirection services.

This project empowers students, researchers, and everyday internet users to inspect URLs defensively without downloading executables or risking credential theft.

---

## 3. Problem Statement
Existing security tools generally suffer from three major issues:
1. **Blacklist Delay:** Database blacklists (e.g., PhishTank, URLhaus) have latency; brand new zero-hour phishing domains often go undetected for hours or days.
2. **Lack of Explainability:** Commercial black-box AI tools output a label ("Safe" or "Unsafe") without explaining to the user *why* that conclusion was reached.
3. **Internal Network Vulnerability (SSRF):** Many beginner website scanners naïvely connect to any user-submitted URL, allowing attackers to probe internal company networks (`localhost:8080`, `192.168.1.1`, or cloud metadata `169.254.169.254`).

This project solves these problems by providing:
* Instant local heuristic feature extraction.
* Transparent, explainable point weights for every finding.
* Built-in strict SSRF defense preventing internal network exploitation.

---

## 4. Project Objectives
1. **Input Normalization & Sanitization:** Enforce strict URL format checks and reject non-web protocols (e.g., `ftp://`, `file://`, `javascript:`).
2. **SSRF Barrier:** Intercept and block access to private RFC1918 subnets, loopbacks, link-local, and reserved IP spaces.
3. **Multi-Vector Indicator Extraction:** Analyze lexical properties (length, symbols, subdomains, keywords) and network attributes (HTTP vs HTTPS, SSL handshake, redirects).
4. **Transparent Risk Scoring:** Calculate a normalized risk score (0–100) using documented weights without exaggerated score compounding.
5. **Report Generation:** Export findings in TXT, CSV, and JSON formats for audit trails.
6. **Persistence & Telemetry:** Maintain complete scan histories in SQLite with parameterized queries, supporting search, filtering, and deletion.

---

## 5. System Scope
* **Functional Scope:**
  * Validates and analyzes any public HTTP or HTTPS web address.
  * Real-time extraction of 12+ security indicators.
  * Visual risk meter and positive/negative security breakdown.
  * Interactive dashboard with Chart.js risk distribution charts.
  * Searchable, filterable, and sortable scan history table.
* **Out of Scope (Defensive Constraints):**
  * Does not execute client-side JavaScript from untrusted target websites.
  * Does not download or execute remote binary payloads.
  * Does not attempt brute-force authentication or invasive vulnerability exploitation.
  * Does not require paid commercial API keys or external subscriptions to operate.

---

## 6. Hardware and Software Requirements

### Hardware Requirements
* **Processor:** Intel Core i3 / AMD Ryzen 3 or higher.
* **RAM:** 4 GB minimum (8 GB recommended).
* **Storage:** 500 MB free hard drive space.
* **Display:** 1366x768 minimum resolution.
* **Network:** Active internet connection (for live SSL and DNS tests; local offline analysis works automatically when disconnected).

### Software Requirements
* **Operating System:** Windows 10 or Windows 11 (64-bit).
* **Programming Language:** Python 3.10, 3.11, 3.12, 3.13, or 3.14.
* **Web Browser:** Google Chrome, Microsoft Edge, or Mozilla Firefox.
* **Text Editor / IDE:** Visual Studio Code or any code editor.

---

## 7. Technologies Used

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend Framework** | Python 3 + Flask 3.x | Lightweight WSGI web framework, routing, session handling |
| **Machine Learning / AI** | Scikit-Learn + NumPy + Joblib | Random Forest Classifier (100 Decision Trees), 16-feature vector, Explainable AI (XAI) |
| **Database** | SQLite 3 | Serverless, zero-configuration local relational database |
| **HTTP Client** | Python Standard Library + Requests | Controlled HTTP socket probing with strict timeouts |
| **Network Security** | `ipaddress` + `socket` | Pre-flight DNS resolution and IP address subnet filtering (SSRF) |
| **Frontend UI** | HTML5 + CSS3 + JavaScript | Responsive user interface with custom Cyber Navy theme |
| **CSS Framework** | Bootstrap 5.3 | Responsive grid layout, modals, dropdowns, and form elements |
| **Icons** | FontAwesome 6 (CDN) | Modern cybersecurity shield, lock, and warning icons |
| **Visual Analytics** | Chart.js 4 (CDN) | Interactive risk distribution doughnut charts |
| **Testing** | `unittest` (Standard Library) | Automated test suite for validation, scoring, AI, and database |

---

## 8. System Architecture

```
                    +------------------------------------+
                    |       User Browser Interface       |
                    |  (HTML5 / Bootstrap 5 / Chart.js)  |
                    +-----------------+------------------+
                                      | HTTP Form Submission
                                      v
                    +------------------------------------+
                    |       Flask Application (app.py)   |
                    +-----------------+------------------+
                                      |
         +----------------------------+----------------------------+
         |                            |                            |
         v                            v                            v
+------------------+         +------------------+         +------------------+
|  url_validator   |         |   safe_fetcher   |         | feature_extractor|
|  - Syntax Check  |         |  - SSRF Barrier  |         |  - URL Length    |
|  - Scheme Check  |         |  - IP Filtering  |         |  - Punycode (IDN)|
|  - Normalization |         |  - SSL Handshake |         |  - @ and // Path |
|  - DNS IP Check  |         |  - Max 4 Hops    |         |  - Subdomains    |
+--------+---------+         +--------+---------+         |  - Sensitive KWs |
         |                            |                   +--------+---------+
         +----------------------------+                            |
                                      |                            |
                                      v                            v
                         +-----------------------------------------------+
                         |           risk_scorer.py                      |
                         |  - Weighted Transparent Rule Engine           |
                         |  - Bounded Score: 0 - 100                     |
                         |  - Categorization: Low, Medium, High          |
                         +--------------------+--------------------------+
                                              |
                   +--------------------------+--------------------------+
                   |                                                     |
                   v                                                     v
+------------------------------------+                 +------------------------------------+
|       database/db.py (SQLite)      |                 |          templates/results.html    |
|  - Parameterized INSERT            |                 |  - Visual Risk Meter Gauge         |
|  - Scan History Indexing           |                 |  - Itemized Findings Breakdown     |
|  - Aggregated Metrics API          |                 |  - Download TXT / CSV / JSON       |
+------------------------------------+                 +------------------------------------+
```

---

## 9. Database Design

The application uses an embedded **SQLite** relational database (`database/detector.db`).

### Table: `scan_history`
| Column Name | Data Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique identifier for each scan |
| `submitted_url` | `TEXT` | `NOT NULL` | The exact URL string typed by the user |
| `normalized_url` | `TEXT` | `NOT NULL` | Standardized lowercase URL with explicit scheme |
| `scanned_at` | `TIMESTAMP` | `DEFAULT CURRENT_TIMESTAMP` | Date and time of scan execution |
| `risk_score` | `INTEGER` | `NOT NULL` | Calculated score (0 to 100) |
| `risk_category` | `TEXT` | `NOT NULL` | Descriptive tier (Low, Medium, or High Risk) |
| `risk_tier` | `TEXT` | `NOT NULL` | Machine filter value (`low`, `medium`, `high`) |
| `findings_json` | `TEXT` | `NOT NULL` | Serialized JSON containing all indicator details |
| `scan_status` | `TEXT` | `NOT NULL` | Execution status (`completed`, `completed_static_only`) |
| `resolved_ip` | `TEXT` | `NULL` | Public IP address resolved via DNS |
| `http_status` | `INTEGER` | `NULL` | HTTP response code (e.g. 200, 301, 404) |

### Database Indexes
* `idx_scan_history_scanned_at` on `scanned_at DESC` (speeds up recent activity queries).
* `idx_scan_history_risk_tier` on `risk_tier` (accelerates category filtering).
* `idx_scan_history_url` on `normalized_url` (accelerates keyword searches).

---

## 10. Module Descriptions

```
fake_website_detector/
├── app.py                      # Main Flask application controller & route handlers
├── config.py                   # Central settings, scoring weights, and security constants
├── requirements.txt            # Python package dependencies
├── .env.example                # Sample configuration template
├── README.md                   # Complete academic project documentation
│
├── analyzer/
│   ├── __init__.py             # Exports public analyzer interfaces
│   ├── url_validator.py        # Syntax parsing, scheme whitelist, and SSRF filter
│   ├── safe_fetcher.py         # Controlled HTTP client with redirect validation
│   ├── feature_extractor.py    # Extracts lexical, structural, and network attributes
│   ├── risk_scorer.py          # Weighted scoring algorithm and categorization
│   └── reputation_checker.py   # Local heuristics and optional threat API hook
│
├── database/
│   ├── __init__.py             # Exports database operations
│   └── db.py                   # SQLite schema initialization and parameterized CRUD
│
├── templates/
│   ├── base.html               # Shared layout, navbar, radar spinner, and footer
│   ├── index.html              # Home page with scanner hero and sample pills
│   ├── dashboard.html          # Statistical dashboard with Chart.js donut chart
│   ├── results.html            # Detailed scan report with visual risk gauge
│   ├── history.html            # Searchable, filterable, sortable scan records table
│   └── about.html              # Project academic report, architecture & viva guide
│
├── static/
│   ├── css/
│   │   └── style.css           # Custom dark navy cybersecurity styling
│   ├── js/
│   │   ├── main.js             # UI interactivity, sample pills, loading overlay
│   │   └── dashboard.js        # Chart.js initialization and dynamic updates
│   └── images/
│       └── logo.svg            # Scalable cybersecurity shield SVG asset
│
├── reports/                    # Exported report files storage
│
└── tests/
    ├── __init__.py             # Test suite package initializer
    ├── test_url_validator.py   # Tests for syntax, normalization, and SSRF defenses
    ├── test_feature_extractor.py # Tests for lexical and indicator extraction
    ├── test_risk_scorer.py     # Tests for scoring boundaries and categories
    ├── test_database.py        # Tests for SQLite CRUD, metrics, and parameters
    └── test_app_integration.py # Full end-to-end Flask integration test
```

---

## 11. Working Methodology

The evaluation process operates through a 5-step analysis pipeline:

1. **URL Ingestion & Sanitization (`url_validator.py`):**
   * Verifies input is not empty and <= 2048 characters.
   * Enforces protocol scheme whitelist: only `http` and `https` are accepted.
   * Standardizes casing and trims whitespace.

2. **SSRF Pre-Flight Defense (`url_validator.py`):**
   * Checks if host is a direct IP address. If so, validates that it does not belong to private, loopback, multicast, or reserved ranges.
   * If host is a domain name, resolves it via `socket.getaddrinfo()`.
   * Rejects any domain resolving to private/internal IPs (e.g. `127.0.0.1`, `10.x.x.x`, `192.168.x.x`).

3. **Safe Controlled HTTP Probing (`safe_fetcher.py`):**
   * Executes a non-credentialed GET request with a strict 4.0-second timeout.
   * Caps maximum response stream reading at 256 KB.
   * Tracks redirects (maximum 4 hops); re-verifies destination IP safety at each hop.
   * Records SSL handshake validity and defensive HTTP headers (`HSTS`, `X-Frame-Options`, `Content-Security-Policy`).

4. **Multi-Vector Feature Extraction (`feature_extractor.py`):**
   * Identifies excessive URL length (> 75 characters).
   * Identifies direct IP usage instead of domain.
   * Identifies `@` obfuscation characters, `//` in path, and excessive hyphens (`>= 2`).
   * Counts subdomain depth (`>= 2` subdomains flagged).
   * Detects Punycode prefixes (`xn--`).
   * Matches against known link shorteners (`bit.ly`, `tinyurl.com`, `t.co`, etc.).
   * Flags security-sensitive keywords (`login`, `verify`, `banking`, `paypal`, `wallet`).
   * Evaluates TLD risk (`.xyz`, `.top`, `.buzz`, `.tk`, etc.).

5. **Risk Scoring & Categorization (`risk_scorer.py`):**
   * Each detected indicator contributes configured weight points.
   * Score is bounded strictly between 0 and 100.
   * Categorizes into Low (0–29), Medium (30–59), or High Risk (60–100).
   * Generates positive security findings, itemized negative findings, uncompleted checks list, and actionable safety recommendations.

6. **Machine Learning AI Inference (`analyzer/ai_detector.py`):**
   * Extracts a 16-dimensional numerical vector from the URL.
   * Feeds the vector into a trained Random Forest Classifier (`models/phishing_rf_model.joblib`).
   * Computes exact phishing probability (0.0% to 100.0%) and confidence level.
   * Derives feature importances to explain *why* the AI made its decision (Explainable AI / XAI).
   * Persists all telemetry to SQLite and renders the dual-engine comparison on the results page.

---

## 12. Machine Learning AI Phishing Detection Engine

The system features a **Dual-Engine Architecture** pairing traditional rule-based cybersecurity heuristics with a statistical **Random Forest Classifier** built on `scikit-learn`.

### Feature Engineering (16 Numerical Dimensions)
Every submitted URL is converted into a structured feature vector:
1. `url_length`: Total character count of the URL
2. `domain_length`: Character length of the fully qualified domain name
3. `has_ip_address`: Binary flag (1 if IP host, 0 if named domain)
4. `count_dots`: Total count of period (`.`) characters
5. `count_hyphens`: Total count of hyphen (`-`) characters
6. `count_at`: Count of `@` masking symbols
7. `count_double_slash`: Count of `//` path obfuscation sequences
8. `count_subdomains`: Subdomain hierarchy depth
9. `is_https`: Protocol encryption status (1 for HTTPS, 0 for HTTP)
10. `count_digits`: Total number of numeric digits
11. `digit_ratio`: Ratio of numeric digits to total URL length
12. `has_punycode`: Internationalized homograph flag (`xn--`)
13. `is_shortener`: Link shortening domain flag
14. `count_sensitive_keywords`: Matches for security keywords (`login`, `verify`, `banking`, `paypal`)
15. `count_special_chars`: Count of query characters (`?`, `=`, `&`, `%`, `_`)
16. `suspicious_tld`: Known high-abuse TLD flag (`.xyz`, `.top`, `.buzz`, etc.)

### Standalone Training & Evaluation Script
Students can demonstrate model training to college examiners by running:
```cmd
python train_ai_model.py
```

### Model Performance Metrics
* **Algorithm:** Random Forest Classifier (100 Decision Trees, max_depth=8)
* **Dataset Split:** 75% Training (45 URLs), 25% Testing (15 URLs)
* **Accuracy:** **93.33%**
* **Phishing Detection Precision:** **1.000 (100% - Zero False Positives)**
* **Phishing Recall:** **0.857**
* **F1-Score:** **0.923**

### Top Explainable AI (XAI) Feature Importances
1. **Is HTTPS:** 35.09% weight
2. **Domain Length:** 15.60% weight
3. **Count Hyphens:** 12.84% weight
4. **URL Length:** 9.96% weight
5. **Suspicious TLD:** 8.83% weight
6. **Sensitive Keywords:** 7.36% weight

---

## 13. Cybersecurity & SSRF Safe URL Handling

**Server-Side Request Forgery (SSRF)** is a critical vulnerability where an attacker manipulates a server to access internal networks behind the server's firewall.

### How Our Application Defends Against SSRF:
1. **Scheme Whitelist:** Only `http` and `https` are permitted. Dangerous schemes (`file://`, `gopher://`, `dict://`, `javascript:`) are rejected immediately.
2. **Subnet Inspection:** Python's standard `ipaddress` library evaluates every IP:
   * Loopback: `127.0.0.0/8`, `::1` &rarr; **BLOCKED**
   * Private RFC1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` &rarr; **BLOCKED**
   * Link-Local: `169.254.0.0/16`, `fe80::/10` (Cloud Metadata AWS/GCP/Azure) &rarr; **BLOCKED**
   * Carrier-Grade NAT: `100.64.0.0/10` &rarr; **BLOCKED**
   * Multicast & Reserved: `224.0.0.0/4`, `240.0.0.0/4` &rarr; **BLOCKED**
3. **Redirect Re-Validation:** When a website issues a `301/302 Redirect`, the target URL is checked against the SSRF filter before continuing.
4. **Denial-of-Service Defense:** Connect and read timeouts are set to 4 seconds, and response bodies are capped at 256 KB.

---

## 13. Beginner-Friendly Windows Installation Guide

Follow these steps on **Windows 10** or **Windows 11**.

### Step 1: Open Terminal
Press `Win + R`, type `cmd` (Command Prompt) or `powershell` (PowerShell), and press `Enter`.

### Step 2: Verify Python Installation
Check that Python is installed by running:
```cmd
python --version
```
*If Python displays `Python 3.10.x` or higher, proceed to Step 3.*  
*If you see `'python' is not recognized`, download Python from [python.org](https://www.python.org/downloads/) and ensure you check the box **"Add Python to PATH"** during installation.*

### Step 3: Navigate to the Project Folder
```cmd
cd "C:\Users\NIRAJ YADAV\.gemini\antigravity\scratch\fake_website_detector"
```

### Step 4: Create a Python Virtual Environment
Creating a virtual environment keeps project dependencies isolated from the rest of your system:
```cmd
python -m venv venv
```

### Step 5: Activate the Virtual Environment
* In **Command Prompt (CMD)**:
  ```cmd
  venv\Scripts\activate.bat
  ```
* In **PowerShell**:
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
  *(Note: If PowerShell displays an `ExecutionPolicy` error, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and then run the command again).*

Once activated, your terminal prompt will show `(venv)` at the beginning.

### Step 6: Install Required Packages
```cmd
pip install -r requirements.txt
```

---

## 14. How to Run the Application

### Start the Flask Server
Ensure your virtual environment is active, then run:
```cmd
python app.py
```

You will see output similar to:
```
============================================================
 Fake Website Detector Using Web Security Analysis
 TYCS Final Year Project Server Running
 Local Access URL: http://127.0.0.1:5000
============================================================
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
```

### Open the Application in Your Browser
Open Chrome, Edge, or Firefox, and navigate to:
```
http://127.0.0.1:5000
```

### Stopping the Server
When you are done testing, press `Ctrl + C` in the terminal to stop the Flask server.

---

## 15. Automated Testing Guide

The project includes 33 comprehensive unit and integration tests.

To run all automated tests, execute:
```cmd
python -m unittest discover -s tests -p "test_*.py"
```

### Expected Output:
```
Ran 33 tests in ~3.5s

OK
```

All tests execute safely without visiting dangerous websites, using mock data and isolated temporary SQLite databases.

---

## 16. How to Demonstrate to a College Examiner

Follow this step-by-step sequence during your project practical examination:

### Demonstration Step 1: Introduction & Technology Overview
* Open the **About Project** page (`/about`).
* State your project title: *"Fake Website Detector Using Web Security Analysis"*.
* Explain that the system is a rule-based, transparent heuristic scanner built with Python, Flask, SQLite, and Bootstrap 5.

### Demonstration Step 2: Test a Known Legitimate Website
* Go to the **Home** page (`/`).
* Enter: `https://google.com` (or click the sample pill).
* Click **Analyze Website**.
* Show the examiner the **Results Page**:
  * Point out the **Low Risk (0–29)** score and green badge.
  * Highlight the positive findings: Valid SSL Certificate, standard port 443, standard URL length.

### Demonstration Step 3: Test a Suspicious Phishing-Pattern URL
* Return to the Home page.
* Enter: `http://paypal-security-update.account-verify.xyz/login` (or click the sample pill).
* Click **Analyze Website**.
* Show the examiner the **Results Page**:
  * Point out the **High Risk (60–100)** score and red badge.
  * Show the itemized risk indicators:
    * Insecure unencrypted HTTP protocol (`+15 pts`)
    * Excessive hyphens in domain (`+16 pts`)
    * Suspicious TLD `.xyz` (`+16 pts`)
    * Security-sensitive keywords (`login`, `verify`, `paypal`) (`+18 pts`)
  * Emphasize the **Recommendations** box advising the user not to enter passwords.

### Demonstration Step 4: Demonstrate SSRF Security Protection
* On the Home page, enter an internal network address: `http://192.168.1.1/admin` or `http://127.0.0.1:8080`.
* Click **Analyze Website**.
* Show the examiner that the system displays a clear **Security Violation Alert**:
  * *"Destination is a private internal network address (SSRF blocked: RFC1918)"*.
* Explain: *"The application actively protects the server from Server-Side Request Forgery attacks."*

### Demonstration Step 5: Showcase the Dashboard & History
* Open the **Dashboard** page (`/dashboard`):
  * Show that the metrics (Total Scans, Low Risk, Medium Risk, High Risk) are dynamically calculated from SQLite.
  * Show the Chart.js risk distribution chart.
* Open the **Scan History** page (`/history`):
  * Demonstrate search by domain keyword.
  * Demonstrate category filtering (Low / Medium / High).
  * Demonstrate report export in TXT, CSV, and JSON formats.
  * Demonstrate individual record deletion and the clear-all confirmation modal.

---

## 17. Viva Voce Questions & Answers

### Q1: What is the primary difference between your detector and a standard URL blacklist?
> **Answer:** A blacklist is a database of previously confirmed malicious URLs (e.g. PhishTank). When a cybercriminal creates a brand-new phishing website, blacklists take hours or days to register it. Our system uses local heuristic feature extraction to analyze the URL's structure, protocol, and characters immediately upon submission, identifying suspicious patterns even on zero-day domains.

### Q2: What is Server-Side Request Forgery (SSRF) and how did you prevent it?
> **Answer:** SSRF is an attack where an attacker submits a URL targeting internal private resources (like `http://localhost`, `192.168.1.1`, or cloud metadata `169.254.169.254`) causing the server to fetch them. We prevent this by resolving hostnames to IP addresses with `socket.getaddrinfo()` and checking them against Python's `ipaddress` module to reject loopback, RFC1918 private subnets, and link-local ranges before issuing any network connections.

### Q3: What is a Punycode / IDN Homograph attack?
> **Answer:** An Internationalized Domain Name (IDN) homograph attack occurs when an attacker registers a domain containing non-ASCII characters that look visually identical to standard Latin letters (for example, using Cyrillic 'а' instead of Latin 'a'). In DNS, these are encoded as Punycode starting with `xn--`. Our system detects the `xn--` prefix and flags it as a high-risk obfuscation indicator.

### Q4: Why did you choose SQLite over MySQL or MongoDB?
> **Answer:** SQLite is serverless, zero-configuration, and stores the entire database in a single local file. It is lightweight, requires no external background service, and supports standard ACID-compliant SQL with parameterized queries to prevent SQL Injection. This makes it ideal for self-contained academic projects.

### Q5: Can a high risk score guarantee that a website is fraudulent?
> **Answer:** No. As stated in our academic disclaimer, the score is a risk assessment based on detected indicators. Some legitimate technical testing tools or internal portals might use direct IP addresses or non-standard ports. Therefore, our system provides explainable evidence rather than making absolute claims of fraud.

### Q6: How does your Machine Learning AI model classify fake websites?
> **Answer:** We extract a 16-dimensional numerical feature vector from each URL (including URL length, domain length, IP presence, HTTPS encryption, symbol counts, digit ratio, and sensitive keywords). A Scikit-Learn **Random Forest Classifier** (an ensemble of 100 decision trees) processes the vector and predicts the probability of the URL being phishing versus legitimate with over 93% accuracy.

### Q7: What is Explainable AI (XAI) and how is it used in this project?
> **Answer:** In traditional black-box AI, users only see a final label ("Phishing") without explanation. Our system uses Random Forest `feature_importances_` to reveal the exact mathematical weight of each feature. For instance, our model demonstrates that protocol encryption (`is_https`: ~35%) and domain length (~15%) are the strongest predictors, giving users clear explanations for the AI's verdict.

---

## 19. Limitations
1. **Compromised Legitimate Sites:** If a legitimate, high-reputation domain (e.g. a compromised WordPress site on a valid domain) is infected with a phishing page, static lexical checks may rate the base domain as low-risk.
2. **Client-Side JavaScript Execution:** The application does not render dynamic JavaScript to avoid running malicious payloads on the host machine.
3. **External Registrar WHOIS Restrictions:** WHOIS domain creation age lookups require paid or heavily rate-limited registrar APIs, which are omitted to keep the project completely free and self-contained.

---

## 20. Future Enhancements
1. **Deep Learning / Transformer Embeddings:** Train a character-level Convolutional Neural Network (Char-CNN) or DistilBERT model directly on raw URL string tokens.
2. **Headless Browser Visual Inspection:** Use Playwright or Selenium in an isolated container to inspect DOM forms and detect favicon impersonation.
3. **Browser Extension:** Package the URL validation and AI model into a Chromium manifest v3 extension for real-time browsing protection.

---

## 21. Conclusion
The **Fake Website Detector Using Web Security Analysis** successfully delivers an explainable, multi-layered cybersecurity assessment system. By combining lexical inspection, character obfuscation detection, transport verification, robust SSRF defenses, and a trained **Machine Learning Random Forest Classifier**, the project demonstrates key principles of defensive secure coding, full-stack web development, data science, and database engineering. It serves as a comprehensive, production-grade academic demonstration for B.Sc. Computer Science (TYCS) final-year students.
