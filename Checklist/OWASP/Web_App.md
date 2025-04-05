## 🚀 ULTIMATE WEB APP BUG BOUNTY & PENETRATION TESTING CHECKLIST

## 🔍 Covering OWASP Top 10, API Security, Cloud, and Advanced Exploitation

### 🌐 PHASE 1: RECONNAISSANCE & ENUMERATION

#### 🔎 Passive Intelligence Gathering

    - Certificate Transparency Logs (crt.sh, certspotter, facebook.com/ct)
    - Subdomain Enumeration (Amass, Subfinder, Chaos, Sublist3r)
    - DNS Recon (DNSdumpster, DNSSEC Walk, AXFR attempts)
    - Cloud Asset Discovery (S3 buckets, Azure blobs, GCP storage)
    - GitHub/GitLab Scraping (truffleHog, gitrob, gitleaks)
    - Wayback Machine & Archive.org (waybackurls, gau)
    - Email Harvesting (Hunter.io, theHarvester)
    - Shodan/Censys Search (org:"Company", http.title:"Login")
    - Google Dorks (site:target.com ext:pdf, intitle:"index of")
    - Pastebin/Dark Web Monitoring (psbdmp, IntelligenceX)
    - LinkedIn/GitHub Stalking (employee tech stack mentions)
    - JavaScript Analysis (LinkFinder, JSFinder, SecretFinder)
    - Favicon Hashing (shodan search http.favicon.hash:123456)
    - WAF/CDN Fingerprinting (wafw00f, cloudflare_enum)
    - Blockchain DNS Lookups (ENS, Handshake)
    - Satellite Imagery Analysis (for physical locations)

### 🕵️ Active Enumeration

    - Subdomain Bruteforcing (ffuf, gobuster, altdns)
    - Virtual Host Discovery (Host-header fuzzing)
    - Port Scanning (Nmap, Masscan, Naabu top 1000+)
    - Web Tech Stack (Wappalyzer, BuiltWith, WhatWeb)
    - API Endpoint Discovery (Burp, Postman, Kiterunner)
    - GraphQL Introspection (graphqlmap, InQL)
    - WebSocket Analysis (WSSiP, Burp WS Fuzzer)
    - Directory Bruteforcing (dirsearch, feroxbuster)
    - Parameter Mining (Param Miner, Arjun, paramspider)
    - S3/GCP Bucket Checks (s3scanner, cloud_enum)
    - SMTP Enumeration (smtp-user-enum)
    - SNMP Community Strings
    - JIRA/Confluence Crawling
    - CI/CD Pipeline Discovery (Jenkins, GitLab CI)
    - Kubernetes API Probing (kube-hunter)

## 🔐 PHASE 2: AUTHENTICATION & AUTHORIZATION

### 🔑 Authentication Testing

    - Credential Stuffing (OpenBullet, Hydra)
    - Password Policy Bypass (length truncation, Unicode)
    - 2FA Bypass (OTP reuse, null OTP, response manipulation)
    - JWT Attacks (alg:none, kid injection, weak secrets)
    - OAuth Misconfigs (redirect_uri, token leakage)
    - SAML Vulnerabilities (XML signature wrapping)
    - Session Fixation (cookie forcing)
    - Concurrent Sessions
    - Remember Me Tokens (insecure generation)
    - Account Lockout Bypass (HTTP verb tampering)
    - Username Enumeration (timing attacks, error diffs)
    - Password Reset Poisoning (host header injection)
    - Magic Link Exploitation (timeout manipulation)
    - CAPTCHA Bypass (OCR, replay, audio analysis)
    - Biometric Bypass (liveness detection flaws)

### 🏴 Authorization Testing

    - Horizontal Privilege Escalation (IDOR)
    - Vertical Privilege Escalation (role parameter)
    - Insecure Direct Object References
    - Parameter Tampering (hidden admin flags)
    - API Mass Assignment (unfiltered properties)
    - GraphQL Authorization Bypass (introspection)
    - Business Logic Bypass (negative prices)
    - Race Conditions (parallel requests)
    - JWT Claim Abuse (role:admin)
    - HTTP Method Tampering (POST → PUT)
    - Path Traversal (../../../etc/passwd)
    - Custom Header Injection (X-Original-URL)
    - Web Cache Deception
    - Serverless Function Permission Escalation

## 💉 PHASE 3: INJECTION & INPUT VALIDATION

### 🧪 Classic Injection

    - SQLi (time-based, error-based, polyglot)
    - XSS (DOM, stored, reflected, mutation)
    - Command Injection (; whoami, $(cmd))
    - SSTI ({{7*7}}, Twig, Jinja2)
    - XXE (external entities, SVG upload)
    - LDAP Injection (&(objectClass=\*))
    - CSV Injection (=HYPERLINK)
    - HTTP Header Injection (\r\n)
    - Mail Command Injection (CRLF in SMTP)
    - GraphQL Injection (nested queries)
    - NoSQL Injection ($ne, $regex)
    - IMAP/SMTP Injection (pre-auth)
    - SQLi via HTTP Parameters (JSON/XML)
    - Browser Protocol Handler Abuse (ms-Excel:)

### 🕵️ Advanced Input Validation

    - HTTP Request Smuggling (CL.TE, TE.TE)
    - Prototype Pollution (**proto** pollution)
    - WebSocket Injection (binary protocol)
    - PDF Injection (JavaScript in PDF)
    - File Upload Bypass (polyglot files)
    - MIME Sniffing (X-Content-Type-Options)
    - Open Redirect (//evil.com)
    - DOM Clobbering (name=body)
    - AngularJS Sandbox Escape
    - Flash CrossDomain Policy Abuse
    - WebAssembly Exploitation
    - Electron App XSS (nodeIntegration)
    - WebRTC IP Leakage
    - Webhook Spoofing (DNS rebinding)

## ☁️ PHASE 4: CLOUD & API TESTING

### 🌩️ Cloud-Specific

    - AWS S3 Bucket Permissions
    - Azure Storage Account Access
    - GCP IAM Misconfigurations
    - Kubernetes Dashboard Exposure
    - Docker API Unauthenticated Access
    - Serverless Function Event Injection
    - Cloud Metadata API (169.254.169.254)
    - CI/CD Pipeline Takeover (GitHub Actions)
    - Terraform State File Exposure
    - Cloud Database Exposures (MongoDB Atlas)
    - Cloudflare WAF Bypass (unicode normalization)
    - Cloud Storage Signed URL Predictability
    - SaaS Misconfigurations (O365, GSuite)
    - Cloud IAM Privilege Escalation

### 📡 API Security

    - Broken Object Level Authorization
    - Excessive Data Exposure
    - Mass Assignment
    - Improper Assets Management
    - GraphQL Batching Attacks
    - REST API Verb Tampering
    - SOAP XML Injection
    - gRPC Protobuf Fuzzing
    - Webhook Spoofing
    - API Key Leakage (JS, mobile apps)
    - OAuth Token Hijacking
    - JWT Weaknesses
    - API Rate Limit Bypass
    - Schema Poisoning

## 🛡️ PHASE 5: SECURITY MISCONFIGURATIONS

### 🏗️ Infrastructure

    - Default Credentials (admin:admin)
    - Exposed Admin Interfaces
    - Verbose Error Messages
    - Directory Listing Enabled
    - Unnecessary HTTP Methods
    - Insecure CORS Configurations
    - Missing Security Headers
    - Clickjacking Vulnerabilities
    - Cache Poisoning (X-Forwarded-Host)
    - HSTS Missing or Misconfigured
    - CSP Bypasses (unsafe-eval)
    - Web Cache Deception
    - Host Header Injection
    - CRLF Injection

### 🔧 Application

    - Debug Mode Enabled
    - Version Control Exposure (.git)
    - Backup File Exposure (.bak)
    - Hardcoded Secrets
    - Insecure Deserialization
    - Weak Cryptography (MD5)
    - Predictable Tokens
    - Mixed Content Issues
    - SameSite Cookie Bypass
    - WebView Vulnerabilities
    - Local Storage Sensitive Data
    - IndexedDB Information Leak
    - Service Worker Abuse

## ⚡ PHASE 6: BUSINESS LOGIC & ADVANCED EXPLOITS

### 💰 Business Logic Flaws

    - Negative Pricing
    - Inventory Manipulation
    - Coupon Code Bruteforcing
    - Time-of-Check Time-of-Use
    - Voting/Rating Manipulation
    - Referral System Abuse
    - Auction Sniping
    - Booking System Race Conditions
    - Document Signing Bypass
    - Workflow Bypass (step skipping)
    - Multi-factor Authentication Bypass
    - Geolocation Spoofing
    - Loyalty Program Exploitation

### 🧠 Advanced Exploitation

    - WebAssembly Memory Corruption
    - IndexedDB SQL Injection
    - Web Audio API Fingerprinting
    - WebGL GPU Memory Inspection
    - WebUSB Device Access
    - Web Bluetooth Recon
    - WebNFC Exploitation
    - Web Serial API Attacks
    - WebHID Device Spoofing
    - WebTransport Protocol Abuse
    - WebCodecs Memory Leaks
    - WebNN Machine Learning Model Poisoning

## 📝 REPORTING & REMEDIATION

    - Clear Reproduction Steps
    - Impact Analysis (CVSS Scoring)
    - Screenshots/Video PoC
    - Curl Commands for API Issues
    - Browser Console Output
    - Burp Suite Project Files
    - Mitigation Recommendations
    - References to OWASP/CWE
    - Legal Disclosure Compliance
    - Follow-up Testing Plan

# 🛠️ RECOMMENDED TOOLSET

    - Recon: Amass, Subfinder, Assetfinder, gau
    - Scanning: Nuclei, Burp Suite, ZAP, nikto
    - Fuzzing: ffuf, wfuzz, kiterunner, Arjun
    - APIesting**: Postman, Insomnia, graphqlmap
    - Cloud: ScoutSuite, cloudsploit, pacu
    - Exploitation: sqlmap, commix, jwt_tool
    - Automation: custom Python/Bash scripts
    - Debugging: Chrome DevTools, Wireshark
