## Web Application Security Testing

### 1 Information Gathering
    1.1 Search Engine Discovery Reconn for Information Leakage
    1.2 Fingerprint Web Server
    1.3 Review Webserver Metafiles for Information Leakage
    1.4 Enumerate Applications on Webserver
    1.5 Review Web Page Content for Information Leakage
    1.6 Identify Application Entry Points
    1.7 Map Execution Paths Through Application
    1.8 Fingerprint Web Application Framework
    1.9 Fingerprint Web Application
    1.10 Map Application Architecture

### 2_Config_and_Deployment_Management.md Testing
    2.1 Test Network Infrastructure Configuration
    2.2 Test Application Platform Configuration
    2.3 Test File Extensions Handling for Sensitive Information
    2.4 Review Old Backup and Unreferenced Files for Sensitive Information
    2.5 Enumerate Infrastructure and Application Admin Interfaces
    2.6 Test HTTP Methods
    2.7 Test HTTP Strict Transport Security
    2.8 Test RIA Cross Domain Policy
    2.9 Test File Permission
    2.10 Test for Subdomain Takeover
    2.11 Test Cloud Storage
    2.12 Test for Content Security Policy
    2.13 Test for Path Confusion
    2.14 Test for Other HTTP Security Header Misconfigurations

### 3_Identity_Management_Testing
    3.1 Test Role Definitions
    3.2 Test User Registration Process
    3.3 Test Account Provisioning Process
    3.4 Testing for Account Enumeration and Guessable User Account
    3.5 Testing for Weak or Unenforced Username Policy

### 4_Authentication_Testing
    4.1 Testing for Credentials Transported over an Encrypted Channel
    4.2 Testing for Default Credentials
    4.3 Testing for Weak Lock Out Mechanism
    4.4 Testing for Bypassing Authentication Schema
    4.5 Testing for Vulnerable Remember Password
    4.6 Testing for Browser Cache Weaknesses
    4.7 Testing for Weak Authentication Methods
    4.8 Testing for Weak Security Question Answer
    4.9 Testing for Weak Password Change or Reset Functionalities
    4.10 Testing for Weaker Authentication in Alternative Channel
    4.11 Testing Multi-Factor Authentication

### 5_Authorization Testing
    5.1 Testing Directory Traversal File Include
    5.2 Testing for Bypassing Authorization Schema
    5.3 Testing for Privilege Escalation
    5.4 Testing for Insecure Direct Object References
    5.5 Testing for OAuth Weaknesses
    5.5.1 Testing for OAuth Authorization Server Weaknesses
    5.5.2 Testing for OAuth Client Weaknesses

### 6_Session Management Testing
    6.1 Testing for Session Management Schema
    6.2 Testing for Cookies Attributes
    6.3 Testing for Session Fixation
    6.4 Testing for Exposed Session Variables
    6.5 Testing for Cross Site Request Forgery
    6.6 Testing for Logout Functionality
    6.7 Testing Session Timeout
    6.8 Testing for Session Puzzling
    6.9 Testing for Session Hijacking
    6.10 Testing JSON Web Tokens
    6.11 Testing for Concurrent Sessions

### 7 Input Validation Testing
    7.1 Testing for Reflected Cross Site Scripting
    7.2 Testing for Stored Cross Site Scripting
    7.3 Testing for HTTP Verb Tampering
    7.4 Testing for HTTP Parameter Pollution
    7.5 Testing for SQL Injection
        7.5.1 Testing for Oracle
        7.5.2 Testing for MySQL
        7.5.3 Testing for SQL Server
        7.5.4 Testing PostgreSQL
        7.5.5 Testing for MS Access
        7.5.6 Testing for NoSQL Injection
        7.5.7 Testing for ORM Injection
        7.5.8 Testing for Client-side

    7.6 Testing for LDAP Injection
    7.7 Testing for XML Injection
    7.8 Testing for SSI Injection
    7.9 Testing for XPath Injection
    7.10 Testing for IMAP SMTP Injection
    7.11 Testing for Code Injection
        7.11.1 Testing for File Inclusion
        
    7.12 Testing for Command Injection
    7.13 Testing for Format String Injection
    7.14 Testing for Incubated Vulnerability
    7.15 Testing for HTTP Splitting Smuggling
    7.16 Testing for HTTP Incoming Requests
    7.17 Testing for Host Header Injection
    7.18 Testing for Server-side Template Injection
    7.19 Testing for Server-Side Request Forgery
    7.20 Testing for Mass Assignment

### 8 Testing for Error Handling
    8.1 Testing for Improper Error Handling
    8.2 Testing for Stack Traces

### 9 Testing for Weak Cryptography
    9.1 Testing for Weak Transport Layer Security
    9.2 Testing for Padding Oracle
    9.3 Testing for Sensitive Information Sent via Unencrypted Channels
    9.4 Testing for Weak Encryption

### 10 Business Logic Testing
    10.0 Introduction to Business Logic
    10.1 Test Business Logic Data Validation
    10.2 Test Ability to Forge Requests
    10.3 Test Integrity Checks
    10.4 Test for Process Timing
    10.5 Test Number of Times a Function Can Be Used Limits
    10.6 Testing for the Circumvention of Work Flows
    10.7 Test Defenses Against Application Misuse
    10.8 Test Upload of Unexpected File Types
    10.9 Test Upload of Malicious Files
    10.10 Test Payment Functionality

### 11 Client-Side Testing
    11.1 Testing for DOM-Based Cross Site Scripting
    11.1.1 Testing for Self DOM Based Cross Site Scripting
    11.2 Testing for JavaScript Execution
    11.3 Testing for HTML Injection
    11.4 Testing for Client-side URL Redirect
    11.5 Testing for CSS Injection
    11.6 Testing for Client-side Resource Manipulation
    11.7 Testing Cross Origin Resource Sharing
    11.8 Testing for Cross Site Flashing
    11.9 Testing for Clickjacking
    11.10 Testing WebSockets
    11.11 Testing Web Messaging
    11.12 Testing Browser Storage
    11.13 Testing for Cross Site Script Inclusion
    11.14 Testing for Reverse Tabnabbing

### 12 API Testing
    12.0 API Testing Overview
    12.1 API Reconnaissance
    12.2 API Broken Object Level Authorization
    12.99 Testing GraphQL
