#!/bin/bash

# Create output directory if it doesn't exist
mkdir -p ./output

###########################################################
# Subdomain Enumeration
###########################################################

# 1. Subdomain Enumeration with `subfinder` (Passive + Recursive)
subfinder -dL domains.txt -all -recursive -o ./output/subdomains.txt
# - `subfinder`: A fast subdomain enumeration tool that uses passive sources and APIs.
# - `-dL`: Input file containing domains.
# - `-all`: Use all available sources for enumeration.
# - `-recursive`: Perform recursive subdomain enumeration.

# 2. Fetch Subdomains from Certificate Transparency Logs (crt.sh)
curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sort -u | anew ./output/subdomains.txt
# - `crt.sh`: Queries Certificate Transparency logs for subdomains.
# - `jq`: Parses JSON output to extract subdomains.
# - `anew`: Appends new results to the existing file.

# 3. Check Which Subdomains Are Alive with `httpx`
cat ./output/subdomains.txt | httpx -ports 80,443,8080,8000,8888 -threads 200 -o ./output/subdomains_alive.txt
# - `httpx`: A fast and modern tool for checking live HTTP/HTTPS services.
# - `-ports`: Specify ports to scan.
# - `-threads`: Number of concurrent threads.

# 4. Count the Number of Alive Subdomains
cat ./output/subdomains_alive.txt | wc -l

###########################################################
# Port Scanning and Service Detection
###########################################################

# 5. Port Scanning and Service Detection with `naabu`
naabu -list ./output/subdomains.txt -c 50 -nmap-cli 'nmap -sV -sC' -o ./output/naabu-full.txt
# - `naabu`: A fast port scanner with nmap integration.
# - `-nmap-cli`: Run nmap with version detection and default scripts.

###########################################################
# Directory and Path Discovery
###########################################################

# 6. Directory Brute Forcing with `feroxbuster`
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -o ./output/directory.txt
# - `feroxbuster`: A fast and recursive directory brute-forcing tool.
# - `-w`: Wordlist for brute-forcing.

# 7. Extract Parameters from Alive Subdomains with `gau`
cat ./output/subdomains_alive.txt | gau > ./output/params.txt
# - `gau`: Fetches URLs from Wayback Machine, Common Crawl, and other sources.

# 8. Filter Parameters with `uro`
cat ./output/params.txt | uro -o ./output/filterparam.txt
# - `uro`: Filters and normalizes URLs.

###########################################################
# JavaScript File Analysis and Secret Extraction
###########################################################

# 9. Find JavaScript Files
cat ./output/filterparam.txt | grep ".js$" > ./output/jsfiles.txt

# 10. Extract Secrets from JavaScript Files with `gitleaks`
cat ./output/jsfiles.txt | while read url; do curl -s "$url" | gitleaks detect --no-git -v >> ./output/secrets.txt; done
# - `gitleaks`: A tool for detecting secrets and sensitive information in files.

###########################################################
# Vulnerability Scanning and Analysis
###########################################################

# 11. Run Nuclei Scans for Common Vulnerabilities
nuclei -l ./output/subdomains_alive.txt -t /nuclei-templates/ -c 50 -o ./output/nuclei-results.txt
# - `nuclei`: A fast vulnerability scanner with a large template library.
# - `-t`: Path to Nuclei templates.

# 12. Run Nuclei Scans for Specific Tags (e.g., CORS, XSS, SQLi)
nuclei -l ./output/subdomains_alive.txt -tags cors,xss,sqli -o ./output/nuclei-tagged-results.txt

###########################################################
# Advanced Scanning and Enumeration
###########################################################

# 13. URL and Parameter Extraction with `katana`
katana -u ./output/subdomains_alive.txt -d 5 -jc -fx -ef png,jpg,css,svg -o ./output/allurls.txt
# - `katana`: A powerful web crawling tool for extracting URLs and parameters.

# 14. Filter for Specific File Types
cat ./output/allurls.txt | grep -E "\.txt|\.log|\.config|\.json" > ./output/sensitive_files.txt

# 15. Run Nuclei Scan for JavaScript Exposures
cat ./output/jsfiles.txt | nuclei -t /nuclei-templates/http/exposures/ -c 30 -o ./output/js-exposures.txt

###########################################################
# Subdomain Takeover and Misconfiguration Testing
###########################################################

# 16. Subdomain Takeover Testing with `subzy`
subzy run --targets ./output/subdomains_alive.txt --verify-ssl -o ./output/subzy-results.txt
# - `subzy`: A tool for detecting subdomain takeover vulnerabilities.

# 17. Test CORS Misconfigurations with `corsy`
python3 corsy.py -i ./output/subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot" -o ./output/corsy-results.txt
# - `corsy`: A tool for testing Cross-Origin Resource Sharing (CORS) misconfigurations.

###########################################################
# Local File Inclusion (LFI) and Directory Traversal Testing
###########################################################

# 18. LFI Testing with `ffuf`
cat ./output/allurls.txt | gf lfi | ffuf -w - -u FUZZ -mr "root:" -o ./output/lfi-results.txt
# - `ffuf`: A fast web fuzzer for testing vulnerabilities like LFI.

# 19. Directory Traversal Testing with `dotdotpwn`
dotdotpwn -m http-url -d 10 -f /etc/passwd -u "http://target.com?page=TRAVERSAL" -b -k "root:" -o ./output/dotdotpwn-results.txt
# - `dotdotpwn`: A tool for testing directory traversal vulnerabilities.

###########################################################
# Open Redirect and CRLF Injection Testing
###########################################################

# 20. Open Redirect Testing with `openredirex`
cat ./output/allurls.txt | gf redirect | openredirex -p ./payloads/open-redirects.txt -o ./output/open-redirect-results.txt
# - `openredirex`: A tool for testing open redirect vulnerabilities.

# 21. CRLF Injection Testing with `crlfuzz`
crlfuzz -l ./output/subdomains_alive.txt -o ./output/crlf-results.txt
# - `crlfuzz`: A tool for testing CRLF injection vulnerabilities.

###########################################################
# Google Dorks and OSINT
###########################################################

# 22. Google Dorks for Sensitive Files
# Example: site:target.com ext:log | ext:txt | ext:conf
# Use tools like `go-dork` or manually search for sensitive files.

###########################################################
# Advanced JavaScript Analysis
###########################################################

# 23. Extract and Analyze JavaScript Files with `jsleak`
cat ./output/jsfiles.txt | jsleak -o ./output/jsleak-results.txt
# - `jsleak`: A tool for extracting sensitive information from JavaScript files.

###########################################################
# Parameter Spidering and Fuzzing
###########################################################

# 24. Parameter Spidering with `paramspider`
paramspider -d target.com --subs -o ./output/paramspider-results.txt
# - `paramspider`: A tool for spidering and extracting parameters from URLs.

# 25. Fuzz Parameters with `ffuf`
cat ./output/paramspider-results.txt | ffuf -w - -u FUZZ -mc 200 -o ./output/ffuf-results.txt
# - `ffuf`: A fast web fuzzer for testing parameters and endpoints.

###########################################################
# Tool Descriptions (Reference Section)
###########################################################

# subfinder - A fast subdomain enumeration tool that uses passive sources and APIs.
# httpx - A modern tool for checking live HTTP/HTTPS services.
# naabu - A fast port scanner with nmap integration.
# feroxbuster - A fast and recursive directory brute-forcing tool.
# gau - Fetches URLs from Wayback Machine, Common Crawl, and other sources.
# uro - Filters and normalizes URLs.
# gitleaks - Detects secrets and sensitive information in files.
# nuclei - A fast vulnerability scanner with a large template library.
# katana - A powerful web crawling tool for extracting URLs and parameters.
# subzy - A tool for detecting subdomain takeover vulnerabilities.
# corsy - A tool for testing CORS misconfigurations.
# ffuf - A fast web fuzzer for testing vulnerabilities like LFI and open redirects.
# dotdotpwn - A tool for testing directory traversal vulnerabilities.
# openredirex - A tool for testing open redirect vulnerabilities.
# crlfuzz - A tool for testing CRLF injection vulnerabilities.
# jsleak - A tool for extracting sensitive information from JavaScript files.
# paramspider - A tool for spidering and extracting parameters from URLs.