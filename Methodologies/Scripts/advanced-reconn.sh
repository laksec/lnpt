#!/bin/bash

# Create output directory if it doesn't exist
mkdir -p ./output

###########################################################
# Subdomain Enumeration
###########################################################

# 1. Passive Subdomain Enumeration with `amass`
amass enum -passive -d target.com -o ./output/amass_passive.txt
# - `amass`: A powerful tool for subdomain enumeration using passive sources (APIs, certificates, etc.).
# - `-passive`: Only use passive enumeration techniques to avoid detection.

# 2. Active Subdomain Enumeration with `amass`
amass enum -active -d target.com -o ./output/amass_active.txt
# - `-active`: Perform active enumeration (brute-forcing, DNS queries).

# 3. Fetch Subdomains from Certificate Transparency Logs (crt.sh)
curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sort -u | anew ./output/crt_subdomains.txt
# - `crt.sh`: Queries Certificate Transparency logs for subdomains.
# - `jq`: Parses JSON output to extract subdomains.
# - `anew`: Appends new results to the existing file.

# 4. Combine and Deduplicate Subdomains
cat ./output/amass_passive.txt ./output/amass_active.txt ./output/crt_subdomains.txt | sort -u > ./output/all_subdomains.txt

# 5. Check Which Subdomains Are Alive with `httpx`
cat ./output/all_subdomains.txt | httpx -ports 80,443,8080,8000,8888 -threads 200 -o ./output/live_subdomains.txt
# - `httpx`: A fast and modern tool for checking live HTTP/HTTPS services.
# - `-ports`: Specify ports to scan.
# - `-threads`: Number of concurrent threads.

###########################################################
# Port Scanning and Service Detection
###########################################################

# 6. Port Scanning with `naabu`
naabu -list ./output/live_subdomains.txt -c 50 -nmap-cli 'nmap -sV -sC' -o ./output/naabu_results.txt
# - `naabu`: A fast port scanner with nmap integration.
# - `-nmap-cli`: Run nmap with version detection and default scripts.

###########################################################
# Directory and Path Discovery
###########################################################

# 7. Directory Brute Forcing with `feroxbuster`
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -o ./output/directory_scan.txt
# - `feroxbuster`: A fast and recursive directory brute-forcing tool.
# - `-w`: Wordlist for brute-forcing.

# 8. Extract Parameters from Alive Subdomains with `gau`
cat ./output/live_subdomains.txt | gau > ./output/params.txt
# - `gau`: Fetches URLs from Wayback Machine, Common Crawl, and other sources.

# 9. Filter Parameters with `uro`
cat ./output/params.txt | uro -o ./output/filtered_params.txt
# - `uro`: Filters and normalizes URLs.

###########################################################
# JavaScript File Analysis and Secret Extraction
###########################################################

# 10. Find JavaScript Files
cat ./output/filtered_params.txt | grep ".js$" > ./output/jsfiles.txt

# 11. Extract Secrets from JavaScript Files with `gitleaks`
cat ./output/jsfiles.txt | while read url; do curl -s "$url" | gitleaks detect --no-git -v >> ./output/secrets.txt; done
# - `gitleaks`: A tool for detecting secrets and sensitive information in files.

###########################################################
# Vulnerability Scanning and Analysis
###########################################################

# 12. Run Nuclei Scans for Common Vulnerabilities
nuclei -l ./output/live_subdomains.txt -t /nuclei-templates/ -c 50 -o ./output/nuclei_results.txt
# - `nuclei`: A fast vulnerability scanner with a large template library.
# - `-t`: Path to Nuclei templates.

# 13. Run Nuclei Scans for Specific Tags (e.g., CORS, XSS, SQLi)
nuclei -l ./output/live_subdomains.txt -tags cors,xss,sqli -o ./output/nuclei_tagged_results.txt

###########################################################
# Advanced Scanning and Enumeration
###########################################################

# 14. URL and Parameter Extraction with `katana`
katana -u ./output/live_subdomains.txt -d 5 -jc -fx -ef png,jpg,css,svg -o ./output/all_urls.txt
# - `katana`: A powerful web crawling tool for extracting URLs and parameters.

# 15. Filter for Specific File Types
cat ./output/all_urls.txt | grep -E "\.txt|\.log|\.config|\.json" > ./output/sensitive_files.txt

# 16. Run Nuclei Scan for JavaScript Exposures
cat ./output/jsfiles.txt | nuclei -t /nuclei-templates/http/exposures/ -c 30 -o ./output/js_exposures.txt

###########################################################
# Subdomain Takeover and Misconfiguration Testing
###########################################################

# 17. Subdomain Takeover Testing with `subjack`
subjack -w ./output/live_subdomains.txt -o ./output/subjack_results.txt
# - `subjack`: A tool for detecting subdomain takeover vulnerabilities.

# 18. Test CORS Misconfigurations with `corsy`
python3 corsy.py -i ./output/live_subdomains.txt -t 10 --headers "User-Agent: GoogleBot" -o ./output/corsy_results.txt
# - `corsy`: A tool for testing Cross-Origin Resource Sharing (CORS) misconfigurations.

###########################################################
# Local File Inclusion (LFI) and Directory Traversal Testing
###########################################################

# 19. LFI Testing with `ffuf`
cat ./output/all_urls.txt | gf lfi | ffuf -w - -u FUZZ -mr "root:" -o ./output/lfi_results.txt
# - `ffuf`: A fast web fuzzer for testing vulnerabilities like LFI.

# 20. Directory Traversal Testing with `dotdotpwn`
dotdotpwn -m http-url -d 10 -f /etc/passwd -u "http://target.com?page=TRAVERSAL" -b -k "root:" -o ./output/dotdotpwn_results.txt
# - `dotdotpwn`: A tool for testing directory traversal vulnerabilities.

###########################################################
# Open Redirect and CRLF Injection Testing
###########################################################

# 21. Open Redirect Testing with `openredirex`
cat ./output/all_urls.txt | gf redirect | openredirex -p ./payloads/open-redirects.txt -o ./output/open_redirect_results.txt
# - `openredirex`: A tool for testing open redirect vulnerabilities.

# 22. CRLF Injection Testing with `crlfuzz`
crlfuzz -l ./output/live_subdomains.txt -o ./output/crlf_results.txt
# - `crlfuzz`: A tool for testing CRLF injection vulnerabilities.

###########################################################
# Tool Descriptions (Reference Section)
###########################################################

# amass - A powerful tool for subdomain enumeration using passive and active techniques.
# crt.sh - Queries Certificate Transparency logs for subdomains.
# httpx - A modern tool for checking live HTTP/HTTPS services.
# naabu - A fast port scanner with nmap integration.
# feroxbuster - A fast and recursive directory brute-forcing tool.
# gau - Fetches URLs from Wayback Machine, Common Crawl, and other sources.
# uro - Filters and normalizes URLs.
# gitleaks - Detects secrets and sensitive information in files.
# nuclei - A fast vulnerability scanner with a large template library.
# katana - A powerful web crawling tool for extracting URLs and parameters.
# subjack - A tool for detecting subdomain takeover vulnerabilities.
# corsy - A tool for testing CORS misconfigurations.
# ffuf - A fast web fuzzer for testing vulnerabilities like LFI and open redirects.
# dotdotpwn - A tool for testing directory traversal vulnerabilities.
# openredirex - A tool for testing open redirect vulnerabilities.
# crlfuzz - A tool for testing CRLF injection vulnerabilities.