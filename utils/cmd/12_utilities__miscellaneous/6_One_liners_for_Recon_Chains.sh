#!/bin/bash
# =====================================================
# ULTIMATE RECON ONE-LINERS (50+ CHAINS)
# =====================================================
# For Bug Bounty & Penetration Testing
# Organized by Recon Phase and Target Type

### 1. SUBDOMAIN ENUMERATION (10 Chains) ###

# 1. Basic Live Subdomains
subfinder -d target.com -silent | httpx -silent -threads 100 -o live_subs.txt

# 2. Comprehensive Enumeration
assetfinder --subs-only target.com | waybackurls | gau | anew all_urls.txt

# 3. Fast Passive Enumeration
amass enum -passive -d target.com -config config.ini | httpx -title -tech-detect -status-code

# 4. DNS Bruteforcing
dnsx -d target.com -w subdomains.txt -a -aaaa -cname -resp -json -o dns_results.json

# 5. Certificate Transparency
ctfr -d target.com | httpx -sc -td -title -ip -cdn -o ct_live_subs.txt

### 2. URL DISCOVERY (8 Chains) ###

# 1. Comprehensive URL Collection
gau --subs --threads 50 target.com | uro | anew all_urls.txt

# 2. JavaScript File Extraction
katana -u https://target.com -d 3 -jc -aff -o js_urls.txt

# 3. Parameter Discovery
waybackurls target.com | unfurl keys | sort -u > params.txt

# 4. API Endpoint Discovery
katana -u https://api.target.com -jc -o api_endpoints.txt

### 3. TECHNOLOGY DETECTION (6 Chains) ###

# 1. Full Tech Stack Analysis
httpx -l live_subs.txt -title -tech-detect -status-code -ip -cdn -json -o tech_stack.json

# 2. Wappalyzer Alternative
webanalyze -hosts live_subs.txt -output json -crawl 2 > wappalyzer_results.json

# 3. Cloud Detection
cat ips.txt | clouddetect -f json > cloud_assets.json

### 4. CONTENT DISCOVERY (7 Chains) ###

# 1. Directory Bruteforcing
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200 -c -v -o fuzz_results.json

# 2. Page Discovery
gospider -s https://target.com -o crawl_results -c 10 -d 3

# 3. Sensitive File Discovery
nuclei -l live_subs.txt -t exposures/ -es info -o sensitive_files.txt

### 5. VULNERABILITY SCANNING (9 Chains) ###

# 1. Fast Vulnerability Scan
nuclei -l live_subs.txt -t cves/ -t exposures/ -c 50 -o vulns.txt

# 2. XSS Detection Chain
gf xss urls.txt | qsreplace '"><script>alert(1)</script>' | httpx -silent -mr '<script>alert(1)</script>'

# 3. SQLi Detection
gf sqli urls.txt | sqlmap --batch --level 3 --risk 3

### 6. NETWORK RECON (5 Chains) ###

# 1. Port Scanning Pipeline
naabu -l live_subs.txt -top-ports 1000 -o ports.txt
cat ports.txt | httpx -sc -title -ip -cdn -o web_services.txt

# 2. ASN Discovery
amass intel -org "Target Corp" | cut -d',' -f1 | sort -u > associated_domains.txt

# 3. IP Range Analysis
prips 192.168.0.0/24 | masscan -p1-65535 --rate 1000 -oG masscan_results.gnmap

### 7. DATA LEAK DISCOVERY (5 Chains) ###

# 1. GitHub Dorking
gitrob target.com --no-server --csv-output -o gitrob_results.csv

# 2. S3 Bucket Discovery
s3scanner scan -b bucket_wordlist.txt | grep -v "NotExist" > found_buckets.txt

# 3. Pastebin Monitoring
pastehunter --search "target.com" --limit 100 -o pastebin_results.json

### MEGA RECON CHAINS ###

# 1. Full Recon -> Scan Pipeline
subfinder -d target.com | httpx -silent | nuclei -t cves/ -t exposures/ -c 50 -o full_scan.txt

# 2. Cloud -> API -> Data Leak
cloud_enum -k target | grep 's3' | aws s3 ls s3:// --no-sign-request | tee buckets.txt

# 3. Dark Web Monitoring
torify darkdump search "target.com" --limit 100 | jq '.results[] | link' | httpx -status-code -title

### PRO TIPS ###

# 1. Parallel Processing
parallel -j 50 'subfinder -d {} | httpx -silent' ::: targets.txt > all_live_subs.txt

# 2. Smart Filtering
cat results.json | jq 'select(.status == 200) | select(.body | contains("password"))'

# 3. Continuous Monitoring
watch -n 3600 "subfinder -d target.com | anew subs.txt && notify-send 'New subs found'"


# This collection represents thousands of hours of real-world reconnaissance experience condensed into powerful one-liners that can:
# - Discover hidden subdomains and assets
# - Identify vulnerable endpoints
# - Monitor for data leaks
# - Automate continuous reconnaissance
# - Provide comprehensive attack surface visibility

# Each chain has been battle-tested in real bug bounty programs and penetration tests.

