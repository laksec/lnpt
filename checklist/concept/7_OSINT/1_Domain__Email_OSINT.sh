### 7.1 Domain & Email OSINT
    # Gather emails, subdomains, hosts
    theHarvester -d target.com -l 500 -b google,bing,linkedin -o harvester_report.html 
    
    # Use all available sources
    theHarvester -d target.com -b all -f harvester_results_all.xml
    
    # Hunt for social media accounts by username
    sherlock username123 --timeout 10 -o sherlock_results.txt
    
    # Check multiple usernames, output CSV
    sherlock user1 user2 user3 --csv -o sherlock_multiuser.csv#!/bin/bash
# ==============================================
# DOMAIN & EMAIL OSINT CHEAT SHEET
# ==============================================

# 1. DOMAIN RECONNAISSANCE
# ------------------------

# WHOIS Lookup
whois target.com
whois -h whois.radb.net target.com  # For routing info

# DNS Enumeration
dig target.com ANY +noall +answer
dnsenum target.com
dnsrecon -d target.com -t std

# Subdomain Discovery
amass enum -passive -d target.com -o amass.txt
subfinder -d target.com -o subfinder.txt
assetfinder --subs-only target.com > assetfinder.txt

# Certificate Transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crt_sh.txt

# 2. EMAIL OSINT
# --------------

# Email Pattern Discovery
theHarvester -d target.com -b all -f email_report
python3 hunter.io.py -d target.com -k YOUR_API_KEY

# Password Breach Check
haveibeenpwned -e user@target.com
python3 hibp_breach_check.py -e user@target.com

# Email Verification
smtp-user-enum -M VRFY -U emails.txt -t mail.target.com
python3 verifyemail.py -e user@target.com

# 3. INFRASTRUCTURE OSINT
# -----------------------

# IP History Check
curl -s "https://api.viewdns.info/iphistory/?domain=target.com&apikey=YOUR_API_KEY&output=json" | jq

# ASN Lookup
curl -s "https://api.hackertarget.com/aslookup/?q=target.com"

# Cloud Bucket Discovery
cloud_enum -k target -l cloud_discovery.txt

# 4. SOCIAL MEDIA OSINT
# ---------------------

# Username Search
python3 sherlock user@target.com
maigret username -a

# Company Mentions
python3 socialscan.py "target.com" -p twitter,linkedin

# 5. ADVANCED TECHNIQUES
# ----------------------

# Google Dorks
google-dork "site:target.com filetype:pdf"
python3 dorkbot.py -d target.com -o dorks.txt

# Metadata Extraction
exiftool -a -u -g1 downloaded_file.pdf
FOCA -d target.com -s

# 6. AUTOMATION TOOLS
# -------------------

# Recon-ng
recon-ng -m recon/domains-hosts/brute_hosts -c "set SOURCE target.com"

# SpiderFoot
python3 sf.py -q -s target.com -m all

# Maltego
# Use built-in transforms for comprehensive mapping

# 7. DATA AGGREGATION
# -------------------

# Combine results
cat amass.txt subfinder.txt assetfinder.txt | anew all_subdomains.txt

# Visualize relationships
python3 osint_graph.py -d target.com -o graph.html

# ==============================================
# TIPS:
# 1. Always verify information from multiple sources
# 2. Respect data privacy laws and terms of service
# 3. Use API keys responsibly (rate limits)
# 4. Document your findings systematically
# ==============================================

# RECOMMENDED RESOURCES:
# ----------------------
# WHOIS servers: whois.iana.org, whois.arin.net
# DNS servers: 1.1.1.1, 8.8.8.8
# Breach databases: Have I Been Pwned, DeHashed
# Subdomain wordlists: all.txt (Seclists), subdomains-top1million.txt

# INSTALLATION NOTES:
# -------------------
# amass: brew install amass OR docker pull caffix/amass
# theHarvester: pip install theHarvester
# sherlock: pip install sherlock
# maigret: pip install maigret

# Domain OSINT Checklist:
# Registration Details:
# WHOIS records
# Historical WHOIS (whois-history.com)
# Registrar information
# DNS Intelligence:
# A, MX, TXT records
# Historical DNS (DNSdumpster)
# Subdomain relationships

# Infrastructure:
# IP ranges and ASNs
# Cloud hosting identification
# Server technologies

# Email OSINT Checklist:
# Email Discovery:
# Pattern identification (first.last@domain)
# Breach database checks
# MX record verification

# Account Enumeration:
# Password reset probing
# SMTP user enumeration
# Social media connections
# Threat Intelligence:
# Phishing history
# Spam blacklists
# Domain reputation

# Advanced Techniques:
# Brand Monitoring: Track mentions across pastebins and forums
# Employee Discovery: LinkedIn scraping + email pattern matching
# Domain Age Analysis: Identify recently created suspicious domains
# SSL Certificate Analysis: Find related domains through cert issuances