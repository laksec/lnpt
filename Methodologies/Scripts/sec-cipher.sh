#!/bin/bash

# Define target domain
TARGET="target.com"

# Basic Information Gathering

# WHOIS Lookup
echo "1. WHOIS Lookup"
whois $TARGET

# DNS Lookup
echo "2. DNS Lookup"
nslookup $TARGET
dig $TARGET

# DNS Records for Name Servers and Mail Servers
echo "3. DNS Records for Name Servers and Mail Servers"
host -t ns $TARGET
host -t mx $TARGET

# Subdomain Enumeration

# Subdomain Enumeration with Various Tools
echo "4. Subdomain Enumeration with Various Tools"
sublist3r -d $TARGET
amass enum -d $TARGET
assetfinder --subs-only $TARGET
findomain -t $TARGET

# Mass DNS Resolution
echo "5. Mass DNS Resolution"
massdns -r resolvers.txt -t A -o S -w results.txt -d subdomains.txt

# Check Live Subdomains
echo "6. Check Live Subdomains"
httprobe < subdomains.txt > live_subdomains.txt
httpx -1 subdomains.txt -o live_hosts.txt

# Scanning and Enumeration

# Nmap Scan for Live Hosts
echo "7. Nmap Scan for Live Hosts"
nmap -iL live_hosts.txt -oA nmap_scan

# Web Technology Fingerprinting
echo "8. Web Technology Fingerprinting"
whatweb -i live_hosts.txt

# Additional Discovery
echo "9. Additional Discovery"
aquatone-discover -d $TARGET
waybackurls $TARGET | tee waybackurls.txt
gau $TARGET | tee gau_urls.txt
hakrawler -url $TARGET -depth 2 -plain | tee hakrawler_output.txt

# Git and Code Repository Searches
echo "10. Git and Code Repository Searches"
github-search $TARGET
gitrob -repo $TARGET
fierce domain $TARGET

# Directory and File Brute Forcing

# Directory Brute Forcing
echo "11. Directory Brute Forcing"
dirsearch -u $TARGET -e *

# Advanced Directory and File Brute Forcing
echo "12. Advanced Directory and File Brute Forcing"
ffuf -w wordlist.txt -u https://$TARGET/FUZZ

# Screenshot Capture
echo "13. Screenshot Capture"
gowitness file -f live_hosts.txt -P screenshots/

# Vulnerability Scanning

# Nuclei Scanning
echo "14. Nuclei Scanning"
nuclei -l live_hosts.txt -t templates/

# Metadata and File Scanning
echo "15. Metadata and File Scanning"
metabigor net org $TARGET
metagoofil -d $TARGET -t doc,pdf,xls,docx,xlsx,ppt,pptx -l 100

# Information Harvesting
echo "16. Information Harvesting"
theHarvester -d $TARGET -l 500 -b all

# DNS and Cloud Enumeration

# DNS Enumeration
echo "17. DNS Enumeration"
dnsenum $TARGET
dnsrecon -d $TARGET
shodan search hostname:$TARGET
censys search $TARGET

# Advanced Enumeration and Scanning
echo "18. Advanced Enumeration and Scanning"
spiderfoot -s $TARGET -o spiderfoot_report.html
sniper -t $TARGET

# Web Application Security Testing

# Subdomain Scanning and WAF Detection
echo "19. Subdomain Scanning and WAF Detection"
subfinder -d $TARGET -o subfinder_results.txt
wafw00f $TARGET

# Parameter and Secret Scanning
echo "20. Parameter and Secret Scanning"
arjun -u https://$TARGET -oT arjun_output.txt
subjack -w subdomains.txt -t 20 -o subjack_results.txt

# Content Discovery and URL Fuzzing
echo "21. Content Discovery and URL Fuzzing"
meg -d 1000 -v /path/to/live_subdomains.txt
waymore -u $TARGET -o waymore_results.txt
unfurl -u $TARGET -o unfurl_results.txt

# XSS and Other Payload Testing
echo "22. XSS and Other Payload Testing"
dalfox file live_hosts.txt
gospider -S live_hosts.txt -o gospider_output/
recon-ng -w workspace -i $TARGET
xray webscan --basic-crawler http://$TARGET
vhost -u $TARGET -o vhost_results.txt

# Vhost Scanning
echo "23. Vhost Scanning"
vhost -u $TARGET -o vhost_results.txt

# Payload Generation and Validation

# Generate Payloads for Various Attacks
echo "24. Generate Payloads for Various Attacks"
gf xss | tee xss_payloads.txt
gf sqli | tee sqli_payloads.txt
gf lfi | tee lfi_payloads.txt
gf ssrf | tee ssrf_payloads.txt
gf idor | tee idor_payloads.txt
gf ssti | tee ssti_payloads.txt

# Git and Secret Scanning
echo "25. Git and Secret Scanning"
git-secrets --scan

# DNS and Network Scanning

# Advanced DNS Scanning and Enumeration
echo "26. Advanced DNS Scanning and Enumeration"
shuffledns -d $TARGET -list resolvers.txt -o shuffledns_results.txt
dnsgen -f subdomains.txt | massdns -r resolvers.txt -t A -o S -w dnsgen_results.txt
mapcidr -silent -cidr $TARGET -o mapcidr_results.txt

# Additional Scanning and Enumeration

# Advanced DNS Scanning with TKO-Subs
echo "27. Advanced DNS Scanning with TKO-Subs"
tko-subs -d $TARGET -data-providers data.csv

# Directory and File Fuzzing with Kiterunner
echo "28. Directory and File Fuzzing with Kiterunner"
kiterunner -w wordlist.txt -u https://$TARGET

# GitHub Dorking for Sensitive Information
echo "29. GitHub Dorking for Sensitive Information"
github-dorker -d $TARGET

# Redirect Payload Generation with GF
echo "30. Redirect Payload Generation with GF"
gfredirect -u $TARGET

# Parameter Discovery with Paramspider
echo "31. Parameter Discovery with Paramspider"
paramspider --domain $TARGET --output paramspider_output.txt

# Directory Brute Forcing with Dirb
echo "32. Directory Brute Forcing with Dirb"
dirb https://$TARGET/ -o dirb_output.txt

# WordPress Vulnerability Scanning with WPScan
echo "33. WordPress Vulnerability Scanning with WPScan"
wpscan --url $TARGET

# Cloud Resource Enumeration with Cloud Enum
echo "34. Cloud Resource Enumeration with Cloud Enum"
cloud_enum -k $TARGET -o cloud_enum_output.txt

# DNS Brute Forcing with Gobuster
echo "35. DNS Brute Forcing with Gobuster"
gobuster dns -d $TARGET -t 50 -w wordlist.txt

# Subdomain Enumeration with Subzero
echo "36. Subdomain Enumeration with Subzero"
subzero -d $TARGET

# DNS Walking with DNSWalk
echo "37. DNS Walking with DNSWalk"
dnswalk $TARGET

# Port Scanning with Masscan
echo "38. Port Scanning with Masscan"
masscan -iL live_hosts.txt -p0-65535 -oX masscan_results.xml

# Cross-Site Scripting Testing with XSStrike
echo "39. Cross-Site Scripting Testing with XSStrike"
xsstrike -u https://$TARGET

# Open Redirect Testing with Byp4xx
echo "40. Open Redirect Testing with Byp4xx"
byp4xx https://$TARGET/FUZZ

# DNS Resolution with DNSx
echo "41. DNS Resolution with DNSx"
dnsx -iL subdomains.txt -resp-only -o dnsx_results.txt

# Wayback Machine Data Collection with Waybackpack
echo "42. Wayback Machine Data Collection with Waybackpack"
waybackpack $TARGET -d output/

# PureDNS for Subdomain Resolution
echo "43. PureDNS for Subdomain Resolution"
puredns resolve subdomains.txt -r resolvers.txt -w puredns_results.txt

# Certificate Transparency Logging with CTFR
echo "44. Certificate Transparency Logging with CTFR"
ctfr -d $TARGET -o ctfr_results.txt

# DNS Resolver Validation with DNSValidator
echo "45. DNS Resolver Validation with DNSValidator"
dnsvalidator -t 100 -f resolvers.txt -o validated_resolvers.txt

# HTTP Check with HTTPX
echo "46. HTTP Check with HTTPX"
httpx -silent -iL live_subdomains.txt -mc 200 title -tech-detect -o httpx_results.txt

# Cloud Resource Enumeration (Alternative)
echo "47. Cloud Resource Enumeration (Alternative)"
cloud_enum -k $TARGET -o cloud_enum_results.txt

echo "Bug bounty methodology completed."
