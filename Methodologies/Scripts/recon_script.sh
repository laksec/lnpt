#!/bin/bash

# Create output directory if it doesn't exist
mkdir -p ./output

###########################################################
# Basic Information Gathering
###########################################################

# WHOIS Lookup - Retrieves domain registration information
whois 10.0.2.2

# DNS Lookup - Resolves the IP to its domain name (if applicable)
nslookup 10.0.2.2
dig -x 10.0.2.2

# DNS Records for Name Servers and Mail Servers - Retrieves NS and MX records
host -t ns 10.0.2.2
host -t mx 10.0.2.2

###########################################################
# Subdomain Enumeration
###########################################################

# Subdomain Enumeration with Sublist3r - Finds subdomains
sublist3r -d 10.0.2.2 -o ./output/sublist3r_results.txt

# Query Certificate Transparency logs for subdomains using crtsh
crtsh -d 10.0.2.2 -o ./output/crtsh_results.txt

# Gather information from search engines and public sources using theHarvester (Google)
theHarvester -d 10.0.2.2 -b google -l 500 -o ./output/theharvester_google_results.txt

# Gather information from search engines and public sources using theHarvester (All sources)
theHarvester -d 10.0.2.2 -b all -l 500 -o ./output/theharvester_all_results.txt

# Perform DNS reconnaissance using dnsrecon
dnsrecon -d 10.0.2.2 -t std -o ./output/dnsrecon_results.txt

# Enumerate subdomains using findomain
findomain -d 10.0.2.2 -o ./output/findomain_results.txt

# Discover subdomains using shuffledns with a wordlist and resolvers
shuffledns -d 10.0.2.2 -list subdomains.txt -r resolvers.txt -o ./output/shuffledns_results.txt

# Query subdomains via various APIs using hunter
hunter -d 10.0.2.2 -o ./output/hunter_results.txt

# Fetch historical URLs from the Wayback Machine using waybackurls
waybackurls 10.0.2.2 | tee ./output/waybackurls.txt

# Search for domain-related information on GitHub using github-search
github-search -d 10.0.2.2 -o ./output/github_search_results.txt

###########################################################
# Domain and IP Analysis
###########################################################

# Perform a Censys search for the domain
censys search "dns.domain: 10.0.2.2" -o ./output/censys_results.txt

# Search for the domain in the Shodan database
shodan domain 10.0.2.2 -o ./output/shodan_results.txt

# Fetch domain details from SecurityTrails
securitytrails -d 10.0.2.2 -o ./output/securitytrails_results.txt

# Perform DNS analysis and report information using robtex
robtex -d 10.0.2.2 -o ./output/robtex_results.txt

# Fetch certificate information from CertSpotter
certspotter -d 10.0.2.2 -o ./output/certspotter_results.txt

# Detect web technologies running on the domain using Wappalyzer
wappalyzer -u https://10.0.2.2 -o ./output/wappalyzer_results.txt

# Perform DNS queries for the target domain using dig
dig any 10.0.2.2 +short

# Fetch HTTP headers from the domain using curl
curl -I https://10.0.2.2

# Retrieve SSL certificate information using openssl
openssl s_client -connect 10.0.2.2:443 -showcerts

###########################################################
# Advanced Subdomain Enumeration
###########################################################

# Find subdomains using assetfinder
assetfinder --subs-only 10.0.2.2 -o ./output/assetfinder_results.txt

# Perform DNS-based subdomain enumeration using KnockPy
knockpy 10.0.2.2 -o ./output/knockpy_results.txt

# Use Google search to find information about the domain using goog-hack
goog-hack -d 10.0.2.2 -o ./output/goog_hack_results.txt

# Check DNS cache poisoning vulnerabilities using dns-cache-snooping
dns-cache-snooping -d 10.0.2.2 -o ./output/dns_cache_snooping_results.txt

# Check multiple sources for subdomains using Anubis
anubis -d 10.0.2.2 -o ./output/anubis_results.txt

# Perform URL scanning using urlscan.io
urlscan.io -d 10.0.2.2 -o ./output/urlscan_results.txt

# Perform a threat intelligence search using OTX
otx -d 10.0.2.2 -o ./output/otx_results.txt

###########################################################
# Vulnerability Scanning
###########################################################

# Analyze SSL/TLS configurations using sslyze
sslyze --regular 10.0.2.2

# Test for Cross-Site Request Forgery (CSRF) vulnerabilities
csrf_poc -u https://10.0.2.2 -o ./output/csrf_poc_results.txt

# Check for JSON Web Token (JWT) vulnerabilities using jwt_tool
jwt_tool -i https://10.0.2.2 -o ./output/jwt_tool_results.txt

# Perform directory brute-forcing using feroxbuster
feroxbuster -u https://10.0.2.2 -w wordlist.txt -o ./output/feroxbuster_results.txt

# Check which HTTP methods are supported by the server using http-methods
http-methods -u https://10.0.2.2 -o ./output/http_methods_test_results.txt

# Perform directory brute-forcing using dirsearch
dirsearch -u https://10.0.2.2 -w wordlist.txt -o ./output/dirsearch_results.txt

# Perform URL fuzzing to discover hidden endpoints using ffuf
ffuf -u https://10.0.2.2/FUZZ -w payloads/response.txt -o ./output/ffuf_results.txt

# Run Nuclei to perform subdomain discovery
nuclei -t subdomain-discovery -u https://10.0.2.2 -o ./output/nuclei_results.txt

# Test for SQL injection vulnerabilities using sqlmap
sqlmap -u https://10.0.2.2 --batch --crawl=5 -o ./output/sqlmap_results.txt

# Test for Cross-Site Scripting (XSS) vulnerabilities using xsstrike
xsstrike -u https://10.0.2.2 -o ./output/xsstrike_results.txt

# Test for Cross-Origin Resource Sharing (CORS) vulnerabilities using corsy
corsy -u https://10.0.2.2 -o ./output/corsy_results.txt

# Check for Server Side Request Forgery (SSRF) vulnerabilities using ssrfmap
ssrfmap -u https://10.0.2.2 -o ./output/ssrfmap_results.txt

# Test for Clickjacking vulnerabilities using clickjacking
clickjacking -u https://10.0.2.2 -o ./output/clickjacking_results.txt

# Test for Cross-Site Scripting (XSS) vulnerabilities using xsscrapy
xsscrapy -u https://10.0.2.2 -o ./output/xsscrapy_results.txt

# Check for potential payloads on the target domain using payloads
payloads -u https://10.0.2.2 -o ./output/payloads_results.txt

# Identify the technologies used by the domain using webanalyzer
webanalyzer -u https://10.0.2.2 -o ./output/webanalyzer_results.txt

###########################################################
# DNS and Network Scanning
###########################################################

# Query WHOIS for domain registration details
whois 10.0.2.2

# Find other domains hosted on the same IP using reverseip
reverseip -d 10.0.2.2

# Perform DNS enumeration using dnsenum
dnsenum 10.0.2.2

# Discover subdomains using subfinder
subfinder -d 10.0.2.2 -o ./output/subdomains_subfinder.txt

# Find subdomains using assetfinder
assetfinder --subs-only 10.0.2.2 > ./output/subdomains_assetfinder.txt

# Perform DNS queries with a wordlist using dnsx
dnsx -d 10.0.2.2 -wl /usr/share/seclists/Discovery/DNS/dns-common.txt -o ./output/dnsx_results.txt

# Perform DNS enumeration using shuffledns with a wordlist
shuffledns -d 10.0.2.2 -w /usr/share/seclists/Discovery/DNS/dns-common.txt -o ./output/shuffledns_results.txt

# Test for active HTTP/HTTPS services using httprobe
httprobe -p https -p http -s 10.0.2.2 -o ./output/httprobe_results.txt

# Detect web application firewalls using wafw00f
wafw00f 10.0.2.2

# Identify technologies used by the domain using whatweb
whatweb -v 10.0.2.2

# Identify web technologies using wappalyzer
wappalyzer -u https://10.0.2.2

# Scan the HTTP configuration of the domain using nmap
nmap --script http-config -p80,443 10.0.2.2

# Check SSL/TLS configurations using testssl.sh
testssl.sh 10.0.2.2


###########################################################
###########################################################
# DNS and Network Scanning
###########################################################
###########################################################

# WHOIS - Retrieves domain registration information, including registrar, owner, and expiration date.
# nslookup - Queries DNS servers to resolve domain names to IP addresses and vice versa.
# dig - A DNS lookup utility that retrieves DNS records (e.g., A, MX, NS, TXT).
# host - A simple utility for performing DNS lookups, often used to retrieve NS and MX records.
# sublist3r - A fast subdomain enumeration tool that uses search engines and APIs to find subdomains.
# crtsh - Queries Certificate Transparency logs to discover subdomains associated with SSL certificates.
# theHarvester - Gathers information from public sources like search engines, PGP key servers, and more.
# dnsrecon - A DNS enumeration tool that performs various DNS queries (e.g., zone transfers, brute-forcing).
# findomain - A cross-platform tool for subdomain enumeration using certificates and APIs.
# shuffledns - A fast subdomain brute-forcing tool that uses a wordlist and resolvers.
# hunter - A tool for querying subdomains via various APIs and services.
# waybackurls - Fetches historical URLs from the Wayback Machine for a given domain.
# github-search - Searches GitHub repositories for sensitive information related to a domain.
# censys - Searches the Censys database for information about domains, IPs, and certificates.
# shodan - A search engine for internet-connected devices, useful for finding open ports and services.
# securitytrails - Retrieves detailed domain information, including DNS records and historical data.
# robtex - A DNS analysis tool that provides information about domains, IPs, and ASNs.
# certspotter - Monitors Certificate Transparency logs for new certificates issued for a domain.
# wappalyzer - Detects web technologies (e.g., CMS, frameworks) used by a website.
# assetfinder - Finds subdomains by querying various sources like DNS and APIs.
# knockpy - A DNS-based subdomain enumeration tool that uses brute-forcing.
# goog-hack - Uses Google dorks to find information about a domain.
# dns-cache-snooping - Checks DNS cache poisoning vulnerabilities by querying DNS servers.
# anubis - A subdomain enumeration tool that checks multiple sources for subdomains.
# urlscan.io - Provides detailed information about a domain and its components by scanning it.
# otx - Performs threat intelligence searches using AlienVault's Open Threat Exchange.
# sslyze - Analyzes SSL/TLS configurations for vulnerabilities and misconfigurations.
# csrf_poc - Tests for Cross-Site Request Forgery (CSRF) vulnerabilities.
# jwt_tool - Checks for JSON Web Token (JWT) vulnerabilities and manipulates JWTs.
# feroxbuster - A fast directory and file brute-forcing tool.
# http-methods - Checks which HTTP methods (e.g., GET, POST) are supported by a server.
# dirsearch - A web path scanner that brute-forces directories and files.
# ffuf - A fast web fuzzer used to discover hidden endpoints and parameters.
# nuclei - A vulnerability scanner that uses templates to detect issues in web applications.
# sqlmap - Automates the detection and exploitation of SQL injection vulnerabilities.
# xsstrike - A tool for detecting and exploiting Cross-Site Scripting (XSS) vulnerabilities.
# corsy - Tests for Cross-Origin Resource Sharing (CORS) misconfigurations.
# ssrfmap - Detects and exploits Server-Side Request Forgery (SSRF) vulnerabilities.
# clickjacking - Tests for Clickjacking vulnerabilities in web applications.
# xsscrapy - A spider tool that crawls a website and tests for XSS vulnerabilities.
# payloads - A tool for testing potential payloads on a target domain.
# webanalyzer - Identifies the technologies used by a website (e.g., CMS, frameworks).
# reverseip - Finds other domains hosted on the same IP address.
# dnsenum - A DNS enumeration tool that performs zone transfers and brute-forcing.
# subfinder - A subdomain discovery tool that uses passive sources and APIs.
# dnsx - A DNS query tool that uses a wordlist to resolve subdomains.
# httprobe - Tests for active HTTP/HTTPS services on a list of domains or IPs.
# wafw00f - Detects web application firewalls (WAFs) protecting a website.
# whatweb - Identifies technologies used by a website (e.g., CMS, frameworks, server type).
# nmap - A network scanning tool used to discover open ports and services.
# testssl.sh - Checks SSL/TLS configurations for vulnerabilities and misconfigurations.