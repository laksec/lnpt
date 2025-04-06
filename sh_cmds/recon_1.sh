#!/bin/bash

# -----------------------------------
# DNS Recon Commands
# -----------------------------------

# General DNS lookup for all record types with timeout
nslookup -type=ANY -timeout=10 $domain >> $output 2>&1
# Purpose: Retrieves all DNS records (A, MX, NS, etc.) with a 10-second timeout for reliability.

# Fetch IPv4 addresses with additional details
dig +nocmd $domain A +answer +stats >> $output 2>&1
# Purpose: Queries IPv4 addresses with query stats for performance insight.

# Fetch IPv6 addresses with TTL
dig +nocmd $domain AAAA +answer +ttl >> $output 2>&1
# Purpose: Queries IPv6 addresses, showing TTL for each record.

# Fetch MX records with priority and TTL
dig +nocmd $domain MX +answer +ttl >> $output 2>&1
# Purpose: Lists mail servers with priority and TTL for detailed analysis.

# Fetch NS records with authoritative servers
dig +nocmd $domain NS +answer +authority >> $output 2>&1
# Purpose: Identifies name servers and authoritative responses.

# Fetch TXT records with multiline output
dig +nocmd $domain TXT +answer +multiline >> $output 2>&1
# Purpose: Retrieves TXT records (e.g., SPF, DKIM) in readable multiline format.

# Fetch SOA record with all fields
dig +nocmd $domain SOA +answer +all >> $output 2>&1
# Purpose: Provides full SOA details (serial, refresh, retry, etc.).

# Trace DNS resolution with full path and timing
dig +trace +stats $domain ANY >> $output 2>&1
# Purpose: Traces DNS resolution from root to target with timing stats.

# Attempt DNS zone transfer with detailed output
dnsrecon -d $domain -t axfr -v >> $output 2>&1
# Purpose: Tries zone transfer with verbose output for debugging.

# Verbose host lookup with all record types
host -a -v $domain >> $output 2>&1
# Purpose: Provides detailed DNS info with verbose parsing.

# Standard DNS enumeration with brute-forcing
dnsrecon -d $domain -t std -w my_wordlist.txt >> $output 2>&1
# Purpose: Enumerates DNS records and attempts subdomain brute-forcing.

# Advanced subdomain discovery with Fierce
fierce --domain $domain --subdomains my_wordlist.txt --traverse 10 >> $output 2>&1
# Purpose: Brute-forces subdomains with a custom wordlist and traversal depth.

# Reverse DNS lookup for all resolved IPs
dig +short $domain A | grep -v '\.$' | xargs -I {} host -v {} >> $output 2>&1
# Purpose: Performs reverse lookup for all IPv4 addresses of the domain.

# Fetch detailed PTR records for IPs
dig +short $domain A | grep -v '\.$' | xargs -I {} dig -x {} +answer +ttl >> $output 2>&1
# Purpose: Queries PTR records with TTL for all resolved IPs.

# Check DNSSEC DNSKEY with full details
dig +dnssec $domain DNSKEY +answer +multiline >> $output 2>&1
# Purpose: Retrieves DNSSEC keys with signature validation details.

# Check DNSSEC DS records with trust chain
dig +dnssec $domain DS +answer +cdflag >> $output 2>&1
# Purpose: Fetches DS records with DNSSEC validation checking.

# Check DNSSEC status with full validation
dig +sigchase $domain ANY >> $output 2>&1
# Purpose: Performs full DNSSEC signature chase to verify integrity.

# -----------------------------------
# GitHub Dorks Recon Commands
# -----------------------------------

# Search GitHub code with domain context
curl -s -A "Mozilla/5.0" "https://github.com/search?q=$domain+org:*+in:file&type=code" | grep -oE "href=\"/[^\"]+\"" >> $output 2>&1
# Purpose: Finds code mentioning the domain with organization context.

# Search for sensitive keywords with pagination
for keyword in password api_key secret_key token credential config private_key; do curl -s -A "Mozilla/5.0" "https://github.com/search?q=$domain+$keyword+in:file&type=code&p=1" | grep -oE "href=\"/[^\"]+\"" >> $output 2>&1; done
# Purpose: Searches for sensitive terms across first page of results.

# Search for specific file extensions with language filter
for ext in .env .yml .yaml .conf .config .json .py .sh .php .java; do curl -s -A "Mozilla/5.0" "https://github.com/search?q=$domain+extension:$ext+language:*&type=code" | grep -oE "href=\"/[^\"]+\"" >> $output 2>&1; done
# Purpose: Finds files by extension with language context.

# Search for exposed credentials with refined terms
curl -s -A "Mozilla/5.0" "https://github.com/search?q=$domain+intext:(username | password | \"api key\" | \"secret key\" | token | \"access key\")&type=code" | grep -oE "href=\"/[^\"]+\"" >> $output 2>&1
# Purpose: Targets precise credential-related terms in code.

# Search repositories with detailed filtering
curl -s -A "Mozilla/5.0" "https://github.com/search?q=$domain+forks:>0+stars:>0&type=repositories" | grep -oE "href=\"/[^\"]+\"" | grep -v "/search" >> $output 2>&1
# Purpose: Finds active repositories mentioning the domain.

# Search commits with author info
curl -s -A "Mozilla/5.0" "https://github.com/search?q=$domain+author:*&type=commits" | grep -oE "href=\"/[^\"]+/commit/[^\"]+\"" >> $output 2>&1
# Purpose: Identifies commits with author context.

# Search issues with status filter
curl -s -A "Mozilla/5.0" "https://github.com/search?q=$domain+is:open+is:issue&type=issues" | grep -oE "href=\"/[^\"]+/issues/[0-9]+\"" >> $output 2>&1
# Purpose: Finds open issues mentioning the domain.

# Search wikis with content filter
curl -s -A "Mozilla/5.0" "https://github.com/search?q=$domain+in:file&type=wikis" | grep -oE "href=\"/[^\"]+/wiki/[^\"]+\"" >> $output 2>&1
# Purpose: Identifies wiki pages with domain references.

# -----------------------------------
# Google Dorks Recon Commands
# -----------------------------------

# Basic site search with exclusions
curl -s -A "Mozilla/5.0" "https://www.google.com/search?q=site:$domain+-inurl:(login | signup | account)" | grep -oE "https?://$domain[^ ]*" >> $output 2>&1
# Purpose: Indexes domain pages, excluding common auth pages.

# Search for sensitive file types with size filter
for ext in pdf doc docx xls xlsx csv conf config bak sql dump; do curl -s -A "Mozilla/5.0" "https://www.google.com/search?q=site:$domain+filetype:$ext+-inurl:(signup | login)" | grep -oE "https?://$domain[^ ]*" >> $output 2>&1; done
# Purpose: Finds sensitive files, excluding irrelevant pages.

# Search for exposed directories with specific terms
curl -s -A "Mozilla/5.0" "https://www.google.com/search?q=site:$domain+intitle:\"index of\"+intext:(backup | config | database)" | grep -oE "https?://$domain[^ ]*" >> $output 2>&1
# Purpose: Targets directories exposing sensitive data.

# Search for admin panels with refined terms
curl -s -A "Mozilla/5.0" "https://www.google.com/search?q=site:$domain+inurl:(admin | dashboard | wp-admin | control | panel)" | grep -oE "https?://$domain[^ ]*" >> $output 2>&1
# Purpose: Identifies admin or control panel URLs.

# Search for login pages with specific keywords
curl -s -A "Mozilla/5.0" "https://www.google.com/search?q=site:$domain+inurl:(login | signin | auth | authenticate)+intext:(username | password)" | grep -oE "https?://$domain[^ ]*" >> $output 2>&1
# Purpose: Finds login pages with credential prompts.

# Search for error messages with leak potential
curl -s -A "Mozilla/5.0" "https://www.google.com/search?q=site:$domain+intext:(\"error\" | \"exception\" | \"failed\" | \"stack trace\" | \"mysql\")" | grep -oE "https?://$domain[^ ]*" >> $output 2>&1
# Purpose: Identifies pages leaking technical details.

# Search for subdomains with exclusions
curl -s -A "Mozilla/5.0" "https://www.google.com/search?q=site:*.$domain+-site:(www.$domain | login.$domain)" | grep -oE "https?://[^ ]*\.$domain[^ ]*" >> $output 2>&1
# Purpose: Discovers subdomains, excluding common ones.

# Search for cached pages with timestamp
curl -s -A "Mozilla/5.0" "https://www.google.com/search?q=cache:$domain" | grep -oE "https?://$domain[^ ]*|\"[A-Za-z]{3} [0-9]{1,2}, [0-9]{4}\"" >> $output 2>&1
# Purpose: Retrieves cached pages with capture dates.

# -----------------------------------
# HTTP/SSL Recon Commands
# -----------------------------------

# Fetch full HTTP headers with verbose output
curl -ILk -A "Mozilla/5.0" --connect-timeout 10 -v $domain >> $output 2>&1
# Purpose: Retrieves headers with verbose connection details.

# Test TRACE method with custom headers
curl -ILk -X TRACE -H "Test: grok" $domain >> $output 2>&1
# Purpose: Checks TRACE method support with a test header.

# Fetch server response with timeout
wget -q --spider --server-response --timeout=10 $domain 2>> $output
# Purpose: Gets server response headers with a timeout.

# Fetch headers with httpie and custom user-agent
http --headers --timeout=10 GET "https://$domain" User-Agent:"Mozilla/5.0" >> $output 2>&1
# Purpose: Alternative header fetch with timeout (requires httpie).

# Fingerprint tech stack with plugins
whatweb -v --plugins-advanced $domain >> $output 2>&1
# Purpose: Identifies technologies with advanced plugin detection.

# Detailed tech stack with Wappalyzer
wappalyzer "https://$domain" --pretty >> $output 2>&1
# Purpose: Provides detailed tech stack in readable format (requires Wappalyzer CLI).

# Extract full SSL certificate chain
echo | openssl s_client -connect $domain:443 -servername $domain -showcerts -tlsextdebug 2>/dev/null | openssl x509 -noout -text -dates -issuer -subject >> $output 2>&1
# Purpose: Shows certificate details including validity and issuer.

# Analyze SSL handshake with protocol details
echo | openssl s_client -connect $domain:443 -servername $domain -state -tls1_3 -tls1_2 -tls1_1 -tls1 2>/dev/null >> $output 2>&1
# Purpose: Displays SSL handshake with supported protocol versions.

# Enumerate SSL ciphers with detailed output
nmap --script ssl-enum-ciphers -p 443 -Pn -v $domain >> $output 2>&1
# Purpose: Lists ciphers with verbose Nmap output.

# Comprehensive SSL analysis with sslscan
sslscan --no-failed --xml=my_sslscan.xml $domain >> $output 2>&1
# Purpose: Detailed SSL scan with XML output for further analysis.

# Deep SSL vulnerability scan
testssl.sh --full --color 0 --quiet $domain:443 >> $output 2>&1
# Purpose: Comprehensive SSL/TLS vuln check without color output.

# Extract and validate security headers
curl -sI $domain | grep -iE "(Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options|X-XSS-Protection|Content-Security-Policy|Referrer-Policy|Permissions-Policy|Cache-Control)" >> $output 2>&1
# Purpose: Captures a broader set of security headers.

# Detailed security header analysis with Nmap
nmap --script http-security-headers -p 80,443 -Pn $domain >> $output 2>&1
# Purpose: Analyzes security headers on multiple ports.

# Extract cookies with detailed attributes
curl -sL --cookie-jar my_cookies.txt $domain | grep -v "^#" | awk '{print $7 "\t" $1 "\t" $6}' >> $output 2>&1
# Purpose: Lists cookies with name, domain, and path.

# Fetch and parse robots.txt with comments
curl -s "https://$domain/robots.txt" | grep -v "^#" >> $output 2>&1
# Purpose: Retrieves robots.txt, excluding comments.

# Fetch and extract sitemap URLs
curl -s "https://$domain/sitemap.xml" | grep -oE "https?://[^<]+" | sort -u >> $output 2>&1
# Purpose: Extracts unique URLs from sitemap.xml.

# -----------------------------------
# Port Recon Commands
# -----------------------------------

# Quick scan of common ports with reason
nmap -F --open --reason -Pn $(dig +short $domain A | grep -v '\.$' | head -n 1) >> $output 2>&1
# Purpose: Scans common ports with reason for state.

# Full port scan with packet tracing
nmap -p- --open -T4 --packet-trace $(dig +short $domain A | grep -v '\.$' | head -n 1) >> $output 2>&1
# Purpose: Scans all ports with packet-level tracing.

# Service version detection with verbosity
nmap -sV -p- --open -T4 -v $(dig +short $domain A | grep -v '\.$' | head -n 1) >> $output 2>&1
# Purpose: Identifies service versions with verbose output.

# Default scripts with service detection
nmap -sC -sV -p- --open -T4 --script-trace $(dig +short $domain A | grep -v '\.$' | head -n 1) >> $output 2>&1
# Purpose: Runs default scripts with script tracing.

# Aggressive scan with detailed output
nmap -A -p- --open -T4 -v --stats-every=10s $(dig +short $domain A | grep -v '\.$' | head -n 1) >> $output 2>&1
# Purpose: Detailed scan with periodic stats.

# Vulnerability scan with specific scripts
nmap --script "vuln and safe" -p- --open -T4 $(dig +short $domain A | grep -v '\.$' | head -n 1) >> $output 2>&1
# Purpose: Checks for safe vulnerabilities only.

# Deep scan of common ports with banners
nmap -p 21,22,23,25,80,443,445,3389 -sV -sC --open -T4 --script=banner $(dig +short $domain A | grep -v '\.$' | head -n 1) >> $output 2>&1
# Purpose: Grabs banners from common ports.

# UDP scan with version detection
nmap -sU -sV --top-ports 200 --open -T4 $(dig +short $domain A | grep -v '\.$' | head -n 1) >> $output 2>&1
# Purpose: Scans top 200 UDP ports with version info.

# OS detection with detailed fingerprint
nmap -O --osscan-guess -v $(dig +short $domain A | grep -v '\.$' | head -n 1) >> $output 2>&1
# Purpose: Identifies OS with aggressive guessing.

# -----------------------------------
# Subdirectory Recon Commands
# -----------------------------------

# Directory brute-forcing with Gobuster and status codes
gobuster dir -u "https://$domain" -w my_wordlist.txt -t 50 -q -s "200,301,302,403" -o my_gobuster.txt 2>/dev/null && cat my_gobuster.txt >> $output 2>&1
# Purpose: Brute-forces directories with specific status codes.

# Deep directory/file enumeration with dirsearch
dirsearch -u "https://$domain" -e php,html,js,txt,xml -w my_wordlist.txt -r --timeout=10 --plain-text-report=my_dirsearch.txt 2>/dev/null && cat my_dirsearch.txt >> $output 2>&1
# Purpose: Recursively enumerates files and directories.

# Fast fuzzing with FFUF and size filter
ffuf -u "https://$domain/FUZZ" -w my_wordlist.txt -mc 200,301,302 -fs 0 -t 100 -o my_ffuf.json 2>/dev/null && jq -r '.results[] | .url' my_ffuf.json >> $output 2>&1
# Purpose: Fuzzes directories with size filtering.

# Extract historical paths from Wayback Machine
curl -s "http://web.archive.org/cdx/search/cdx?url=$domain/*&output=json&filter=statuscode:200" | jq -r '.[] | .[2]' | grep -oE "^/[a-zA-Z0-9._/-]+" | sort -u >> $output 2>&1
# Purpose: Gets successful (200) paths from archives.

# Parse robots.txt with full context
curl -s "https://$domain/robots.txt" | grep -E "(Allow|Disallow|User-agent)" >> $output 2>&1
# Purpose: Extracts rules and agents from robots.txt.

# Extract sitemap paths with depth
curl -s "https://$domain/sitemap.xml" | grep -oE "/[a-zA-Z0-9._/-]+" | sort -u >> $output 2>&1
# Purpose: Lists unique paths with subdirectories from sitemap.

# Check for sensitive backup files with headers
for ext in .bak .zip .tar.gz .sql .conf .config .old .db; do curl -s -I "https://$domain/${ext}" | grep -E "(200|403)" >> $output 2>&1; done
# Purpose: Tests for accessible or forbidden backup files.

# -----------------------------------
# Subdomain Recon Commands
# -----------------------------------

# Subdomain enumeration with Sublist3r and verbosity
sublist3r -d $domain -v -o my_sublist3r.txt 2>/dev/null && cat my_sublist3r.txt >> $output 2>&1
# Purpose: Discovers subdomains with verbose output.

# Active subdomain discovery with Amass and sources
amass enum -d $domain -active -brute -w my_wordlist.txt -o my_amass.txt 2>/dev/null && cat my_amass.txt >> $output 2>&1
# Purpose: Actively enumerates subdomains with brute-forcing.

# Fast subdomain enumeration with Subfinder and recursion
subfinder -d $domain -r -v -o my_subfinder.txt 2>/dev/null && cat my_subfinder.txt >> $output 2>&1
# Purpose: Recursively finds subdomains with verbose logging.

# DNS brute-forcing with dnsrecon and custom nameservers
dnsrecon -d $domain -t brt -f my_wordlist.txt -n 8.8.8.8 >> $output 2>&1
# Purpose: Brute-forces subdomains using Google DNS.

# Subdomains from Certificate Transparency with exclusions
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value | select(. != "*.$domain")' | sort -u >> $output 2>&1
# Purpose: Excludes wildcard entries from cert logs.

# Subdomain enumeration with Fierce and delay
fierce --domain $domain --delay 2 --subdomains my_wordlist.txt >> $output 2>&1
# Purpose: Enumerates subdomains with a delay for rate limiting.

# Comprehensive DNS enumeration with dnsenum
dnsenum --enum -f my_wordlist.txt --resolver 1.1.1.1 $domain >> $output 2>&1
# Purpose: Enumerates DNS with custom resolver and brute-forcing.

# Resolve all subdomains from a file
cat my_subdomains.txt | xargs -I {} dig +short {} A +answer >> $output 2>&1
# Purpose: Resolves IPs for a list of subdomains.

# -----------------------------------
# Wayback Recon Commands
# -----------------------------------

# Fetch all archived URLs with filtering
curl -s "http://web.archive.org/cdx/search/cdx?url=$domain/*&output=json&fl=original&filter=statuscode:[23]..&limit=1000" | jq -r '.[] | .[0]' | sort -u >> $output 2>&1
# Purpose: Lists successful archived URLs (200-399) up to 1000.

# Fetch timestamps with URL context
curl -s "http://web.archive.org/cdx/search/cdx?url=$domain/*&output=json&fl=timestamp,original&filter=mimetype:text/html" | jq -r '.[] | [.[]] | join(" ")' | sort -u >> $output 2>&1
# Purpose: Gets timestamps for HTML pages only.

# Fetch MIME types with URL mapping
curl -s "http://web.archive.org/cdx/search/cdx?url=$domain/*&output=json&fl=mimetype,original&filter=mimetype:.*(json|xml|pdf)" | jq -r '.[] | [.[]] | join(" ")' | sort -u >> $output 2>&1
# Purpose: Targets specific MIME types (JSON, XML, PDF).

# Fetch status codes with historical context
curl -s "http://web.archive.org/cdx/search/cdx?url=$domain/*&output=json&fl=statuscode,original,timestamp" | jq -r '.[] | [.[]] | join(" ")' | sort -u >> $output 2>&1
# Purpose: Maps status codes to URLs and dates.

# Extract unique paths with depth
curl -s "http://web.archive.org/cdx/search/cdx?url=$domain/*&output=json&fl=original" | jq -r '.[] | .[0]' | grep -oE "^https?://$domain(/[a-zA-Z0-9._/-]+)+" | sort -u >> $output 2>&1
# Purpose: Lists deep unique paths from archives.

# Extract parameterized URLs with keys
curl -s "http://web.archive.org/cdx/search/cdx?url=$domain/*&output=json&fl=original" | jq -r '.[] | .[0]' | grep -E "\?.*[a-zA-Z0-9]+=" | sort -u >> $output 2>&1
# Purpose: Identifies URLs with query parameters.

# Extract diverse file extensions
curl -s "http://web.archive.org/cdx/search/cdx?url=$domain/*&output=json&fl=original" | jq -r '.[] | .[0]' | grep -oE "\.[a-zA-Z0-9]{1,10}(\?|$)" | sort -u >> $output 2>&1
# Purpose: Captures a wider range of file extensions.

# Extract subdomains with filtering
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=json&fl=original&filter=statuscode:200" | jq -r '.[] | .[0]' | grep -oE "[a-zA-Z0-9.-]+\.$domain" | sort -u >> $output 2>&1
# Purpose: Lists successful subdomains from archives.

# -----------------------------------
# Ownership Recon Commands
# -----------------------------------

# Detailed WHOIS lookup with raw output
whois -v $domain >> $output 2>&1
# Purpose: Retrieves verbose domain registration details.

# Alternative WHOIS with specific server
whois -h whois.pwhois.org -v $domain >> $output 2>&1
# Purpose: Uses an alternative WHOIS server for deeper data.

# RDAP lookup with full JSON parsing
curl -s "https://rdap.arin.net/registry/domain/$domain" | jq -r '. | {name: .name, handle: .handle, status: .status[], events: .events[] | {action: .eventAction, date: .eventDate}}' >> $output 2>&1
# Purpose: Extracts structured domain info via RDAP.

# Filter registrant details with context
whois $domain | grep -iE "(Registrant|Admin|Tech|Email|Organization|Name Server|Phone|Address)" >> $output 2>&1
# Purpose: Captures broader registrant and contact info.

# Reverse WHOIS with dnsrecon and verbosity
dnsrecon -d $domain -t rwhois -v >> $output 2>&1
# Purpose: Finds related domains via reverse WHOIS lookup.

# Historical data with Wayback Machine
curl -s "http://web.archive.org/cdx/search/cdx?url=$domain&output=json&fl=timestamp,original,statuscode&from=1990" | jq -r '.[] | [.[]] | join(" ")' | sort -u >> $output 2>&1
# Purpose: Retrieves full history since 1990.

# WHOIS for all resolved IPs
dig +short $domain A | grep -v '\.$' | xargs -I {} whois {} >> $output 2>&1
# Purpose: Gets ownership details for all IPv4 addresses.

# IP geolocation with external API
dig +short $domain A | grep -v '\.$' | xargs -I {} curl -s "https://ipinfo.io/{}?token=my_token" | jq -r '. | {ip: .ip, city: .city, region: .region, country: .country}' >> $output 2>&1
# Purpose: Adds geolocation data for IPs (requires ipinfo.io token).