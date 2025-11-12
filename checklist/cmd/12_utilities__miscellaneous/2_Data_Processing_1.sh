#!/bin/bash
# ================================================
# KALI LINUX DATA PROCESSING CHEAT SHEET (EXTENDED)
# ================================================
# For Ethical Hacking & Bug Bounty Hunting
# Includes 30+ Tools for Maximum Efficiency

### URL PROCESSING (15+ Tools) ###

# 1. gf + grep - Advanced Pattern Matching
gf xss urls.txt | grep -vE '(logout|redirect|static)' | tee xss_filtered.txt
gf sqli urls.txt | grep -i 'admin' | tee admin_sqli.txt
gf ssrf urls.txt | httpx -silent -status-code -title | tee ssrf_live.txt

# 2. URL Deduplication (3 Methods)
urldedupe -s urls.txt -o unique_urls.txt -threads 10
cat urls.txt | sort -u | sponge unique_sorted.txt
httpx -l urls.txt -title -status-code -no-color -silent | anew live_unique.txt

# 3. Parameter Extraction (5 Tools)
cat urls.txt | unfurl keys | sort -u > all_params.txt
cat urls.txt | grep -Po '(?<=\?|&)[^=]+' | sort -u > param_names.txt
waybackurls example.com | qsreplace 'FUZZ' | tee fuzzable_urls.txt
arjun -i urls.txt -o params_arjun.txt
paramspider -d example.com -l high -o params_spider.txt

# 4. URL Manipulation (6 Techniques)
sed 's/^http:/https:/g' urls.txt | sponge https_urls.txt
awk -F'/' '{print $3}' domains.txt | sort -u > root_domains.txt
parallel -j 20 'echo {} | uro | tee -a clean_urls.txt' < urls.txt
curl -s "http://example.com" | html-tool links | grep -Eo 'https?://[^"]+' | anew crawled_urls.txt
cat jsfiles.txt | grep -Eo 'https?://[^"]+' | sort -u > extracted_urls.txt

### JSON PROCESSING (5 Tools) ###

# 1. jq - Swiss Army Knife
cat response.json | jq '.users[] | {name, email, id}' > extracted_users.json
cat api.json | jq 'paths(scalars) as $p | [$p, getpath($p)]' > all_paths.txt

# 2. gron - Make JSON Greppable
gron huge.json | grep 'user.password' | gron --ungron > passwords.json

# 3. jd - Diff Tool
jd before.json after.json > changes.diff

# 4. fx - Interactive Viewer
cat large.json | fx 'this.filter(x => x.active)'

# 5. jless - Pager
curl -s https://api.target.com/v1/users | jless

### ENCODING/DECODING (8 Methods) ###

# 1. Base64
echo -n "admin:pass" | base64 -w0 | curl -H "Authorization: Basic $(cat -)" http://target.com

# 2. Hex/URL Encoding
echo "<script>" | xxd -p | tr -d '\n' | sed 's/../%&/g' > xss_payload.txt
python3 -c "import urllib.parse; print(urllib.parse.quote(input()))" <<< "admin'--"

# 3. Unicode
echo "𝕏𝕊𝕊" | iconv -f utf-8 -t utf-16le | hexdump -C

# 4. JWT
jq -R 'split(".") | [1] | @base64d | fromjson' <<< "$JWT_TOKEN"

# 5. HTML Entities
echo "&lt;script&gt;" | recode html..ascii

### TEXT PROCESSING (10+ Tools) ###

# 1. Advanced Grepping
rg -i 'password.*=' --no-filename *.js | sort -u > js_passwords.txt
awk '/^HTTP\/1.1 200 OK/,/^$/' access.log > successful_requests.txt

# 2. CSV Processing
xsv select 'email,password' data.csv | xsv search -s password '.+' > creds.csv
csvcut -c 1,3-5 large.csv | csvgrep -c "status" -m "active" > filtered.csv

# 3. XML Processing
xmlstarlet sel -t -v "//user/name" users.xml > names.txt
xq '.root.item[] | select(.price > 100)' catalog.xml

# 4. Diff Tools
diff -u old.txt new.txt | colordiff
git diff --no-index file1.txt file2.txt | delta

### NETWORK DATA PROCESSING ###

# 1. PCAP Analysis
tshark -r traffic.pcap -Y 'http.request.method == POST' -T fields -e http.host -e http.request.uri > http_posts.txt
tcpdump -nnr capture.pcap 'port 53' | awk '{print $NF}' | sort -u > dns_queries.txt

# 2. Log Analysis
goaccess access.log --log-format=COMBINED -o report.html
lnav -t "Apache Errors" error.log

### SPECIALIZED TOOLS ###

# 1. JavaScript Analysis
subjs -i domains.txt -o js_urls.txt
secretfinder -i js_files/ -o secrets.json

# 2. Automation with Parallel
cat urls.txt | parallel -j 50 'curl -s {} | htmlq a -href' | tee all_links.txt

# 3. Data Visualization
cat scan_results.json | jq -r '.results[] | [.ip,.port] | @csv' | csvtk plot -H -b "▇"

# 4. PDF Processing
pdftotext document.pdf - | grep -E 'API_KEY|SECRET'

### WORKFLOW EXAMPLES ###

# Full Recon Pipeline
subfinder -d example.com -o subs.txt
cat subs.txt | httpx -silent -threads 100 | tee live_hosts.txt
cat live_hosts.txt | waybackurls | grep -vE '(\.jpg|\.png|\.css)' | uro | tee all_urls.txt
cat all_urls.txt | gf xss | qsreplace '"><script>alert(1)</script>' | httpx -silent -ms '><script>alert(1)</script>'

# API Endpoint Discovery
katana -u https://api.example.com -jc -aff -d 3 -o api_endpoints.txt
cat api_endpoints.txt | grep -E '/v[0-9]/.*(users|admin)' | tee sensitive_endpoints.txt

