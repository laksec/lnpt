
# 1. The Core Engine (Subfinder)
# This is your primary tool. It covers the most ground (including most of what crt.sh and bufferover provide).
subfinder -dL domains.txt -all -recursive -silent -o subfinder_results.txt

# 2. The Legacy Backup (Assetfinder)
# Use this specifically to catch odd bits of data from the "wayback machine" and search engines that Subfinder occasionally misses.
cat domains.txt | xargs -I % sh -c "assetfinder --subs-only %" | sort -u > assetfinder_results.txt

# 3. The Raw Certificate Query (crt.sh)
# Since Subfinder sometimes fails to parse complex crt.sh JSON outputs, running a manual raw query is a good "final check."
cat domains.txt | xargs -I % sh -c "curl -s 'https://crt.sh/?q=%25.%&output=json' | jq -r '.[].name_value' | sed 's/\*\.//g'" | sort -u > crtsh_results.txt

# 4. The Historical Scraper (GAU/Wayback)
# Run this because Subfinder does NOT do this. This finds subdomains by looking at what URLs were crawled 5 or 10 years ago.
cat domains.txt | gau --subs --threads 10 | unfurl -u domains | sort -u > historical_results.txt

# # Define your input
# export TARGET_FILE="domains.txt"

# # Execute all unique sources into one pool
# (
#   subfinder -dL "$TARGET_FILE" -all -silent;
#   cat "$TARGET_FILE" | xargs -I % assetfinder --subs-only %;
#   cat "$TARGET_FILE" | xargs -I % sh -c "curl -s 'https://crt.sh/?q=%25.%&output=json' | jq -r '.[].name_value' | sed 's/\*\.//g'";
#   cat "$TARGET_FILE" | gau --subs --threads 5 | unfurl -u domains
# ) | sort -u | grep -v '*' | tee all_subdomains_discovered.txt
# -------------------

# ============================================
# SUBDOMAIN BRUTEFORCE + RESOLUTION COMMANDS
# ============================================

# ----------------------------------------------------------------------
# COMMAND 1: Bruteforce subdomains using puredns (with wildcard handling)
# ----------------------------------------------------------------------
# Usage: ./subdomain_bruteforce.sh <domains_file> <wordlist> <output_dir>
# Example: ./subdomain_bruteforce.sh targets.txt subdomains.txt ./recon

# Create output directories
mkdir -p ./recon/1_subdomains

# Run puredns bruteforce with wildcard detection
puredns bruteforce subdomains.txt targets.txt \
    -r /etc/resolv.conf \
    --wildcard-batch \
    --wildcard-tests 10 \
    -l 1000 \
    -o ./recon/1_subdomains/bruteforce.txt 2>/dev/null

# ----------------------------------------------------------------------
# COMMAND 2: Combine discovered subdomains with bruteforce results
# ----------------------------------------------------------------------
# Usage: ./combine_subdomains.sh <discovered_file> <bruteforce_file> <output_file>

# Combine and deduplicate all subdomains
cat ./recon/1_subdomains/all_discovered.txt ./recon/1_subdomains/bruteforce.txt 2>/dev/null | \
    sort -u | grep -E '^[a-zA-Z0-9.-]+$' > ./recon/1_subdomains/to_resolve.txt

# ----------------------------------------------------------------------
# COMMAND 3: Resolve all subdomains using puredns
# ----------------------------------------------------------------------
# Usage: ./resolve_subdomains.sh <subdomains_file> <resolvers_file> <output_dir>

# Create output directory for resolved results
mkdir -p ./recon/2_resolved

# Resolve subdomains with wildcard handling
puredns resolve ./recon/1_subdomains/to_resolve.txt \
    -r /etc/resolv.conf \
    --wildcard-batch \
    --write ./recon/2_resolved/resolved.txt 2>/dev/null

# Extract clean subdomain list
cut -d' ' -f1 ./recon/2_resolved/resolved.txt | sort -u > ./recon/1_subdomains/all_subdomains.txt

# Extract unique IPs
awk '{print $2}' ./recon/2_resolved/resolved.txt | sort -u > ./recon/2_resolved/ips.txt

# ----------------------------------------------------------------------
# FALLBACK COMMANDS (when puredns is not available)
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# COMMAND 4 (Fallback): Generate bruteforce candidates with sed
# ----------------------------------------------------------------------
# Usage: ./generate_bruteforce_candidates.sh <domains_file> <wordlist> <output_file>

# Generate domain:wordlist combinations
while read -r domain; do
    sed "s/$/.${domain}/" subdomains.txt
done < targets.txt | sort -u > ./recon/1_subdomains/bruteforce_candidates.txt

# ----------------------------------------------------------------------
# COMMAND 5 (Fallback): Resolve using massdns
# ----------------------------------------------------------------------
# Usage: ./massdns_resolve.sh <candidates_file> <resolvers_file> <output_dir>

# Create output directories
mkdir -p ./recon/2_resolved

# Run massdns resolution
massdns -r /etc/resolv.conf \
    -t A \
    -o S \
    -w ./recon/2_resolved/massdns.txt \
    ./recon/1_subdomains/bruteforce_candidates.txt 2>/dev/null

# ----------------------------------------------------------------------
# COMMAND 6 (Fallback): Parse massdns results
# ----------------------------------------------------------------------
# Usage: ./parse_massdns.sh <massdns_file> <output_dir>

# Extract resolved domains
grep " A " ./recon/2_resolved/massdns.txt | \
    awk '{print $1}' | sed 's/\.$//' | sort -u > ./recon/1_subdomains/bruteforce.txt

# Combine discovered and bruteforced subdomains
cat ./recon/1_subdomains/all_discovered.txt ./recon/1_subdomains/bruteforce.txt | \
    sort -u | grep -E '^[a-zA-Z0-9.-]+$' > ./recon/1_subdomains/all_subdomains.txt

# Extract A records with domains and IPs
grep " A " ./recon/2_resolved/massdns.txt | \
    awk '{print $1" "$3}' | sed 's/\.$//' | sort -u > ./recon/2_resolved/a_records.txt

# Extract unique IPs
awk '{print $2}' ./recon/2_resolved/a_records.txt | sort -u > ./recon/2_resolved/ips.txt

# ----------------------------------------------------------------------
# COMMAND 7: Show summary statistics
# ----------------------------------------------------------------------
# Usage: ./show_resolution_stats.sh <output_dir>

# Show final counts
final_count=$(wc -l < ./recon/1_subdomains/all_subdomains.txt 2>/dev/null || echo 0)
ip_count=$(wc -l < ./recon/2_resolved/ips.txt 2>/dev/null || echo 0)
echo "Phase 2 completed: $final_count resolved subdomains, $ip_count unique IPs"

# ----------------------------------------------------------------------
# ONE-LINER: Complete phase 2 workflow with puredns
# ----------------------------------------------------------------------
# Usage: ./complete_phase2_puredns.sh <targets_file> <wordlist> <output_dir>

mkdir -p ./recon/{1_subdomains,2_resolved} && \
puredns bruteforce subdomains.txt targets.txt -r /etc/resolv.conf --wildcard-batch -o ./recon/1_subdomains/bruteforce.txt 2>/dev/null && \
cat ./recon/1_subdomains/all_discovered.txt ./recon/1_subdomains/bruteforce.txt 2>/dev/null | sort -u > ./recon/1_subdomains/to_resolve.txt && \
puredns resolve ./recon/1_subdomains/to_resolve.txt -r /etc/resolv.conf --wildcard-batch --write ./recon/2_resolved/resolved.txt 2>/dev/null && \
cut -d' ' -f1 ./recon/2_resolved/resolved.txt | sort -u > ./recon/1_subdomains/all_subdomains.txt && \
awk '{print $2}' ./recon/2_resolved/resolved.txt | sort -u > ./recon/2_resolved/ips.txt && \
echo "Completed: $(wc -l < ./recon/1_subdomains/all_subdomains.txt) subdomains, $(wc -l < ./recon/2_resolved/ips.txt) IPs"

# ----------------------------------------------------------------------
# ONE-LINER: Complete phase 2 workflow with massdns (fallback)
# ----------------------------------------------------------------------
# Usage: ./complete_phase2_massdns.sh <targets_file> <wordlist> <output_dir>

mkdir -p ./recon/{1_subdomains,2_resolved} && \
while read -r d; do sed "s/$/.${d}/" subdomains.txt; done < targets.txt | sort -u > ./recon/1_subdomains/bruteforce_candidates.txt && \
massdns -r /etc/resolv.conf -t A -o S -w ./recon/2_resolved/massdns.txt ./recon/1_subdomains/bruteforce_candidates.txt 2>/dev/null && \
grep " A " ./recon/2_resolved/massdns.txt | awk '{print $1}' | sed 's/\.$//' | sort -u > ./recon/1_subdomains/bruteforce.txt && \
cat ./recon/1_subdomains/all_discovered.txt ./recon/1_subdomains/bruteforce.txt 2>/dev/null | sort -u > ./recon/1_subdomains/all_subdomains.txt && \
grep " A " ./recon/2_resolved/massdns.txt | awk '{print $1" "$3}' | sed 's/\.$//' | sort -u > ./recon/2_resolved/a_records.txt && \
awk '{print $2}' ./recon/2_resolved/a_records.txt | sort -u > ./recon/2_resolved/ips.txt && \
echo "Completed: $(wc -l < ./recon/1_subdomains/all_subdomains.txt) subdomains, $(wc -l < ./recon/2_resolved/ips.txt) IPs"


# ============================================
# LIVE HOSTS DETECTION COMMANDS
# ============================================

# ----------------------------------------------------------------------
# COMMAND 1: Basic live host detection with httpx
# ----------------------------------------------------------------------
# Usage: ./httpx_live_hosts.sh <subdomains_file> <output_dir>
# Example: ./httpx_live_hosts.sh ./recon/1_subdomains/all_subdomains.txt ./recon

# Create output directory
mkdir -p ./recon/3_live

# Run httpx to detect live hosts with basic checks
httpx -l ./recon/1_subdomains/all_subdomains.txt \
    -silent \
    -sc \
    -title \
    -td \
    -ip \
    -cname \
    -threads 50 \
    -timeout 5 \
    -ports 80,443,8080,8443 \
    -o ./recon/3_live/httpx.txt 2>/dev/null

# Extract just the live URLs
awk '{print $1}' ./recon/3_live/httpx.txt 2>/dev/null | sort -u > ./recon/3_live/live_urls.txt

# Show count
live_count=$(wc -l < ./recon/3_live/live_urls.txt 2>/dev/null || echo 0)
echo "Live hosts found: $live_count"

# ----------------------------------------------------------------------
# COMMAND 2: Advanced httpx with status code filtering
# ----------------------------------------------------------------------
# Usage: ./httpx_advanced.sh <subdomains_file> <output_dir>

mkdir -p ./recon/3_live

# Run httpx with more comprehensive options
httpx -l ./recon/1_subdomains/all_subdomains.txt \
    -silent \
    -sc \
    -title \
    -td \
    -ip \
    -cname \
    -cdn \
    -probe \
    -follow-redirects \
    -max-redirects 3 \
    -threads 100 \
    -timeout 7 \
    -ports 80,443,8000,8080,8443,8888 \
    -o ./recon/3_live/httpx_full.txt 2>/dev/null

# Extract URLs with status codes for filtering
cat ./recon/3_live/httpx_full.txt | sort -u > ./recon/3_live/live_with_details.txt

# Filter by successful status codes (200, 201, 204, 301, 302, 307, 308)
grep -E "\[(200|201|204|301|302|307|308)\]" ./recon/3_live/live_with_details.txt | \
    awk '{print $1}' > ./recon/3_live/successful_urls.txt

# Extract all live URLs (any response)
awk '{print $1}' ./recon/3_live/live_with_details.txt > ./recon/3_live/live_urls.txt

echo "All live: $(wc -l < ./recon/3_live/live_urls.txt)"
echo "Successful responses: $(wc -l < ./recon/3_live/successful_urls.txt)"

# ----------------------------------------------------------------------
# COMMAND 3: HTTP/HTTPS probing with httprobe (alternative)
# ----------------------------------------------------------------------
# Usage: ./httprobe_live.sh <subdomains_file> <output_dir>

mkdir -p ./recon/3_lite_live

# Generate HTTP/HTTPS URLs
cat ./recon/1_subdomains/all_subdomains.txt | \
    while read sub; do 
        echo "http://$sub"
        echo "https://$sub"
    done > ./recon/3_lite_live/all_urls.txt

# Probe with httprobe (faster, but less info)
cat ./recon/3_lite_live/all_urls.txt | \
    httprobe -c 50 -t 3000 -p ./recon/3_lite_live/live_urls_lite.txt 2>/dev/null

sort -u ./recon/3_lite_live/live_urls_lite.txt -o ./recon/3_lite_live/live_urls_lite.txt

echo "Live hosts (httprobe): $(wc -l < ./recon/3_lite_live/live_urls_lite.txt)"

# ----------------------------------------------------------------------
# COMMAND 4: Extract detailed information from httpx results
# ----------------------------------------------------------------------
# Usage: ./extract_httpx_details.sh <httpx_file> <output_dir>

# Extract URLs with IPs
awk '{print $1" "$NF}' ./recon/3_live/httpx.txt > ./recon/3_live/url_to_ip.txt

# Extract titles for each live host
grep -oP '^https?://[^\s]+|\].*?title\[.*?\]' ./recon/3_live/httpx.txt | \
    paste -d ' ' - - > ./recon/3_live/url_to_title.txt

# Create CSV format for reporting
echo "URL,Status Code,Title,IP,CNAME" > ./recon/3_live/live_hosts_report.csv
awk '{
    url=$1
    status=""
    title=""
    ip=""
    cname=""
    
    for(i=2;i<=NF;i++) {
        if($i ~ /^\[[0-9]{3}\]$/) status=$i
        if($i ~ /title\[.*\]/) {
            match($i, /title\[(.*)\]/, arr)
            title=arr[1]
        }
        if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) ip=$i
        if($i ~ /cname\[.*\]/) {
            match($i, /cname\[(.*)\]/, arr)
            cname=arr[1]
        }
    }
    
    print url "," status "," title "," ip "," cname
}' ./recon/3_live/httpx.txt >> ./recon/3_live/live_hosts_report.csv

# ----------------------------------------------------------------------
# COMMAND 5: Live host detection with multiple tools (comprehensive)
# ----------------------------------------------------------------------
# Usage: ./comprehensive_live_check.sh <subdomains_file> <output_dir>

mkdir -p ./recon/3_comprehensive

# Method 1: TCP port scanning with naabu (if available)
if command -v naabu &> /dev/null; then
    naabu -list ./recon/1_subdomains/all_subdomains.txt \
        -top-ports 100 \
        -silent \
        -o ./recon/3_comprehensive/naabu_ports.txt 2>/dev/null
fi

# Method 2: HTTP probing with httpx
httpx -l ./recon/1_subdomains/all_subdomains.txt \
    -silent \
    -sc \
    -title \
    -ip \
    -ports 80,443,8080,8443 \
    -o ./recon/3_comprehensive/httpx_results.txt 2>/dev/null

# Method 3: Quick check with curl (simple connectivity test)
cat ./recon/1_subdomains/all_subdomains.txt | \
    parallel -j 50 "curl -s -o /dev/null -w '%{http_code}' -m 3 https://{} 2>/dev/null | grep -q '^[2-3]' && echo https://{}" \
    2>/dev/null > ./recon/3_comprehensive/curl_live.txt

# Combine all results
cat ./recon/3_comprehensive/httpx_results.txt | awk '{print $1}' > ./recon/3_comprehensive/all_live.txt
cat ./recon/3_comprehensive/curl_live.txt >> ./recon/3_comprehensive/all_live.txt
sort -u ./recon/3_comprehensive/all_live.txt -o ./recon/3_comprehensive/live_urls_final.txt

echo "Comprehensive live hosts: $(wc -l < ./recon/3_comprehensive/live_urls_final.txt)"

# ----------------------------------------------------------------------
# COMMAND 6: Screen capture of live hosts (if gowitness or aquatone available)
# ----------------------------------------------------------------------
# Usage: ./screenshot_live_hosts.sh <urls_file> <output_dir>

mkdir -p ./recon/3_screenshots

# Using gowitness (if available)
if command -v gowitness &> /dev/null; then
    gowitness file -f ./recon/3_live/live_urls.txt \
        -P ./recon/3_screenshots/ \
        --threads 10 \
        --timeout 10 2>/dev/null
    echo "Screenshots saved to ./recon/3_screenshots/"
fi

# Using aquatone (alternative)
if command -v aquatone &> /dev/null; then
    cat ./recon/3_live/live_urls.txt | aquatone -out ./recon/3_screenshots/aquatone/ -threads 10
fi

# ----------------------------------------------------------------------
# COMMAND 7: One-liner - Complete live host detection workflow
# ----------------------------------------------------------------------
# Usage: ./complete_live_detection.sh <subdomains_file> <output_dir>

mkdir -p ./recon/3_live && \
httpx -l ./recon/1_subdomains/all_subdomains.txt -silent -sc -title -ip -cname -threads 50 -ports 80,443,8080,8443 -o ./recon/3_live/httpx.txt 2>/dev/null && \
awk '{print $1}' ./recon/3_live/httpx.txt | sort -u > ./recon/3_live/live_urls.txt && \
echo "Found $(wc -l < ./recon/3_live/live_urls.txt) live hosts" && \
echo "=== Status Code Distribution ===" && \
grep -o '\[[0-9]\{3\}\]' ./recon/3_live/httpx.txt | sort | uniq -c | sort -rn

# ----------------------------------------------------------------------
# COMMAND 8: Filter and categorize by response codes
# ----------------------------------------------------------------------
# Usage: ./categorize_by_status.sh <httpx_file> <output_dir>

mkdir -p ./recon/3_categorized

# Categorize by status code
grep "\[200\]" ./recon/3_live/httpx.txt | awk '{print $1}' > ./recon/3_categorized/200_ok.txt
grep "\[30[0-9]\]" ./recon/3_live/httpx.txt | awk '{print $1}' > ./recon/3_categorized/30x_redirects.txt
grep "\[40[0-9]\]" ./recon/3_live/httpx.txt | awk '{print $1}' > ./recon/3_categorized/40x_client_errors.txt
grep "\[50[0-9]\]" ./recon/3_live/httpx.txt | awk '{print $1}' > ./recon/3_categorized/50x_server_errors.txt

echo "Categorized live hosts:"
echo "  200 OK: $(wc -l < ./recon/3_categorized/200_ok.txt)"
echo "  Redirects: $(wc -l < ./recon/3_categorized/30x_redirects.txt)"
echo "  Client Errors: $(wc -l < ./recon/3_categorized/40x_client_errors.txt)"
echo "  Server Errors: $(wc -l < ./recon/3_categorized/50x_server_errors.txt)"


Here are the independent commands for URL discovery:

```bash
# ============================================
# URL DISCOVERY COMMANDS
# ============================================

# ----------------------------------------------------------------------
# COMMAND 1: Wayback Machine URL discovery
# ----------------------------------------------------------------------
# Usage: ./waybackurls_discovery.sh <live_urls_file> <output_dir>
# Example: ./waybackurls_discovery.sh ./recon/3_live/live_urls.txt ./recon

# Create output directory
mkdir -p ./recon/4_urls

# Fetch URLs from Wayback Machine
cat ./recon/3_live/live_urls.txt | waybackurls 2>/dev/null | sort -u > ./recon/4_urls/wayback.txt

# Show count
echo "Wayback URLs found: $(wc -l < ./recon/4_urls/wayback.txt)"

# ----------------------------------------------------------------------
# COMMAND 2: Gau URL discovery
# ----------------------------------------------------------------------
# Usage: ./gau_discovery.sh <live_urls_file> <output_dir>

mkdir -p ./recon/4_urls

# Run gau with multiple threads
cat ./recon/3_live/live_urls.txt | gau --threads 20 2>/dev/null | sort -u > ./recon/4_urls/gau.txt

echo "Gau URLs found: $(wc -l < ./recon/4_urls/gau.txt)"

# ----------------------------------------------------------------------
# COMMAND 3: Gau with additional providers
# ----------------------------------------------------------------------
# Usage: ./gau_all_providers.sh <live_urls_file> <output_dir>

mkdir -p ./recon/4_urls

# Run gau with all providers (wayback, otx, commoncrawl)
cat ./recon/3_live/live_urls.txt | gau --providers wayback,otx,commoncrawl --threads 30 2>/dev/null | \
    sort -u > ./recon/4_urls/gau_all.txt

echo "Gau (all providers) URLs: $(wc -l < ./recon/4_urls/gau_all.txt)"

# ----------------------------------------------------------------------
# COMMAND 4: Combined URL discovery (Wayback + Gau)
# ----------------------------------------------------------------------
# Usage: ./combined_url_discovery.sh <live_urls_file> <output_dir>

mkdir -p ./recon/4_urls
> ./recon/4_urls/all_urls.txt

# Fetch from Wayback Machine
if command -v waybackurls &> /dev/null; then
    echo "Fetching Wayback Machine URLs..."
    cat ./recon/3_live/live_urls.txt | waybackurls 2>/dev/null | sort -u > ./recon/4_urls/wayback.txt
    cat ./recon/4_urls/wayback.txt >> ./recon/4_urls/all_urls.txt
    echo "  Wayback: $(wc -l < ./recon/4_urls/wayback.txt)"
fi

# Fetch from gau
if command -v gau &> /dev/null; then
    echo "Fetching gau URLs..."
    cat ./recon/3_live/live_urls.txt | gau --threads 20 2>/dev/null | sort -u > ./recon/4_urls/gau.txt
    cat ./recon/4_urls/gau.txt >> ./recon/4_urls/all_urls.txt
    echo "  Gau: $(wc -l < ./recon/4_urls/gau.txt)"
fi

# Clean and deduplicate all URLs
sort -u ./recon/4_urls/all_urls.txt -o ./recon/4_urls/all_urls.txt

total_urls=$(wc -l < ./recon/4_urls/all_urls.txt)
echo "Total unique URLs: $total_urls"

# ----------------------------------------------------------------------
# COMMAND 5: Hakrawler for crawling live sites
# ----------------------------------------------------------------------
# Usage: ./hakrawler_discovery.sh <live_urls_file> <output_dir>

mkdir -p ./recon/4_urls

# Crawl live sites with hakrawler
cat ./recon/3_live/live_urls.txt | hakrawler -depth 2 -plain -usewayback -subs 2>/dev/null | \
    sort -u > ./recon/4_urls/hakrawler.txt

echo "Hakrawler URLs: $(wc -l < ./recon/4_urls/hakrawler.txt)"

# ----------------------------------------------------------------------
# COMMAND 6: Katana URL discovery (modern alternative)
# ----------------------------------------------------------------------
# Usage: ./katana_discovery.sh <live_urls_file> <output_dir>

mkdir -p ./recon/4_urls

# Run katana crawler
if command -v katana &> /dev/null; then
    cat ./recon/3_live/live_urls.txt | katana -silent -jc -d 2 -c 50 -o ./recon/4_urls/katana.txt 2>/dev/null
    echo "Katana URLs: $(wc -l < ./recon/4_urls/katana.txt)"
fi

# ----------------------------------------------------------------------
# COMMAND 7: Extract sensitive files from URLs
# ----------------------------------------------------------------------
# Usage: ./extract_sensitive_files.sh <urls_file> <output_dir>

mkdir -p ./recon/4_urls

# Extract sensitive file extensions
grep -E "\.js$|\.json$|\.xml$|\.yaml$|\.yml$|\.conf$|\.config$|\.bak$|\.old$|\.sql$|\.db$|\.log$|\.txt$|\.md$" \
    ./recon/4_urls/all_urls.txt 2>/dev/null | sort -u > ./recon/4_urls/sensitive_files.txt

# Extract backup files
grep -E "\.bak$|\.old$|\.backup$|\.sql$|\.dump$|\.tar$|\.gz$|\.zip$|\.rar$" \
    ./recon/4_urls/all_urls.txt 2>/dev/null | sort -u > ./recon/4_urls/backup_files.txt

# Extract configuration files
grep -E "\.conf$|\.config$|\.ini$|\.env$|\.yml$|\.yaml$|\.toml$|\.xml$" \
    ./recon/4_urls/all_urls.txt 2>/dev/null | sort -u > ./recon/4_urls/config_files.txt

echo "Sensitive files: $(wc -l < ./recon/4_urls/sensitive_files.txt)"
echo "Backup files: $(wc -l < ./recon/4_urls/backup_files.txt)"
echo "Config files: $(wc -l < ./recon/4_urls/config_files.txt)"

# ----------------------------------------------------------------------
# COMMAND 8: Extract API endpoints
# ----------------------------------------------------------------------
# Usage: ./extract_api_endpoints.sh <urls_file> <output_dir>

mkdir -p ./recon/4_urls

# Extract API-related endpoints
grep -E "api|v1|v2|v3|v4|graphql|rest|swagger|docs|redoc|openapi|endpoint|service|internal|external|public|private" \
    ./recon/4_urls/all_urls.txt 2>/dev/null | sort -u > ./recon/4_urls/api_endpoints.txt

# Extract GraphQL endpoints
grep -E "graphql|gql|query" ./recon/4_urls/all_urls.txt 2>/dev/null | sort -u > ./recon/4_urls/graphql_endpoints.txt

# Extract Swagger/OpenAPI docs
grep -E "swagger|openapi|docs|redoc" ./recon/4_urls/all_urls.txt 2>/dev/null | sort -u > ./recon/4_urls/api_docs.txt

echo "API endpoints: $(wc -l < ./recon/4_urls/api_endpoints.txt)"
echo "GraphQL endpoints: $(wc -l < ./recon/4_urls/graphql_endpoints.txt)"
echo "API documentation: $(wc -l < ./recon/4_urls/api_docs.txt)"

# ----------------------------------------------------------------------
# COMMAND 9: Extract parameters from URLs
# ----------------------------------------------------------------------
# Usage: ./extract_parameters.sh <urls_file> <output_dir>

mkdir -p ./recon/4_urls

# Extract URLs with parameters
grep "\?" ./recon/4_urls/all_urls.txt > ./recon/4_urls/urls_with_params.txt

# Extract all unique parameters
grep -o "\?[^#]*" ./recon/4_urls/urls_with_params.txt | \
    grep -o "[^?&=][^&=]*" | sort -u > ./recon/4_urls/all_parameters.txt

# Extract URLs with specific interesting parameters
grep -E "(id=|page=|file=|path=|redirect=|url=|return=|next=|prev=|ref=|callback=|next=|continue=)" \
    ./recon/4_urls/urls_with_params.txt > ./recon/4_urls/interesting_params.txt

echo "URLs with parameters: $(wc -l < ./recon/4_urls/urls_with_params.txt)"
echo "Unique parameters: $(wc -l < ./recon/4_urls/all_parameters.txt)"
echo "Interesting parameter URLs: $(wc -l < ./recon/4_urls/interesting_params.txt)"

# ----------------------------------------------------------------------
# COMMAND 10: Comprehensive URL discovery workflow
# ----------------------------------------------------------------------
# Usage: ./complete_url_discovery.sh <live_urls_file> <output_dir>

mkdir -p ./recon/4_urls
> ./recon/4_urls/all_urls_raw.txt

echo "[*] Starting comprehensive URL discovery..."

# Method 1: Wayback Machine
if command -v waybackurls &> /dev/null; then
    echo "[*] Fetching Wayback Machine URLs..."
    cat ./recon/3_live/live_urls.txt | waybackurls 2>/dev/null >> ./recon/4_urls/all_urls_raw.txt
fi

# Method 2: Gau
if command -v gau &> /dev/null; then
    echo "[*] Fetching gau URLs..."
    cat ./recon/3_live/live_urls.txt | gau --threads 30 2>/dev/null >> ./recon/4_urls/all_urls_raw.txt
fi

# Method 3: Hakrawler
if command -v hakrawler &> /dev/null; then
    echo "[*] Crawling with hakrawler..."
    cat ./recon/3_live/live_urls.txt | hakrawler -depth 2 -plain -subs 2>/dev/null >> ./recon/4_urls/all_urls_raw.txt
fi

# Method 4: Katana (if available)
if command -v katana &> /dev/null; then
    echo "[*] Crawling with katana..."
    cat ./recon/3_live/live_urls.txt | katana -silent -jc -d 2 -c 50 2>/dev/null >> ./recon/4_urls/all_urls_raw.txt
fi

# Clean and deduplicate
echo "[*] Processing and categorizing URLs..."
sort -u ./recon/4_urls/all_urls_raw.txt > ./recon/4_urls/all_urls.txt
rm ./recon/4_urls/all_urls_raw.txt

# Extract categories
grep -E "\.js$" ./recon/4_urls/all_urls.txt > ./recon/4_urls/js_files.txt
grep -E "\.json$" ./recon/4_urls/all_urls.txt > ./recon/4_urls/json_files.txt
grep -E "api|v[0-9]/|graphql|rest" ./recon/4_urls/all_urls.txt > ./recon/4_urls/api_endpoints.txt
grep -E "\.(bak|old|backup|sql|db|log|txt|md)$" ./recon/4_urls/all_urls.txt > ./recon/4_urls/sensitive_files.txt
grep "\?" ./recon/4_urls/all_urls.txt > ./recon/4_urls/parameter_urls.txt

# Summary
echo ""
echo "[+] URL Discovery Complete"
echo "========================================"
echo "Total unique URLs: $(wc -l < ./recon/4_urls/all_urls.txt)"
echo "JavaScript files: $(wc -l < ./recon/4_urls/js_files.txt 2>/dev/null || echo 0)"
echo "JSON files: $(wc -l < ./recon/4_urls/json_files.txt 2>/dev/null || echo 0)"
echo "API endpoints: $(wc -l < ./recon/4_urls/api_endpoints.txt 2>/dev/null || echo 0)"
echo "Sensitive files: $(wc -l < ./recon/4_urls/sensitive_files.txt 2>/dev/null || echo 0)"
echo "URLs with parameters: $(wc -l < ./recon/4_urls/parameter_urls.txt 2>/dev/null || echo 0)"
echo "========================================"

# ----------------------------------------------------------------------
# COMMAND 11: One-liner - Quick URL discovery
# ----------------------------------------------------------------------
# Usage: ./quick_url_discovery.sh <live_urls_file>

mkdir -p ./recon/4_urls && \
cat ./recon/3_live/live_urls.txt | waybackurls 2>/dev/null | sort -u > ./recon/4_urls/wayback.txt && \
cat ./recon/3_live/live_urls.txt | gau --threads 20 2>/dev/null | sort -u > ./recon/4_urls/gau.txt && \
cat ./recon/4_urls/wayback.txt ./recon/4_urls/gau.txt | sort -u > ./recon/4_urls/all_urls.txt && \
echo "Found $(wc -l < ./recon/4_urls/all_urls.txt) unique URLs" && \
echo "Sensitive files: $(grep -E '\.(js|json|bak|old|sql|db|conf|config)$' ./recon/4_urls/all_urls.txt | wc -l)"