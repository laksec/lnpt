
# URL DISCOVERY - COMMAND LINE TOOLS (FOR FILES)

## 1. WAYBACKURLS

# Extract URLs from Wayback Machine for domains in file
while read dm; do waybackurls "$dm"; done < dml.txt | sort -u > wayback_urls.txt

# With date filtering
while read dm; do waybackurls --dates "$dm"; done < dml.txt > wayback_dated.txt

# Get only unique URLs per domain
while read dm; do waybackurls "$dm" | sort -u; done < dml.txt > wayback_unique.txt


## 2. GAU (GET ALL URLs)

# Get URLs from multiple sources for domains in file
while read dm; do gau "$dm"; done < dml.txt | sort -u > gau_urls.txt

# With subs option
while read dm; do gau --subs "$dm"; done < dml.txt > gau_subs.txt

# Get from specific sources only
while read dm; do gau --from wayback,commoncrawl,otx "$dm"; done < dml.txt > gau_specific.txt


## 3. KATANA

# Crawl domains from file
katana -list dml.txt -o katana_urls.txt

# Crawl with depth control
katana -list dml.txt -depth 3 -o katana_depth.txt

# Crawl with extensions filter
katana -list dml.txt -extension php,asp,aspx,jsp -o katana_extensions.txt

# Crawl with custom parameters
katana -list dml.txt -jc -kf -o katana_full.txt


## 4. GOSPIDER

# Spider domains from file
gospider -S dml.txt -o gospider_output/

# Spider with depth control
gospider -S dml.txt -d 2 -o gospider_depth/

# Extract only URLs
gospider -S dml.txt -o output.txt -c 10 -d 2 --other-source


## 5. HAKRAWLER

# Crawl domains from file
while read dm; do hakrawler -url "$dm" -depth 2; done < dml.txt > hakrawler_urls.txt

# Crawl with JavaScript analysis
while read dm; do hakrawler -url "$dm" -js -depth 3; done < dml.txt > hakrawler_js.txt


## 6. URLFINDER

# Find URLs for domains in file
while read dm; do urlfinder -d "$dm"; done < dml.txt > urlfinder_results.txt


## 7. GIT HOUND (GITHUB)

# Search GitHub for URLs related to domains
while read dm; do git-hound --dig-files --dig-commits "$dm"; done < dml.txt > github_urls.txt


## 8. PARAM SPIDER

# Find parameters for domains in file
while read dm; do python3 paramspider.py -d "$dm"; done < dml.txt > params.txt

# With output per domain
while read dm; do python3 paramspider.py -d "$dm" -o "params_${domain//./_}.txt"; done < dml.txt


## 9. ARJUN (PARAMETER DISCOVERY)

# Find parameters for URLs in file
arjun -i urls.txt -o arjun_params.txt

# With multiple methods
arjun -i urls.txt -m GET -o arjun_get.txt
arjun -i urls.txt -m POST -o arjun_post.txt


## 10. COMMON CRAWL

# Extract URLs from Common Crawl for domains in file
while read dm; do cc.py "$dm"; done < dml.txt | sort -u > commoncrawl_urls.txt


## 11. OTX (ALIENVAULT)

# Get URLs from OTX for domains in file
while read dm; do otx -s "$dm" -e; done < dml.txt > otx_urls.txt


## 12. URLSCAN.IO

# Get URLs from URLScan.io for domains in file
while read dm; do curl -s "https://urlscan.io/api/v1/search/?q=domain:$dm" | jq -r '.results[].page.url'; done < dml.txt > urlscan_urls.txt


## 13. FEROXBUSTER

# Directory bruteforce for domains in file
while read dm; do feroxbuster -u "https://$dm" -w common.txt -o "ferox_${domain//./_}.txt"; done < dml.txt

# Recursive scan
while read dm; do feroxbuster -u "https://$dm" -w common.txt -r -o "ferox_recursive_${domain//./_}.txt"; done < dml.txt


## 14. FFUF (DIR/FILE DISCOVERY)

# Directory discovery for domains in file
while read dm; do ffuf -u "https://$dm/FUZZ" -w common.txt -o "ffuf_${domain//./_}.json"; done < dml.txt

# File discovery with extensions
while read dm; do ffuf -u "https://$dm/FUZZ" -w common.txt -e .php,.asp,.aspx,.jsp,.html -o "ffuf_files_${domain//./_}.json"; done < dml.txt


## 15. MEG (BULK URL FETCHING)

# Fetch URLs for domains in file
while read dm; do meg -d 1000 -v "$dm" /; done < dml.txt > meg_results.txt


## 16. PARAMS FROM JS FILES

# Extract URLs and params from JavaScript files
while read dm; do curl -s "$dm" | grep -oE 'src="[^"]*\.js"' | cut -d'"' -f2 | xargs -I {} sh -c 'curl -s "$1" | grep -oE "[\?&][a-zA-Z_][a-zA-Z0-9_]*=" | sort -u' _ {}; done < dml.txt > js_params.txt


## 17. URL PROCESSING & FILTERING

# Extract unique domains from URLs
cat urls.txt | grep -oE 'https?://[^/]+' | sort -u > unique_dml.txt

# Extract paths only
cat urls.txt | grep -oE 'https?://[^/]+(/.*)' | cut -d'/' -f4- > paths_only.txt

# Extract parameters
cat urls.txt | grep -oE '\?[^ ]+' | sort -u > all_params.txt

# Filter by file extension
cat urls.txt | grep -E '\.(php|asp|aspx|jsp|html|htm)$' > dynamic_urls.txt
cat urls.txt | grep -E '\.(js|css|png|jpg|jpeg|gif|svg)$' > static_urls.txt


## 18. COMBINATION PIPELINES

# Wayback + GAU combination
while read dm; do waybackurls "$dm"; gau "$dm"; done < dml.txt | sort -u > combined_urls.txt

# Spider + Wayback pipeline
katana -list dml.txt -silent | waybackurls | sort -u > spider_wayback.txt

# URLs → Parameters pipeline
cat urls.txt | arjun -i - -o urls_with_params.txt


## 19. OUTPUT FORMATTING

# JSON output
cat urls.txt | jq -R -s 'split("\n") | map(select(. != ""))' > urls.json

# CSV output
echo "URL,Extension,Has Parameters" > urls_analysis.csv
cat urls.txt | while read url; do 
    ext=$(echo "$url" | grep -oE '\.\w+$' | cut -d. -f2)
    has_params=$(echo "$url" | grep -q '\?' && echo "Yes" || echo "No")
    echo "$url,$ext,$has_params"
done >> urls_analysis.csv


## 20. MONITORING FOR NEW URLs

# Diff-based monitoring
old="old_urls.txt"; new="new_urls.txt"
while read dm; do waybackurls "$dm"; gau "$dm"; done < dml.txt | sort -u > $new
comm -13 <(sort $old) <(sort $new) > new_urls_found.txt
mv $new $old


## 21. BULK URL VALIDATION

# Check which URLs are still active
cat urls.txt | httpx -silent -status-code -o active_urls.txt

# Filter by status code
cat urls.txt | httpx -silent -status-code | grep "200" | cut -d' ' -f1 > working_urls.txt


## 22. SPECIALIZED DISCOVERY

# API endpoint discovery
cat urls.txt | grep -i "api\|rest\|graphql\|soap\|json\|xml" > api_endpoints.txt

# Admin panel discovery
cat urls.txt | grep -i "admin\|login\|dashboard\|panel\|console\|manager" > admin_urls.txt

# Backup file discovery
cat urls.txt | grep -i "backup\|dump\|old\|test\|dev\|staging" > backup_urls.txt


## 23. URL NORMALIZATION

# Remove duplicates with different protocols
cat urls.txt | sed 's/^https:\/\///;s/^http:\/\///' | sort -u > normalized_urls.txt

# Sort by path depth
cat urls.txt | awk -F/ '{print NF-1 " " $0}' | sort -rn | cut -d' ' -f2- > sorted_by_depth.txt


## 24. QUICK COMMANDS

# Count total URLs discovered
while read dm; do waybackurls "$dm"; gau "$dm"; done < dml.txt | wc -l

# Get top 10 most common paths
cat urls.txt | grep -oE 'https?://[^/]+(/[^?]*)' | cut -d'/' -f4- | sort | uniq -c | sort -rn | head -10

# Extract all unique parameters
cat urls.txt | grep -oE '\?.*' | tr '&' '\n' | cut -d'=' -f1 | sort -u > all_unique_params.txt
