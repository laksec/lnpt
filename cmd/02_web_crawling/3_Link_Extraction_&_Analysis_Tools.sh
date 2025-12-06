# LINK EXTRACTION & ANALYSIS - COMMAND LINE TOOLS (FOR FILES)

## 1. HTML LINK EXTRACTION

# Extract all links from URLs in file
while read url; do
    curl -s "$url" | grep -o 'href="[^"]*"' | cut -d'"' -f2 | sed "s#^//#https://#;s#^/#$url/#"
done < urls.txt | sort -u > extracted_links.txt

# Extract links with specific patterns
while read url; do
    curl -s "$url" | grep -o 'href="[^"]*"' | cut -d'"' -f2 | grep -E "\.(php|asp|aspx|jsp|html|htm)$"
done < urls.txt > dynamic_links.txt


## 2. WAYBACKURLS LINK EXTRACTION

# Extract historical links from Wayback Machine
while read domain; do
    waybackurls "$domain" | sort -u
done < domains.txt > wayback_links.txt

# Filter for specific patterns
while read domain; do
    waybackurls "$domain" | grep -E "\.(php|asp|aspx|jsp)" | sort -u
done < domains.txt > wayback_dynamic.txt


## 3. GAU (GET ALL URLs) LINK EXTRACTION

# Extract links from multiple sources
while read domain; do
    gau "$domain" | sort -u
done < domains.txt > gau_links.txt

# Filter by source
while read domain; do
    gau --from wayback,commoncrawl "$domain" | sort -u
done < domains.txt > gau_filtered.txt


## 4. KATANA CRAWLING FOR LINKS

# Crawl and extract links
katana -list urls.txt -o katana_links.txt

# Crawl with depth control
katana -list urls.txt -depth 3 -o katana_depth_links.txt

# Extract only external links
katana -list urls.txt -o katana_all.txt && grep -E "^https?://" katana_all.txt | grep -v "$(head -1 urls.txt | sed 's#https\?://##')" > katana_external.txt


## 5. GOSPIDER LINK EXTRACTION

# Spider for links
gospider -S urls.txt -o gospider_output/ -c 10 -d 2

# Extract only URLs from output
grep -r "\[url\]" gospider_output/ | cut -d' ' -f2 | sort -u > gospider_links.txt


## 6. HAKRAWLER LINK EXTRACTION

# Crawl and extract links
while read url; do
    hakrawler -url "$url" -depth 2
done < urls.txt | sort -u > hakrawler_links.txt


## 7. LINK EXTRACTION WITH CUSTOM SCRIPTS

# Extract all URLs including JS, CSS, images
while read url; do
    curl -s "$url" | grep -oE 'src="[^"]*"|href="[^"]*"|action="[^"]*"' | cut -d'"' -f2 | sed "s#^//#https://#;s#^/#$url/#"
done < urls.txt | sort -u > all_assets.txt


## 8. JS FILE LINK EXTRACTION

# Extract links from JavaScript files
while read url; do
    curl -s "$url" | grep -o 'src="[^"]*\.js"' | cut -d'"' -f2 | sed "s#^//#https://#;s#^/#$url/#"
done < urls.txt | sort -u > js_links.txt


## 9. SOCIAL MEDIA LINK EXTRACTION

# Extract social media links
while read url; do
    curl -s "$url" | grep -oE 'https?://(twitter|facebook|linkedin|instagram|youtube)\.com/[^"]*' | sort -u
done < urls.txt > social_links.txt


## 10. EMAIL EXTRACTION

# Extract email addresses from links
while read url; do
    curl -s "$url" | grep -oE 'mailto:[^"]+' | sed 's/mailto://'
done < urls.txt > extracted_emails.txt


## 11. LINK ANALYSIS

# Analyze link structure
cat extracted_links.txt | awk -F/ '{print "Depth: " (NF-3) " - " $0}' | sort -rn > link_depth_analysis.txt

# Count links per domain
cat extracted_links.txt | grep -oE 'https?://[^/]+' | sort | uniq -c | sort -rn > domains_link_count.txt


## 12. INTERNAL VS EXTERNAL LINK ANALYSIS

# Separate internal and external links
base_domain=$(echo "$(head -1 urls.txt)" | sed 's#https\?://##;s#/.*##')

while read link; do
    if echo "$link" | grep -q "$base_domain"; then
        echo "$link" >> internal_links.txt
    else
        echo "$link" >> external_links.txt
    fi
done < extracted_links.txt


## 13. BROKEN LINK CHECKING

# Check for broken links
cat extracted_links.txt | httpx -silent -status-code -o link_status.txt

# Extract broken links (4xx, 5xx)
cat link_status.txt | grep -E " 404| 500| 403| 401" | cut -d' ' -f1 > broken_links.txt


## 14. LINK VALIDATION

# Validate all extracted links
cat extracted_links.txt | httpx -silent -title -status-code -content-length -o validated_links.txt

# Filter working links
cat validated_links.txt | grep "200\|301\|302" | cut -d' ' -f1 > working_links.txt


## 15. PARAMETERIZED LINK EXTRACTION

# Extract links with parameters
cat extracted_links.txt | grep -E '\?[a-zA-Z_][a-zA-Z0-9_]*=' > links_with_params.txt

# Extract parameter names
cat links_with_params.txt | grep -oE '\?[^&]+' | sed 's/?//' | tr '&' '\n' | cut -d'=' -f1 | sort -u > param_names.txt


## 16. FILE TYPE ANALYSIS

# Analyze link file types
cat extracted_links.txt | grep -oE '\.([a-zA-Z0-9]+)(\?|$)' | sed 's/\.//;s/?.*//' | sort | uniq -c | sort -rn > file_types.txt


## 17. COMBINATION PIPELINES

# Extract → Filter → Validate pipeline
while read url; do
    curl -s "$url" | grep -o 'href="[^"]*"' | cut -d'"' -f2 | sed "s#^//#https://#;s#^/#$url/#"
done < urls.txt | httpx -silent -status-code | grep "200" | cut -d' ' -f1 > pipeline_valid_links.txt


## 18. BATCH PROCESSING

# Batch link extraction
split -l 20 urls.txt url_batch_
for batch in url_batch_*; do
    while read url; do
        curl -s "$url" | grep -o 'href="[^"]*"' | cut -d'"' -f2 | sed "s#^//#https://#;s#^/#$url/#"
    done < "$batch" > "links_batch_$batch.txt"
done
cat links_batch_*.txt | sort -u > all_extracted_links.txt


## 19. LINK NORMALIZATION

# Normalize links (remove fragments, sort params)
cat extracted_links.txt | sed 's/#.*//;s/?.*//' | sort -u > normalized_links.txt

# Remove duplicate links with different protocols
cat extracted_links.txt | sed 's/^https:\/\///;s/^http:\/\///' | sort -u > protocol_normalized.txt


## 20. LINK PATTERN ANALYSIS

# Find common link patterns
cat extracted_links.txt | awk -F/ '{for(i=4;i<=NF;i++) print $i}' | sort | uniq -c | sort -rn | head -20 > common_paths.txt


## 21. MONITORING FOR NEW LINKS

# Diff-based link monitoring
old="old_links.txt"; new="new_links.txt"

# Extract new links
while read url; do
    curl -s "$url" | grep -o 'href="[^"]*"' | cut -d'"' -f2 | sed "s#^//#https://#;s#^/#$url/#"
done < urls.txt | sort -u > $new

# Find new links
if [ -f "$old" ]; then
    comm -13 <(sort "$old") <(sort "$new") > newly_discovered_links.txt
fi

# Update tracking
mv "$new" "$old"


## 22. SOCIAL GRAPH ANALYSIS

# Analyze link relationships
echo "digraph LinkGraph {" > link_graph.dot
while read url; do
    base=$(echo "$url" | sed 's#https\?://##;s#/.*##')
    curl -s "$url" | grep -o 'href="[^"]*"' | cut -d'"' -f2 | while read link; do
        target=$(echo "$link" | sed 's#https\?://##;s#/.*##')
        echo "  \"$base\" -> \"$target\";"
    done
done < urls.txt | sort -u >> link_graph.dot
echo "}" >> link_graph.dot


## 23. OUTPUT FORMATTING

# JSON output
cat extracted_links.txt | jq -R -s 'split("\n") | map(select(. != "")) | map({url: ., type: (. | capture(".*\\.(?<ext>[a-zA-Z0-9]+)") | .ext // "unknown")})' > links.json

# CSV output
echo "URL,Depth,File Type,Has Parameters,Status" > links_analysis.csv
while read link; do
    depth=$(echo "$link" | awk -F/ '{print NF-3}')
    file_type=$(echo "$link" | grep -oE '\.([a-zA-Z0-9]+)(\?|$)' | sed 's/\.//;s/?.*//')
    has_params=$(echo "$link" | grep -q '\?' && echo "Yes" || echo "No")
    status=$(curl -s "$link" -I 2>/dev/null | head -1 | cut -d' ' -f2)
    
    echo "$link,$depth,$file_type,$has_params,$status" >> links_analysis.csv
done < extracted_links.txt


## 24. QUICK COMMANDS

# Count total links
echo "Total links: $(wc -l < extracted_links.txt)"
echo "Internal links: $(wc -l < internal_links.txt 2>/dev/null || echo 0)"
echo "External links: $(wc -l < external_links.txt 2>/dev/null || echo 0)"

# Most common domains
cat extracted_links.txt | grep -oE 'https?://[^/]+' | sort | uniq -c | sort -rn | head -10

# Check for specific patterns
cat extracted_links.txt | grep -i "admin\|login\|dashboard" | head -10


## 25. ADVANCED ANALYSIS

# Analyze link distribution
cat extracted_links.txt | awk -F/ '{print $1 "//" $3}' | sort | uniq -c | sort -rn > domain_distribution.txt

# Find orphan links (not linked from elsewhere)
cat extracted_links.txt | while read link; do
    if ! grep -q "$link" extracted_links.txt; then
        echo "$link"
    fi
done > orphan_links.txt


## 26. LINK QUALITY ANALYSIS

# Check link quality metrics
while read link; do
    echo -n "$link: "
    curl -s "$link" -I 2>/dev/null | head -1 | cut -d' ' -f2-
done < extracted_links.txt | head -20 > link_quality.txt


## 27. INTEGRATION WITH OTHER TOOLS

# Link extraction → Nuclei scanning
cat extracted_links.txt | nuclei -t ~/nuclei-templates/ -o nuclei_link_scan.txt

# Link extraction → Wayback Machine check
while read link; do
    domain=$(echo "$link" | sed 's#https\?://##;s#/.*##')
    waybackurls "$domain" | grep -q "$link" && echo "$link: Found in Wayback"
done < extracted_links.txt > wayback_verified.txt


## 28. PERFORMANCE OPTIMIZED

# Parallel link extraction
cat urls.txt | xargs -P 10 -I {} sh -c 'curl -s "{}" | grep -o "href=\"[^\"]*\"" | cut -d\" -f2 | sed "s#^//#https://#;s#^/#{}/#"' > parallel_links.txt

# Resume interrupted extraction
if [ -f "extraction_in_progress.txt" ]; then
    cat extraction_in_progress.txt >> extracted_links.txt
fi


## 29. SPECIALIZED EXTRACTION

# Extract API endpoints
cat extracted_links.txt | grep -i "api\|rest\|graphql\|/v[0-9]/" > api_endpoints.txt

# Extract file download links
cat extracted_links.txt | grep -E "\.(pdf|doc|docx|xls|xlsx|ppt|pptx|zip|tar|gz)$" > download_links.txt

# Extract image links
cat extracted_links.txt | grep -E "\.(jpg|jpeg|png|gif|svg|webp)$" > image_links.txt
