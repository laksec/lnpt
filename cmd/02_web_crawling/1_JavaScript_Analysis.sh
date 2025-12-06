# JAVASCRIPT ANALYSIS - COMMAND LINE TOOLS (FOR FILES)

## 1. JS FILE EXTRACTION

# Extract JS file URLs from URLs in file
while read url; do curl -s "$url" | grep -o 'src="[^"]*\.js"' | cut -d'"' -f2 | sed 's#^//#https://#'; done < urls.txt | sort -u > js_files.txt

# Extract JS from inline scripts
while read url; do curl -s "$url" | grep -o '<script[^>]*>[^<]*</script>' | sed 's/<script[^>]*>//;s/<\/script>//' | head -1 | awk -v u="$url" '{if(length($0)>0) print u ": " $0}'; done < urls.txt > inline_scripts.txt

# Extract JS file URLs from sitemap
while read url; do curl -s "$url/sitemap.xml" 2>/dev/null | grep -o 'loc>[^<]*\.js</loc>' | sed 's/loc>//;s/<\/loc>//'; done < urls.txt > sitemap_js.txt


## 2. LINKFINDER (JS ENDPOINT EXTRACTION)

# Extract endpoints from JS files in file
while read js_url; do python3 linkfinder.py -i "$js_url" -o cli; done < js_files.txt > linkfinder_results.txt

# Extract endpoints with regex patterns
while read js_url; do python3 linkfinder.py -i "$js_url" -o cli -r "api|endpoint|graphql|rest|/v[0-9]/"; done < js_files.txt > api_endpoints.txt

# Output to file per JS
while read js_url; do filename=$(echo "$js_url" | sed 's/[^a-zA-Z0-9]/_/g'); python3 linkfinder.py -i "$js_url" -o "linkfinder_${filename}.txt"; done < js_files.txt


## 3. JSBEAUTIFY FOR READABILITY

# Beautify JS files for analysis
while read js_url; do curl -s "$js_url" | js-beautify > "beautified_$(echo $js_url | sed 's/[^a-zA-Z0-9]/_/g').js"; done < js_files.txt


## 4. SECRETS/KEY EXTRACTION

# Extract potential secrets from JS files
while read js_url; do curl -s "$js_url" | grep -E "(api[_-]?key|secret|token|password|auth|credential|access[_-]?key|secret[_-]?key)" -i; done < js_files.txt > potential_secrets.txt

# Extract API keys patterns
while read js_url; do curl -s "$js_url" | grep -E "[a-zA-Z0-9]{32,}" | grep -v "//\|/\*"; done < js_files.txt > potential_api_keys.txt

# Extract AWS keys
while read js_url; do curl -s "$js_url" | grep -E "(AKIA|ASIA)[A-Z0-9]{16}"; done < js_files.txt > aws_keys.txt

# Extract Google API keys
while read js_url; do curl -s "$js_url" | grep -E "AIza[0-9A-Za-z\\-_]{35}"; done < js_files.txt > google_keys.txt


## 5. GETJS (TOOL SPECIFIC)

# Get JS files from URLs
while read url; do getjs -u "$url" -o "getjs_$(echo $url | sed 's/[^a-zA-Z0-9]/_/g').txt"; done < urls.txt


## 6. SUBDOMAIN EXTRACTION FROM JS

# Extract subdomains from JS files
while read js_url; do curl -s "$js_url" | grep -oE "[a-zA-Z0-9._-]+\.(com|net|org|io|edu|gov)" | sort -u; done < js_files.txt > js_subdomains.txt


## 7. ENDPOINT EXTRACTION

# Extract API endpoints
while read js_url; do curl -s "$js_url" | grep -oE '"(GET|POST|PUT|DELETE|PATCH)\s+[^"]+"' | sed 's/"//g'; done < js_files.txt > http_methods.txt

# Extract URL patterns
while read js_url; do curl -s "$js_url" | grep -oE 'https?://[^"'\'']+' | sort -u; done < js_files.txt > js_urls.txt

# Extract GraphQL endpoints
while read js_url; do curl -s "$js_url" | grep -i "graphql" | grep -oE 'https?://[^"'\'' ]+'; done < js_files.txt > graphql_endpoints.txt


## 8. PARAMETER EXTRACTION

# Extract parameters from JS files
while read js_url; do curl -s "$js_url" | grep -oE '[\?&][a-zA-Z_][a-zA-Z0-9_]*=' | sed 's/[?&]//g;s/=$//' | sort -u; done < js_files.txt > js_params.txt


## 9. JSA (JAVASCRIPT ANALYZER)

# Analyze JS for interesting patterns
while read js_url; do jsa -u "$js_url" -o "jsa_$(echo $js_url | sed 's/[^a-zA-Z0-9]/_/g').txt"; done < js_files.txt


## 10. NUCLEI JS TEMPLATES

# Scan JS files with nuclei templates
nuclei -l js_files.txt -t ~/nuclei-templates/javascript/ -o nuclei_js_scan.txt


## 11. DEPENDENCY ANALYSIS

# Extract npm packages
while read js_url; do curl -s "$js_url" | grep -oE 'require\(["'\''][^"'\'']+["'\'']\)' | sed "s/require([\"']//;s/[\"'])//"; done < js_files.txt > npm_packages.txt

# Extract import statements
while read js_url; do curl -s "$js_url" | grep -oE 'import\s+[^;]+' | sed 's/import\s*//'; done < js_files.txt > imports.txt


## 12. REGEX PATTERN SEARCH

# Find interesting regex patterns
while read js_url; do curl -s "$js_url" | grep -oE '/[^/]+/' | grep -v '^//'; done < js_files.txt > regex_patterns.txt

# Find email regex patterns
while read js_url; do curl -s "$js_url" | grep -i "email.*regex\|regex.*email"; done < js_files.txt > email_regex.txt


## 13. JAVASCRIPT FUZZING

# Fuzz JS endpoints
while read endpoint; do ffuf -u "$endpoint/FUZZ" -w js_wordlist.txt -o "js_fuzz_$(echo $endpoint | sed 's/[^a-zA-Z0-9]/_/g').json"; done < js_endpoints.txt


## 14. SOURCE MAP ANALYSIS

# Find and analyze source maps
while read js_url; do curl -s "${js_url%.js}.map" -I | head -1 | grep -q "200" && echo "$js_url -> ${js_url%.js}.map"; done < js_files.txt > source_maps.txt

# Download source maps
while read js_url; do map_url="${js_url%.js}.map"; curl -s "$map_url" -o "sourcemap_$(echo $js_url | sed 's/[^a-zA-Z0-9]/_/g').json"; done < js_files.txt


## 15. WEBPACK ANALYSIS

# Analyze webpack bundles
while read js_url; do curl -s "$js_url" | grep -q "webpackJsonp\|webpackChunk" && echo "$js_url: Webpack detected"; done < js_files.txt > webpack_detected.txt


## 16. MINIFIED JS DETECTION

# Detect minified JavaScript
while read js_url; do curl -s "$js_url" | head -1 | grep -q "^[^{}]*{[^{}]*{[^{}]*{" && echo "$js_url: Possibly minified"; done < js_files.txt > minified_detected.txt


## 17. OUTPUT PROCESSING

# Create CSV report
echo "JS URL,Secrets Found,Endpoints Found,Subdomains Found,Size" > js_analysis.csv
while read js_url; do
    secrets=$(curl -s "$js_url" | grep -c -E "(api[_-]?key|secret|token)" -i)
    endpoints=$(curl -s "$js_url" | grep -c -E 'https?://[^"'\'']+')
    subdomains=$(curl -s "$js_url" | grep -oE "[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}" | sort -u | wc -l)
    size=$(curl -s "$js_url" | wc -c)
    echo "$js_url,$secrets,$endpoints,$subdomains,$size" >> js_analysis.csv
done < js_files.txt


## 18. COMBINATION PIPELINES

# Extract JS → Linkfinder → Nuclei pipeline
while read url; do curl -s "$url" | grep -o 'src="[^"]*\.js"' | cut -d'"' -f2 | while read js; do python3 linkfinder.py -i "$js" -o cli; done; done < urls.txt | nuclei -t ~/nuclei-templates/ -o pipeline_results.txt

# JS files → Secrets extraction → Validation
while read js_url; do curl -s "$js_url" | grep -E "[a-zA-Z0-9]{32,}" | while read line; do echo "$js_url: $line"; done; done < js_files.txt > all_potential_secrets.txt


## 19. BATCH PROCESSING

# Process JS files in batches
split -l 50 js_files.txt js_batch_
for batch in js_batch_*; do while read js_url; do python3 linkfinder.py -i "$js_url" -o "linkfinder_$batch.txt"; done < "$batch"; done

# Parallel processing
cat js_files.txt | xargs -P 10 -I {} sh -c 'curl -s "{}" | grep -E "(api[_-]?key|secret|token)" -i | head -5 | awk -v u="{}" "{print u \": \" \$0}"'


## 20. COMPARATIVE ANALYSIS

# Compare findings from different tools
comm -12 <(sort linkfinder_results.txt) <(sort getjs_results.txt) > common_finds.txt
comm -13 <(sort linkfinder_results.txt) <(sort getjs_results.txt) > unique_to_getjs.txt
comm -23 <(sort linkfinder_results.txt) <(sort getjs_results.txt) > unique_to_linkfinder.txt


## 21. MONITORING FOR CHANGES

# Diff-based monitoring
old="old_js_analysis.txt"; new="new_js_analysis.txt"
while read js_url; do curl -s "$js_url" | grep -E "(api[_-]?key|secret|token)" -i | head -10; done < js_files.txt | sort -u > $new
comm -13 <(sort $old) <(sort $new) > new_secrets_found.txt
mv $new $old


## 22. QUICK CHECKS

# Check for common JS frameworks
while read js_url; do echo -n "$js_url: "; curl -s "$js_url" | grep -oE "react|vue|angular|jquery|backbone|ember" -i | head -1; done < js_files.txt > js_frameworks.txt

# Check file size
while read js_url; do size=$(curl -s "$js_url" | wc -c); echo "$js_url: $size bytes"; done < js_files.txt > js_sizes.txt


## 23. DEEPER ANALYSIS

# Analyze function names
while read js_url; do curl -s "$js_url" | grep -oE 'function\s+[a-zA-Z_][a-zA-Z0-9_]*' | sed 's/function\s*//' | sort -u; done < js_files.txt > function_names.txt

# Analyze variable names
while read js_url; do curl -s "$js_url" | grep -oE 'var\s+[a-zA-Z_][a-zA-Z0-9_]*' | sed 's/var\s*//' | sort -u; done < js_files.txt > variable_names.txt


## 24. INTEGRATION WITH OTHER TOOLS

# JS analysis → Subdomain discovery
cat js_subdomains.txt | dnsx -silent -a -resp -o js_subdomains_resolved.txt

# JS endpoints → HTTP probing
cat js_endpoints.txt | httpx -silent -status-code -title -o js_endpoints_active.txt

# JS secrets → Nuclei validation
cat potential_secrets.txt | grep -oE "[a-zA-Z0-9]{32,}" | while read secret; do echo "Potential secret found: $secret"; done | nuclei -t ~/nuclei-templates/secrets/ -o secrets_validation.txt
