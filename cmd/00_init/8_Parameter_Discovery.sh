# PARAMETER DISCOVERY - COMMAND LINE TOOLS (FOR FILES)

## 1. ARJUN (PARAMETER DISCOVERY)

# Discover parameters for URLs in file
arjun -i urls.txt -o arjun_params.txt

# Discover GET parameters
arjun -i urls.txt -m GET -o arjun_get.txt

# Discover POST parameters
arjun -i urls.txt -m POST -o arjun_post.txt

# JSON output format
arjun -i urls.txt -oJ arjun_params.json

# With rate limiting
arjun -i urls.txt -d 100 -o arjun_slow.txt

# Include default parameter values
arjun -i urls.txt --include-default -o arjun_with_defaults.txt


## 2. PARAM SPIDER

# Find parameters for domains in file
while read dm; do python3 paramspider.py -d "$dm" -o "params_${dm//./_}.txt"; done < dml.txt

# Exclude certain extensions
while read dm; do python3 paramspider.py -d "$dm" -e woff,css,js,png,svg,jpg,jpeg,gif -o "params_clean_${dm//./_}.txt"; done < dml.txt

# Include only specific extensions
while read dm; do python3 paramspider.py -d "$dm" --include php,asp,aspx,jsp,html -o "params_ext_${dm//./_}.txt"; done < dml.txt

# Output as JSON
while read dm; do python3 paramspider.py -d "$dm" -o json -o "params_${dm//./_}.json"; done < dml.txt


## 3. GAU + GREP FOR PARAMETERS

# Extract URLs with parameters from Gau results
while read dm; do gau "$dm"; done < dml.txt | grep -E '\?[a-zA-Z_][a-zA-Z0-9_]*=' > gau_params.txt

# Extract only parameter names
while read dm; do gau "$dm"; done < dml.txt | grep -oE '\?[^&]+' | sed 's/?//' | tr '&' '\n' | cut -d'=' -f1 | sort -u > gau_param_names.txt


## 4. WAYBACKURLS + PARAM EXTRACTION

# Extract parameters from Wayback URLs
while read dm; do waybackurls "$dm"; done < dml.txt | grep -E '\?[a-zA-Z_][a-zA-Z0-9_]*=' > wayback_params.txt

# Get unique parameter patterns
while read dm; do waybackurls "$dm"; done < dml.txt | grep -oE '\?[^ ]+' | sort -u > wayback_param_patterns.txt


## 5. KATANA FOR PARAM DISCOVERY

# Crawl and extract URLs with parameters
katana -list urls.txt -o katana_output.txt && grep -E '\?[a-zA-Z_][a-zA-Z0-9_]*=' katana_output.txt > katana_params.txt

# Crawl with depth for parameter discovery
katana -list urls.txt -depth 3 -o katana_depth.txt && grep '\?' katana_depth.txt > katana_depth_params.txt


## 6. PARAMMINER (BURP EXTENSION CLI)

# Discover hidden parameters
while read url; do python3 paramminer.py -u "$url" -o "paramminer_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt

# Use custom wordlist
while read url; do python3 paramminer.py -u "$url" -w param_wordlist.txt -o "paramminer_custom_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt


## 7. GOSPIDER PARAM EXTRACTION

# Spider and extract parameters
gospider -S urls.txt -o gospider_output/ -c 10 -d 2
grep -r '\?' gospider_output/ | grep -E '\?[a-zA-Z_][a-zA-Z0-9_]*=' > gospider_params.txt


## 8. JS FILE PARAMETER EXTRACTION

# Extract parameters from JavaScript files
while read url; do curl -s "$url" | grep -o 'src="[^"]*\.js"' | cut -d'"' -f2 | while read js; do curl -s "$js" 2>/dev/null | grep -oE '[\?&][a-zA-Z_][a-zA-Z0-9_]*=' | sed 's/[?&]//;s/=$//'; done; done < urls.txt | sort -u > js_params.txt


## 9. XN LINKFINDER (JS ANALYSIS)

# Analyze JavaScript for endpoints/parameters
while read url; do curl -s "$url" | grep -o 'src="[^"]*\.js"' | cut -d'"' -f2 | while read js; do python3 linkfinder.py -i "$js" -o cli; done; done < urls.txt > linkfinder_results.txt


## 10. GETPARAMS (TOOL SPECIFIC)

# Extract parameters from URLs
getparams -i urls.txt -o getparams_output.txt

# Extract only unique parameters
getparams -i urls.txt -u -o getparams_unique.txt


## 11. CUSTOM PARAMETER EXTRACTION

# Simple grep for parameters
cat urls.txt | grep -oE '\?[^ ]+' > simple_params.txt

# Extract parameter names only
cat urls.txt | grep -oE '\?[^&]+' | sed 's/?//' | tr '&' '\n' | cut -d'=' -f1 | sort -u > param_names.txt

# Extract parameter values
cat urls.txt | grep -oE '\?[^&]+' | sed 's/?//' | tr '&' '\n' | cut -d'=' -f2 | sort -u > param_values.txt


## 12. PARAMETER PATTERN ANALYSIS

# Find common parameter patterns
cat urls.txt | grep -oE '\?[^&]+' | sed 's/?//' | tr '&' '\n' | awk -F= '{print $1}' | sort | uniq -c | sort -rn > common_params.txt

# Find numeric parameters
cat urls.txt | grep -oE '\?[^&]+' | sed 's/?//' | tr '&' '\n' | grep -E '=[0-9]+$' > numeric_params.txt

# Find UUID parameters
cat urls.txt | grep -oE '\?[^&]+' | sed 's/?//' | tr '&' '\n' | grep -E '=[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}' > uuid_params.txt


## 13. SENSITIVE PARAMETER DETECTION

# Look for sensitive parameter names
cat urls.txt | grep -oiE '\?[^&]*(token|key|secret|password|auth|pass|cred|hash|salt)[^&=]*=' > sensitive_params.txt

# Look for API keys in parameters
cat urls.txt | grep -oiE '\?[^&]*=[a-zA-Z0-9]{32,}' > potential_api_keys.txt


## 14. PARAMETER FUZZING

# Fuzz discovered parameters with nuclei
cat urls_with_params.txt | nuclei -t ~/nuclei-templates/ -tags parameter -o nuclei_parameter_fuzz.txt

# Fuzz with common payloads
while read url; do python3 param_fuzzer.py -u "$url" -w fuzz_wordlist.txt -o "fuzz_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls_with_params.txt


## 15. PARAMETER ENUMERATION

# Enumerate parameter values
while read url; do for param in id user uid; do for i in {1..100}; do curl -s "$url?$param=$i" -I | head -1 | grep -q "200\|301\|302" && echo "$url?$param=$i"; done; done; done < base_urls.txt > enumerated_params.txt


## 16. URL RECONSTRUCTION WITH PARAMETERS

# Reconstruct URLs with all discovered parameters
while read base_url; do params=$(grep "^$base_url" discovered_params.txt | grep -oE '\?[^ ]+' | head -1); echo "$base_url$params"; done < base_urls.txt > reconstructed_urls.txt


## 17. OUTPUT PROCESSING

# Convert to CSV format
echo "URL,Parameter Count,Parameters" > params_report.csv
while read url; do param_count=$(echo "$url" | grep -o '&' | wc -l); ((param_count++)); params=$(echo "$url" | grep -oE '\?[^ ]+' | sed 's/?//'); echo "$url,$param_count,$params"; done < urls_with_params.txt >> params_report.csv

# JSON output
cat urls_with_params.txt | jq -R '{url: ., parameters: (. | capture("\\?(?<params>.*)") | .params // "" | split("&") | map(split("=") | {key: .[0], value: .[1]})}' | jq -s '.' > params.json


## 18. COMBINATION PIPELINES

# Gau → Parameter extraction
while read dm; do gau "$dm"; done < dml.txt | grep -E '\?[a-zA-Z_][a-zA-Z0-9_]*=' > gau_extracted_params.txt

# Wayback → Arjun pipeline
while read dm; do waybackurls "$dm"; done < dml.txt | arjun -i - -o wayback_arjun_params.txt

# Katana → Parameter filter pipeline
katana -list urls.txt -silent | grep -E '\?[a-zA-Z_][a-zA-Z0-9_]*=' > katana_filtered_params.txt


## 19. PARAMETER VALIDATION

# Check if parameters are still active
cat urls_with_params.txt | httpx -silent -status-code -o active_params.txt

# Filter by response code
cat urls_with_params.txt | httpx -silent -status-code | grep "200" | cut -d' ' -f1 > working_params.txt


## 20. BATCH PROCESSING

# Process URLs in batches
split -l 100 urls.txt batch_
for batch in batch_*; do arjun -i "$batch" -o "arjun_$batch.txt"; done
cat arjun_batch_*.txt > all_params.txt

# Parallel processing
cat urls.txt | xargs -P 10 -I {} sh -c 'arjun -u "{}" -o "arjun_{}.txt"'


## 21. SPECIALIZED PARAMETER DISCOVERY

# Find GraphQL endpoints and parameters
cat urls.txt | grep -i graphql | while read url; do curl -s "$url" -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}'; done > graphql_endpoints.txt

# Find SOAP/WSDL parameters
cat urls.txt | grep -i '\.wsdl$\|\.asmx$\|/wsdl' > soap_endpoints.txt


## 22. PARAMETER WORDLIST GENERATION

# Generate wordlist from discovered parameters
cat urls_with_params.txt | grep -oE '\?[^&]+' | sed 's/?//' | tr '&' '\n' | cut -d'=' -f1 | sort -u > param_wordlist.txt

# Generate value patterns
cat urls_with_params.txt | grep -oE '\?[^&]+' | sed 's/?//' | tr '&' '\n' | cut -d'=' -f2 | sort -u > value_patterns.txt


## 23. MONITORING FOR NEW PARAMETERS

# Diff-based monitoring
old="old_params.txt"; new="new_params.txt"
while read dm; do paramspider -d "$dm"; done < dml.txt | sort -u > $new
comm -13 <(sort $old) <(sort $new) > new_params_found.txt
mv $new $old


## 24. QUICK COMMANDS

# Count total parameters discovered
cat urls_with_params.txt | wc -l

# Count unique parameter names
cat urls_with_params.txt | grep -oE '\?[^&]+' | sed 's/?//' | tr '&' '\n' | cut -d'=' -f1 | sort -u | wc -l

# Most common parameters
cat urls_with_params.txt | grep -oE '\?[^&]+' | sed 's/?//' | tr '&' '\n' | cut -d'=' -f1 | sort | uniq -c | sort -rn | head -20

# Check for parameters in real-time
while read url; do echo -n "$url: "; curl -s "$url?test=1" -I | head -1 | cut -d' ' -f2; done < base_urls.txt
