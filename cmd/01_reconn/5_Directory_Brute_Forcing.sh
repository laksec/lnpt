
# DIRECTORY BRUTEFORCING - COMMAND LINE TOOLS (FOR FILES)

## 1. FFUF (FAST WEB FUZZER)

# Basic directory bruteforce for URLs in file
while read url; do ffuf -u "$url/FUZZ" -w dir_wordlist.txt -o "ffuf_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt

# Recursive directory discovery
while read url; do ffuf -u "$url/FUZZ" -w dir_wordlist.txt -recursion -recursion-depth 3 -o "ffuf_recursive_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt

# File discovery with extensions
while read url; do ffuf -u "$url/FUZZ" -w dir_wordlist.txt -e .php,.asp,.aspx,.jsp,.html,.txt,.json,.xml -o "ffuf_extensions_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt

# Filter by specific status codes
while read url; do ffuf -u "$url/FUZZ" -w dir_wordlist.txt -mc 200,301,302,403,500 -o "ffuf_filtered_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt

# With auto-calibration
while read url; do ffuf -u "$url/FUZZ" -w dir_wordlist.txt -ac -o "ffuf_calibrated_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt

# Rate-limited scanning
while read url; do ffuf -u "$url/FUZZ" -w dir_wordlist.txt -rate 50 -o "ffuf_slow_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt


## 2. DIRSEARCH

# Directory search for URLs in file
while read url; do python3 dirsearch.py -u "$url" -w dir_wordlist.txt -o "dirsearch_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt

# Recursive search with depth
while read url; do python3 dirsearch.py -u "$url" -w dir_wordlist.txt -r -R 3 -o "dirsearch_recursive_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt

# With extensions filter
while read url; do python3 dirsearch.py -u "$url" -w dir_wordlist.txt -e php,asp,aspx,jsp,html,txt,json,xml -o "dirsearch_ext_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt

# With specific status codes
while read url; do python3 dirsearch.py -u "$url" -w dir_wordlist.txt -s 200,301,302,403 -o "dirsearch_status_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt


## 3. GOBUSTER

# Directory busting for URLs in file
while read url; do gobuster dir -u "$url" -w dir_wordlist.txt -o "gobuster_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt

# With extensions
while read url; do gobuster dir -u "$url" -w dir_wordlist.txt -x php,asp,aspx,jsp,html -o "gobuster_ext_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt

# Recursive mode
while read url; do gobuster dir -u "$url" -w dir_wordlist.txt -r -o "gobuster_recursive_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt

# Status code filtering
while read url; do gobuster dir -u "$url" -w dir_wordlist.txt -s 200,204,301,302,307,403 -o "gobuster_status_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt


## 4. FEROXBUSTER

# Fast recursive directory discovery
while read url; do feroxbuster -u "$url" -w dir_wordlist.txt -o "ferox_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt

# With auto-calibration
while read url; do feroxbuster -u "$url" -w dir_wordlist.txt --auto-calibrate -o "ferox_calibrated_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt

# Scan with rate limiting
while read url; do feroxbuster -u "$url" -w dir_wordlist.txt --rate-limit 20 -o "ferox_rate_limited_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt

# Scan with depth limit
while read url; do feroxbuster -u "$url" -w dir_wordlist.txt -d 3 -o "ferox_depth_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt


## 5. DIRB

# Basic dirb scan
while read url; do dirb "$url" dir_wordlist.txt -o "dirb_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt

# With extensions
while read url; do dirb "$url" dir_wordlist.txt -X .php,.asp,.aspx -o "dirb_ext_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt


## 6. WFUZZ

# Directory fuzzing with wfuzz
while read url; do wfuzz -c -z file,dir_wordlist.txt --hc 404 "$url/FUZZ" -o "wfuzz_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt


## 7. SPECIALIZED DIRECTORY DISCOVERY

# Admin panel discovery
while read url; do ffuf -u "$url/FUZZ" -w admin_wordlist.txt -mc 200,301,302,403 -o "admin_panels_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt

# Backup file discovery
while read url; do ffuf -u "$url/FUZZ" -w backup_wordlist.txt -e bak,backup,old,tmp,temp -o "backup_files_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt

# Config file discovery
while read url; do ffuf -u "$url/FUZZ" -w config_wordlist.txt -e php,conf,config,ini,yml,yaml,json -o "config_files_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt

# Log file discovery
while read url; do ffuf -u "$url/FUZZ" -w log_wordlist.txt -e log,txt -o "log_files_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt


## 8. API ENDPOINT DISCOVERY

# API directory discovery
while read url; do ffuf -u "$url/FUZZ" -w api_wordlist.txt -e json,xml -o "api_endpoints_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt


## 9. WORDPRESS SPECIFIC

# WordPress directory discovery
while read url; do wpscan --url "$url" --enumerate ap,at,cb,dbe -o "wpscan_dirs_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < wordpress_sites.txt


## 10. OUTPUT PROCESSING

# Extract discovered directories from ffuf results
for file in ffuf_*.json; do jq -r '.results[].url' "$file"; done | sort -u > all_discovered_dirs.txt

# Extract status codes
for file in ffuf_*.json; do jq -r '.results[] | "\(.url) \(.status)"' "$file"; done > dirs_with_status.txt

# Filter interesting findings
grep -r "200\|301\|302\|403" dirsearch_*.txt | sort -u > interesting_dirs.txt


## 11. COMBINATION PIPELINES

# Gobuster → FFUF pipeline
while read url; do gobuster dir -u "$url" -w small_wordlist.txt -o /dev/null 2>&1 | grep -o "http[^ ]*" | ffuf -u FUZZ -w large_wordlist.txt -o "pipeline_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt

# Dirsearch → Nuclei pipeline
cat dirsearch_*.txt | grep -E "200|301|302" | cut -d' ' -f1 | nuclei -t ~/nuclei-templates/ -o nuclei_dir_results.txt


## 12. BATCH PROCESSING

# Process URLs in batches
split -l 10 urls.txt batch_
for batch in batch_*; do while read url; do ffuf -u "$url/FUZZ" -w dir_wordlist.txt -o "ffuf_$batch.json" -s; done < "$batch"; done

# Parallel processing
cat urls.txt | xargs -P 5 -I {} sh -c 'ffuf -u "{}/FUZZ" -w dir_wordlist.txt -o "ffuf_{}.json"'


## 13. RATE-LIMITED SCANNING

# Slow scanning to avoid detection
while read url; do ffuf -u "$url/FUZZ" -w dir_wordlist.txt -rate 10 -o "ffuf_slow_$(echo $url | md5sum | cut -d' ' -f1).json"; sleep 10; done < urls.txt

# Random delays between requests
while read url; do ffuf -u "$url/FUZZ" -w dir_wordlist.txt -o "ffuf_$(echo $url | md5sum | cut -d' ' -f1).json"; sleep $((RANDOM % 15 + 5)); done < urls.txt


## 14. WORDLIST MANAGEMENT

# Generate custom wordlist from target
while read url; do curl -s "$url" | grep -o 'href="[^"]*"' | cut -d'"' -f2 | grep -v "http" | sed 's/^\///' >> custom_wordlist.txt; done < urls.txt

# Generate wordlist from robots.txt
while read url; do curl -s "$url/robots.txt" 2>/dev/null | grep "Disallow:" | cut -d' ' -f2 | sed 's/^\///' >> robots_wordlist.txt; done < urls.txt

# Merge and deduplicate wordlists
cat dir_wordlist.txt custom_wordlist.txt robots_wordlist.txt | sort -u > merged_wordlist.txt


## 15. ERROR-BASED DISCOVERY

# Look for error messages revealing directories
while read url; do curl -s "$url/nonexistent" | grep -i "not found\|error\|exception\|stack trace" | head -1 | awk -v u="$url" '{print u ": " $0}'; done < urls.txt > error_discovery.txt


## 16. COMMON DIRECTORY CHECKS

# Quick check for common directories
while read url; do for dir in admin login dashboard panel wp-admin phpmyadmin; do curl -s "$url/$dir" -I | head -1 | grep -q "200\|301\|302\|403" && echo "$url/$dir"; done; done < urls.txt > common_dirs.txt

# Check for common files
while read url; do for file in robots.txt sitemap.xml .git/HEAD .env config.php; do curl -s "$url/$file" -I | head -1 | grep -q "200\|301\|302" && echo "$url/$file"; done; done < urls.txt > common_files.txt


## 17. DEPTH-BASED SCANNING

# Scan with increasing depth
for depth in 1 2 3; do while read url; do ffuf -u "$url/FUZZ" -w dir_wordlist.txt -recursion -recursion-depth $depth -o "ffuf_depth${depth}_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt; done


## 18. OUTPUT FORMATTING

# Create CSV report
echo "URL,Discovered Path,Status Code,Content Length" > dir_report.csv
for file in ffuf_*.json; do jq -r '.results[] | "\(.input.FUZZ),\(.url),\(.status),\(.length)"' "$file" >> dir_report.csv; done

# Create summary markdown
echo "# Directory Discovery Report" > report.md
echo "## Summary" >> report.md
echo "- Total URLs scanned: $(wc -l < urls.txt)" >> report.md
echo "- Total directories found: $(cat all_discovered_dirs.txt 2>/dev/null | wc -l)" >> report.md
echo "" >> report.md
echo "## Discovered Directories" >> report.md
cat all_discovered_dirs.txt 2>/dev/null | while read dir; do echo "- $dir"; done >> report.md


## 19. VALIDATION

# Validate discovered directories
cat all_discovered_dirs.txt | httpx -silent -status-code -o validated_dirs.txt

# Filter working directories
cat validated_dirs.txt | grep "200\|301\|302" | cut -d' ' -f1 > working_dirs.txt


## 20. COMPARATIVE ANALYSIS

# Compare results from different tools
comm -12 <(sort ffuf_dirs.txt) <(sort dirsearch_dirs.txt) > common_finds.txt
comm -13 <(sort ffuf_dirs.txt) <(sort dirsearch_dirs.txt) > unique_to_dirsearch.txt
comm -23 <(sort ffuf_dirs.txt) <(sort dirsearch_dirs.txt) > unique_to_ffuf.txt


## 21. RECURSIVE WORDLIST GENERATION

# Generate recursive wordlist from discovered directories
cat all_discovered_dirs.txt | awk -F/ '{for(i=4;i<=NF;i++) print $i}' | sort -u > discovered_words.txt


## 22. MONITORING FOR NEW DIRECTORIES

# Diff-based monitoring
old="old_dirs.txt"; new="new_dirs.txt"
while read url; do ffuf -u "$url/FUZZ" -w dir_wordlist.txt -o /dev/null 2>&1 | grep "http" | cut -d' ' -f7; done < urls.txt | sort -u > $new
comm -13 <(sort $old) <(sort $new) > new_dirs_found.txt
mv $new $old


## 23. PERFORMANCE OPTIMIZATION

# Fast scanning
while read url; do ffuf -u "$url/FUZZ" -w dir_wordlist.txt -t 100 -o "ffuf_fast_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt

# Resume interrupted scan
while read url; do ffuf -u "$url/FUZZ" -w dir_wordlist.txt -o "ffuf_$(echo $url | md5sum | cut -d' ' -f1).json" -resume; done < urls.txt


## 24. QUICK COMMANDS

# Quick directory check
while read url; do echo -n "$url: "; for dir in admin login dashboard; do curl -s "$url/$dir" -I | head -1 | grep -q "200\|301\|302\|403" && echo -n "$dir "; done; echo ""; done < urls.txt

# Count discoveries per tool
echo "FFUF: $(cat ffuf_*.json 2>/dev/null | jq -r '.results[].url' | wc -l)"
echo "Dirsearch: $(cat dirsearch_*.txt 2>/dev/null | grep -c "Status:")"
echo "Gobuster: $(cat gobuster_*.txt 2>/dev/null | grep -c "Status:")"

# Top 10 most common directories
cat all_discovered_dirs.txt | awk -F/ '{print $NF}' | sort | uniq -c | sort -rn | head -10