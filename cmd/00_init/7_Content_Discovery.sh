# CONTENT DISCOVERY - COMMAND LINE TOOLS (FOR FILES)

## 1. FFUF (FAST WEB FUZZER)

# Basic directory discovery for URLs in file
while read url; do ffuf -u "$url/FUZZ" -w wordlist.txt -o "ffuf_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt

# Recursive directory discovery
while read url; do ffuf -u "$url/FUZZ" -w wordlist.txt -recursion -o "ffuf_recursive_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt

# File discovery with extensions
while read url; do ffuf -u "$url/FUZZ" -w wordlist.txt -e .php,.asp,.aspx,.jsp,.html,.txt,.json,.xml -o "ffuf_files_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt

# Filter by status codes
while read url; do ffuf -u "$url/FUZZ" -w wordlist.txt -mc 200,301,302,403 -o "ffuf_filtered_$(echo $url | md5sum | cut -d' ' -f1).json"; done < urls.txt

# VHost discovery for domains in file
while read domain; do ffuf -u http://$domain -H "Host: FUZZ.$domain" -w wordlist.txt -o "vhosts_${domain//./_}.json"; done < domains.txt


## 2. DIRSEARCH

# Directory search for URLs in file
while read url; do python3 dirsearch.py -u "$url" -w wordlist.txt -o "dirsearch_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt

# Recursive search
while read url; do python3 dirsearch.py -u "$url" -w wordlist.txt -r -o "dirsearch_recursive_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt

# With extensions
while read url; do python3 dirsearch.py -u "$url" -w wordlist.txt -e php,asp,aspx,jsp,html -o "dirsearch_ext_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt


## 3. GOBUSTER

# Directory busting for URLs in file
while read url; do gobuster dir -u "$url" -w wordlist.txt -o "gobuster_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt

# DNS subdomain busting for domains in file
while read domain; do gobuster dns -d "$domain" -w wordlist.txt -o "gobuster_dns_${domain//./_}.txt"; done < domains.txt

# VHost discovery
while read domain; do gobuster vhost -u "http://$domain" -w wordlist.txt -o "gobuster_vhost_${domain//./_}.txt"; done < domains.txt


## 4. FEROXBUSTER

# Fast recursive content discovery
while read url; do feroxbuster -u "$url" -w wordlist.txt -o "ferox_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt

# With auto-calibration
while read url; do feroxbuster -u "$url" -w wordlist.txt --auto-calibrate -o "ferox_calibrated_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt

# Scan with rate limiting
while read url; do feroxbuster -u "$url" -w wordlist.txt --rate-limit 10 -o "ferox_rate_limited_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < urls.txt


## 5. KATANA (CRAWLING)

# Crawl and discover content from URLs in file
katana -list urls.txt -o katana_discovered.txt

# Crawl with depth control
katana -list urls.txt -depth 3 -o katana_depth3.txt

# Crawl with extension filtering
katana -list urls.txt -extension php,asp,aspx,jsp -o katana_extensions.txt


## 6. GOSPIDER

# Spider URLs for content discovery
gospider -S urls.txt -o gospider_output/ -c 10 -d 2

# Extract only discovered URLs
gospider -S urls.txt -o output.txt -c 10 -d 2 --other-source


## 7. PARAM SPIDER (PARAMETER DISCOVERY)

# Find parameters for domains in file
while read domain; do python3 paramspider.py -d "$domain" -o "params_${domain//./_}.txt"; done < domains.txt

# Exclude certain extensions
while read domain; do python3 paramspider.py -d "$domain" -e woff,css,js,png,svg -o "params_clean_${domain//./_}.txt"; done < domains.txt


## 8. ARJUN (PARAMETER DISCOVERY)

# Find parameters for URLs in file
arjun -i urls.txt -o arjun_params.txt

# With different HTTP methods
arjun -i urls.txt -m GET -o arjun_get.txt
arjun -i urls.txt -m POST -o arjun_post.txt


## 9. NUCLEI (TEMPLATE-BASED DISCOVERY)

# Run nuclei templates on URLs
nuclei -l urls.txt -o nuclei_results.txt

# Run specific template categories
nuclei -l urls.txt -t exposures/ -o nuclei_exposures.txt
nuclei -l urls.txt -t misconfiguration/ -o nuclei_misconfig.txt
nuclei -l urls.txt -t technologies/ -o nuclei_tech.txt


## 10. CMS-SPECIFIC DISCOVERY

# WordPress discovery
while read url; do wpscan --url "$url" --enumerate vp,vt,u --output "wpscan_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < wordpress_sites.txt

# Joomla discovery
while read url; do python3 joomscan.py -u "$url" -o "joomscan_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < joomla_sites.txt

# Drupal discovery
while read url; do droopescan scan drupal -u "$url" -o "droopescan_$(echo $url | md5sum | cut -d' ' -f1).txt"; done < drupal_sites.txt


## 11. JS FILE ANALYSIS

# Extract URLs from JavaScript files
while read url; do curl -s "$url" | grep -o 'src="[^"]*\.js"' | cut -d'"' -f2; done < urls.txt | sort -u > js_files.txt

# Analyze JS files for secrets/endpoints
while read js_url; do curl -s "$js_url" | grep -E "api|endpoint|token|key|secret|password" | head -5; done < js_files.txt > js_analysis.txt


## 12. BACKUP FILE DISCOVERY

# Common backup file patterns
while read url; do for ext in bak backup old tmp temp; do curl -s "$url.$ext" -I | head -1 | grep -q "200\|301\|302" && echo "$url.$ext"; done; done < urls.txt > backup_files.txt


## 13. API DISCOVERY

# Common API endpoints
while read url; do for endpoint in api/v1 api/v2 graphql rest/v1 swagger openapi; do curl -s "$url/$endpoint" -I | head -1 | grep -q "200\|401\|403" && echo "$url/$endpoint"; done; done < urls.txt > api_endpoints.txt


## 14. CONFIG FILE DISCOVERY

# Common config files
while read url; do for file in .env config.php configuration.php wp-config.php settings.php; do curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file"; done; done < urls.txt > config_files.txt


## 15. LOG FILE DISCOVERY

# Common log files
while read url; do for file in access.log error.log debug.log; do curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file"; done; done < urls.txt > log_files.txt


## 16. GIT/SVN DISCOVERY

# Git repository discovery
while read url; do curl -s "$url/.git/HEAD" -I | head -1 | grep -q "200" && echo "$url/.git/"; done < urls.txt > git_repos.txt

# SVN discovery
while read url; do curl -s "$url/.svn/entries" -I | head -1 | grep -q "200" && echo "$url/.svn/"; done < urls.txt > svn_repos.txt


## 17. OUTPUT PROCESSING

# Extract discovered paths
cat ffuf_*.json | jq -r '.results[].url' | sort -u > discovered_paths.txt

# Filter interesting findings
cat nuclei_results.txt | grep -i "critical\|high\|medium" > nuclei_important.txt

# Create summary report
echo "Content Discovery Report" > report.txt
echo "========================" >> report.txt
echo "Total URLs scanned: $(wc -l < urls.txt)" >> report.txt
echo "Discovered paths: $(wc -l < discovered_paths.txt)" >> report.txt
echo "Interesting findings: $(grep -c "\[CRITICAL\|\[HIGH" nuclei_results.txt 2>/dev/null || echo 0)" >> report.txt


## 18. COMBINATION PIPELINES

# Crawl → Fuzz pipeline
katana -list urls.txt -silent | ffuf -u FUZZ -w wordlist.txt -o katana_ffuf.txt

# Parameter discovery → Test pipeline
arjun -i urls.txt -o params.txt && nuclei -l params.txt -o nuclei_params.txt

# Directory discovery → Screenshot pipeline
ffuf -u "https://FUZZ/" -w wordlist.txt -mc 200 -o ffuf.txt && cat ffuf.txt | jq -r '.results[].url' | aquatone -out screenshots


## 19. RATE-LIMITED SCANNING

# Slow scanning to avoid detection
while read url; do ffuf -u "$url/FUZZ" -w wordlist.txt -rate 10 -o "ffuf_slow_$(echo $url | md5sum | cut -d' ' -f1).json"; sleep 5; done < urls.txt

# Random delays
while read url; do ffuf -u "$url/FUZZ" -w wordlist.txt -o "ffuf_$(echo $url | md5sum | cut -d' ' -f1).json"; sleep $((RANDOM % 10 + 5)); done < urls.txt


## 20. WORDLIST MANAGEMENT

# Generate custom wordlists from target
while read url; do curl -s "$url" | grep -o 'href="[^"]*"' | cut -d'"' -f2 | grep -v "http" >> custom_wordlist.txt; done < urls.txt

# Merge and deduplicate wordlists
cat wordlist1.txt wordlist2.txt custom_wordlist.txt | sort -u > merged_wordlist.txt


## 21. ERROR-BASED DISCOVERY

# Look for error messages revealing paths
while read url; do curl -s "$url/nonexistent" | grep -i "not found\|error\|exception\|stack trace" | head -1 | awk -v u="$url" '{print u ": " $0}'; done < urls.txt > error_paths.txt


## 22. ROBOTS.TXT ANALYSIS

# Extract paths from robots.txt
while read url; do curl -s "$url/robots.txt" | grep "Disallow:" | cut -d' ' -f2; done < urls.txt | sort -u > robots_paths.txt


## 23. SITEMAP ANALYSIS

# Extract paths from sitemap.xml
while read url; do curl -s "$url/sitemap.xml" | grep -o '<loc>[^<]*</loc>' | sed 's/<loc>//;s/<\/loc>//'; done < urls.txt | sort -u > sitemap_paths.txt


## 24. QUICK COMMANDS

# Quick directory check
while read url; do for dir in admin login dashboard; do curl -s "$url/$dir" -I | head -1 | grep -q "200" && echo "$url/$dir"; done; done < urls.txt

# Check for common files
while read url; do for file in robots.txt sitemap.xml .git/HEAD; do curl -s "$url/$file" -I | head -1 | grep -q "200\|301\|302" && echo "$url/$file"; done; done < urls.txt
