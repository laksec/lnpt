# TECHNOLOGY FINGERPRINTING - COMMAND LINE TOOLS

## 1. HTTPX TECH DETECTION

# Basic technology detection
httpx -l dml.txt -tech-detect -o tech.txt

# Tech detection with full details
httpx -l dml.txt -tech-detect -title -status-code -web-server -o detailed_tech.txt

# Filter by specific technology
httpx -l dml.txt -tech-detect | grep "WordPress\|Joomla\|Drupal" > cms_sites.txt

# JSON output with tech detection
httpx -l dml.txt -tech-detect -json -o tech.json


## 2. WAPPLER (SPECIALIZED WAF/WAF DETECTION)

# Basic WAF detection
wafw00f -l dml.txt -o waf_detected.txt

# Aggressive WAF detection
wafw00f -l dml.txt -a -o waf_aggressive.txt

# WAF detection with details
wafw00f -l dml.txt -v -o waf_verbose.txt

# JSON output
wafw00f -l dml.txt -o json -o waf.json


## 3. WHATWEB (WEB TECHNOLOGY DETECTION)

# Basic whatweb scan
whatweb -i dml.txt -v -o whatweb_scan.txt

# Aggressive detection
whatweb -i dml.txt -a 3 -v -o whatweb_aggressive.txt

# Quiet mode (only results)
whatweb -i dml.txt -q -o whatweb_quiet.txt

# JSON output
whatweb -i dml.txt --log-json=whatweb.json


## 4. NMAP HTTP TECH DETECTION

# Nmap HTTP scripts
nmap -iL dml.txt -p 80,443 --script http-headers,http-title,http-server-header -oN http_info.txt

# CMS detection scripts
nmap -iL dml.txt -p 80,443 --script http-wordpress-enum,http-joomla-brute,http-drupal-enum -oN cms_scan.txt

# WAF detection with nmap
nmap -iL dml.txt -p 80,443 --script http-waf-detect,http-waf-fingerprint -oN waf_nmap.txt

# Full HTTP enumeration
nmap -iL dml.txt -p 80,443 --script http-enum,http-methods,http-robots.txt -oN http_full.txt


## 5. WEBTECH (GO-BASED TECH DETECTION)

# Basic webtech scan
webtech -u dml.txt -o webtech_results.txt

# Crawl and detect
webtech -u dml.txt -crawl -o webtech_crawl.txt

# JSON output
webtech -u dml.txt -o json -o webtech.json


## 6. CURL-BASED FINGERPRINTING

# Detect WordPress
while read url; do curl -s "$url/wp-login.php" | grep -q "WordPress" && echo "$url: WordPress"; done < dml.txt

# Detect Joomla
while read url; do curl -s "$url/administrator/" | grep -q "Joomla" && echo "$url: Joomla"; done < dml.txt

# Detect Drupal
while read url; do curl -s "$url/CHANGELOG.txt" | grep -q "Drupal" && echo "$url: Drupal"; done < dml.txt

# Check for React/Angular/Vue
while read url; do curl -s "$url" | grep -i "react\|angular\|vue" | head -1 | awk -v u="$url" '{print u ": " $0}'; done < dml.txt


## 7. HEADER ANALYSIS

# Extract and analyze headers
while read url; do echo "=== $url ==="; curl -I -s "$url" | grep -i "server\|x-powered-by\|x-generator"; done < dml.txt > headers.txt

# Framework detection via headers
while read url; do curl -I -s "$url" | grep -i "x-aspnet\|x-aspnetmvc\|x-drupal\|x-generator" | awk -v u="$url" '{print u ": " $0}'; done < dml.txt > framework_headers.txt

# WAF detection via headers
while read url; do curl -I -s "$url" | grep -i "cloudflare\|akamai\|sucuri\|imperva\|barracuda" | awk -v u="$url" '{print u ": " $0}'; done < dml.txt > waf_headers.txt


## 8. SSL/TLS FINGERPRINTING

# SSL certificate analysis
tlsx -l dml.txt -san -cn -issuer -expired -o ssl_certs.txt

# JARM fingerprinting
tlsx -l dml.txt -jarm -o jarm_fingerprints.txt

# TLS version detection
tlsx -l dml.txt -tls-version -o tls_versions.txt

# Cipher suite detection
nmap -iL dml.txt -p 443 --script ssl-enum-ciphers -oN ssl_ciphers.txt


## 9. CONTENT ANALYSIS

# Page title extraction
httpx -l dml.txt -title -silent | awk '{print $1 " -> " $2}' > titles.txt

# Meta generator detection
while read url; do curl -s "$url" | grep -i "<meta.*generator" | awk -v u="$url" '{print u ": " $0}'; done < dml.txt > meta_generators.txt

# JavaScript framework detection
while read url; do curl -s "$url" | grep -i "react\|vue\|angular\|jquery\|bootstrap" | head -1 | awk -v u="$url" '{print u ": " $0}'; done < dml.txt > js_frameworks.txt


## 10. ROBOTS.TXT ANALYSIS

# Check robots.txt for tech hints
while read url; do curl -s "$url/robots.txt" | grep -i "wp-admin\|joomla\|drupal\|wordpress" && echo "$url: CMS hints in robots.txt"; done < dml.txt > robots_hints.txt


## 11. COOKIE ANALYSIS

# Analyze cookies for technology hints
while read url; do curl -I -s "$url" | grep -i "set-cookie" | grep -i "wordpress\|joomla\|drupal\|php" | awk -v u="$url" '{print u ": " $0}'; done < dml.txt > cookie_tech.txt


## 12. PIPELINE COMBINATIONS

# Port scan → Tech detection
naabu -l dml.txt -p 80,443 -silent | httpx -tech-detect -o port_tech.txt

# Subdomain → Tech detection
subfinder -dL domains.txt -silent | httpx -tech-detect -title -o subdomain_tech.txt

# Certificate → Tech detection
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | httpx -tech-detect -o crt_tech.txt


## 13. DATABASE DETECTION

# MySQL detection
while read target; do nmap -p 3306 $target --script mysql-info -oN mysql_info.txt 2>/dev/null; done < dml.txt

# PostgreSQL detection
while read target; do nmap -p 5432 $target --script pgsql-brute -oN pgsql_info.txt 2>/dev/null; done < dml.txt

# MongoDB detection
while read target; do nmap -p 27017 $target --script mongodb-info -oN mongodb_info.txt 2>/dev/null; done < dml.txt

# Redis detection
while read target; do nmap -p 6379 $target --script redis-info -oN redis_info.txt 2>/dev/null; done < dml.txt


## 14. OUTPUT PROCESSING

# Extract just technologies
httpx -l dml.txt -tech-detect | grep -o "\[.*\]" | sort | uniq -c | sort -rn > tech_count.txt

# Create technology matrix
echo "Domain,Web Server,Technologies" > tech_matrix.csv
httpx -l dml.txt -tech-detect -web-server -silent | awk '{print $1 "," $2 "," $3}' >> tech_matrix.csv

# JSON formatted output
httpx -l dml.txt -tech-detect -json | jq '.[] | {domain: .url, tech: .tech}' > tech_json.txt


## 15. BANNER GRABBING

# Service banner grabbing
while read target; do for port in 21 22 23 25 110 143; do echo -n "$target:$port - "; timeout 2 nc -v $target $port 2>&1 | head -1; done; done < dml.txt > service_banners.txt

# HTTP server banners
httpx -l dml.txt -web-server -silent | awk '{print $1 " - " $2}' > http_banners.txt


## 16. CUSTOM DETECTION SCRIPTS

# WordPress version detection
while read url; do curl -s "$url/readme.html" | grep -i "wordpress" | head -1 | awk -v u="$url" '{print u ": " $0}'; done < dml.txt > wp_versions.txt

# PHP version detection
while read url; do curl -s "$url" | grep -i "php/" | head -1 | awk -v u="$url" '{print u ": " $0}'; done < dml.txt > php_versions.txt

# Apache/Nginx version
while read url; do curl -I -s "$url" | grep -i "server:" | awk -v u="$url" '{print u ": " $0}'; done < dml.txt > server_versions.txt


## 17. PERFORMANCE OPTIMIZED

# Fast tech detection
httpx -l dml.txt -tech-detect -timeout 3 -threads 100 -o fast_tech.txt

# Batch processing
pv dml.txt | httpx -tech-detect -silent > batch_tech.txt

# Resume scan
httpx -l dml.txt -tech-detect -resume -o resumed_tech.txt


## 18. SPECIALIZED DETECTION

# E-commerce platforms
httpx -l dml.txt -tech-detect | grep -i "magento\|shopify\|woocommerce\|prestashop\|opencart" > ecommerce.txt

# JavaScript frameworks
httpx -l dml.txt -tech-detect | grep -i "react\|angular\|vue\|ember\|backbone" > js_frameworks_detected.txt

# Cloud platforms
httpx -l dml.txt -tech-detect | grep -i "aws\|azure\|gcp\|cloudflare\|heroku" > cloud_platforms.txt

# Analytics tools
httpx -l dml.txt -tech-detect | grep -i "google-analytics\|matomo\|mixpanel\|hotjar" > analytics.txt
