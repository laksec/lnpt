### 2.1 URL Discovery
    # ARCHIVAL SOURCES (GAU/Wayback)
    # Comprehensive URL discovery (all sources)
    gau target.com --subs --threads 50 --o gau_all_urls.txt
    gau target.com --providers wayback,commoncrawl,otx --json -o gau_specific.json

    # Wayback Machine specialized queries
    waybackurls target.com --dates 2020-2023 | anew wayback_2020-2023.txt
    waybackurls target.com | grep -E "\.js(on)?$" | anew wayback_js_files.txt
    waybackurls target.com | grep "\?" | grep -v "\.\(css\|jpg\|png\)" | anew wayback_params.txt

    # ACTIVE CRAWLING TOOLS
    # Katana (advanced crawling)
    katana -u https://target.com -d 4 -jc -kf -o katana_deep.txt
    katana -list live_urls.txt -ef woff,css,png -aff php,aspx -o katana_filtered.txt

    # Gospider (powerful spider)
    gospider -s https://target.com -d 3 -t 20 -c 10 --js --other-source -o gospider_full
    gospider -S subdomains.txt -d 2 --blacklist ".(jpg|png|css)$" -o gospider_subdomains

    # Hakrawler (fast crawler)
    hakrawler -url https://target.com -d 3 -subs -u -t 15 -scope target.com -o hakrawler.txt
    hakrawler -url https://target.com -proxy http://127.0.0.1:8080 -insecure -o hakrawler_proxied.txt

    # FILTERING & PROCESSING

    # Filter interesting URLs
    cat gau_all_urls.txt | grep -E "api|admin|auth" | anew sensitive_urls.txt
    cat katana_deep.txt | grep "\.php" | grep "id=" | anew php_params.txt

    # Extract parameters
    cat wayback_params.txt | unfurl -u format %q | sort -u > all_params.txt

    # Combine and dedupe
    cat gau_all_urls.txt wayback_*.txt katana_*.txt | sort -u > all_urls.txt

    # RECOMMENDED WORKFLOW:
    # 1. Start with gau/waybackurls for historical data
    # 2. Run katana/gospider for active crawling
    # 3. Filter results for sensitive endpoints
    # 4. Extract parameters for testing
    # 5. Combine all sources for complete coverage

    # PRO TIPS:
    # For large scopes: Split domains and parallelize with GNU parallel
    # For authentication: Use '-H "Cookie: session=xyz"' in crawling tools
    # For stealth: Rotate user agents and use delays
    # For monitoring: Schedule weekly scans with cron + git for versioning

#### 2.1.1 URL Discovery from Multiple Sources
#### 2.1.2 Sitemap Discovery & Parsing
    # MANUAL SITEMAP EXTRACTION
    # Basic sitemap parsing with curl
    curl -s https://target.com/sitemap.xml | grep -Eo '<loc>[^<]+' | sed 's/<loc>//' > sitemap_urls.txt

    # Handle compressed sitemaps
    curl -s https://target.com/sitemap.xml.gz | gunzip | grep -Eo '<loc>[^<]+' | sed 's/<loc>//' > sitemap_urls.txt

    # Parse sitemap index (with recursive fetching)
    curl -s https://target.com/sitemap_index.xml | grep -Eo '<loc>[^<]+' | sed 's/<loc>//' | xargs -I{} sh -c 'curl -s {} | grep -Eo "<loc>[^<]+" | sed "s/<loc>//"' > all_sitemap_urls.txt

    # AUTOMATED TOOLS
    # Katana sitemap discovery
    katana -u https://target.com -sitemap -o katana_sitemap.txt

    # Gospider sitemap processing
    gospider -s https://target.com --sitemap --other-source -o gospider_sitemap.txt

    # SITEMAP FUZZING
    # Common sitemap locations
    ffuf -w /path/to/sitemap_wordlist.txt -u https://target.com/FUZZ -mc 200 -o ffuf_sitemap.json

    # Sitemap wordlist should contain:
    # sitemap.xml
    # sitemap_index.xml
    # sitemap1.xml
    # sitemap_news.xml
    # sitemap-a.xml
    # sitemap.gz
    # wp-sitemap.xml
    # robots.txt

    # ROBOTS.TXT CHECK
    curl -s https://target.com/robots.txt | grep -i "sitemap" | awk -F': ' '{print $2}' > discovered_sitemaps.txt

    # ADVANCED TECHNIQUES

    # 1. Combine all methods
    cat <(curl -s https://target.com/robots.txt | grep -i sitemap | awk '{print $2}') \
        <(ffuf -w sitemap_wordlist.txt -u https://target.com/FUZZ -mc 200 -of csv | awk -F, '{print $1}') \
        | sort -u | xargs -I{} sh -c 'curl -s {} | grep -Eo "<loc>[^<]+" | sed "s/<loc>//"' > all_urls.txt

    # 2. Parallel processing
    cat sitemap_list.txt | parallel -j 10 'curl -s {} | grep -Eo "<loc>[^<]+" | sed "s/<loc>//"' > urls.txt

    # 3. JQ processing for JSON sitemaps
    curl -s https://target.com/sitemap.json | jq -r '.urls[].loc' > json_sitemap_urls.txt

    # PRO TIPS:
    # 1. Always check /robots.txt first
    # 2. Try common sitemap paths if standard ones fail
    # 3. Look for compressed sitemaps (.gz)
    # 4. Combine with waybackurls for historical sitemaps
    # 5. Use '-H "Accept: application/xml"' header for stubborn endpoints

#### 2.1.3 Robots.txt Analysis
    # BASIC FETCH & PARSE
    # Fetch robots.txt and highlight disallowed paths
    curl -s https://target.com/robots.txt | grep --color -E "Disallow:|Allow:"

    # Extract disallowed paths (clean output)
    curl -s https://target.com/robots.txt | awk '/Disallow:/ {print $2}' | sort -u > disallowed.txt

    # Extract sitemap references
    curl -s https://target.com/robots.txt | grep -i sitemap | awk '{print $2}' > sitemaps.txt

    # ADVANCED ANALYSIS
    # Check path accessibility (with status codes)
    cat disallowed.txt | xargs -I{} sh -c 'echo -n "{} - "; curl -s -o /dev/null -w "%{http_code}\n" "https://target.com{}"' > path_status.txt

    # FFUF mass testing (fast)
    ffuf -w disallowed.txt -u https://target.com/FUZZ -mc 200,403 -o ffuf_robots_results.json

    # SPECIALIZED TOOLS
    # Using robotstxt (Python parser)
    robotstxt https://target.com/robots.txt --disallow --output disallowed_paths.json

    # Using hakrawler's robots parser
    hakrawler -robots -url https://target.com -o robots_analysis.txt

    # PROBING TECHNIQUES

    # 1. Check for directory listing
    cat disallowed.txt | grep -v "\." | xargs -I{} sh -c 'curl -s "https://target.com{}" | grep -q "Index of" && echo "Directory listing: {}"'

    # 2. Find hidden files
    cat disallowed.txt | grep "\.\w\+$" | xargs -I{} sh -c 'curl -s -o /dev/null -w "%{http_code} - {}\n" "https://target.com{}"'

    # 3. Combine with common extensions
    cat disallowed.txt | while read path; do
    for ext in bak old txt json; do
        curl -s -o /dev/null -w "%{http_code} - $path$ext\n" "https://target.com$path$ext"
    done
    done > extended_checks.txt

    # PRO TIPS:
    # 1. Always check both HTTP and HTTPS versions
    # 2. Look for commented-out paths (# Disallow: /secret/)
    # 3. Test with trailing slashes and without
    # 4. Check for case-sensitive paths
    # 5. Combine with Wayback Machine data:
    #  waybackurls target.com | grep -f disallowed.txt

    # EXAMPLE WORKFLOW:
    # 1. curl -s https://target.com/robots.txt > robots.txt
    # 2. Extract disallowed paths
    # 3. ffuf -w disallowed.txt -u https://target.com/FUZZ -mc 200,403,401 -o results.json
    # 4. Analyze accessible paths manually

#### 2.1.4 Wayback Machine for Deleted/Old Content Analysis
    # Specifically looking for content that is no longer live
    
    waybackurls target.com | grep -E '\.(bak|old|zip|sql|config|log|env)' | anew potential_old_sensitive_files.txt 
    # Filter wayback results for sensitive extensions

    waybackurls target.com | while read url; do curl -s "$url" | grep "password\|api_key\|secret"; done 
    # Curl old URLs found and grep for keywords (can be slow/noisy)

    # SENSITIVE FILE DISCOVERY
    # Find backup/config files in Wayback
    waybackurls target.com | grep -E '\.(bak|old|zip|sql|tar\.gz|config|log|env|swp|~)$' \
        | anew potential_sensitive_files.txt

    # Find common sensitive filenames
    waybackurls target.com | grep -iE '(config|backup|dump|secret)\.(php|json|xml|sql)' \
        | anew common_sensitive_names.txt

    # CONTENT ANALYSIS
    # Search for secrets in historical pages (parallelized)
    waybackurls target.com | parallel -j 20 'curl -s {} | grep -E "password|api[_-]?key|secret|token"' \
        | anew potential_secrets.txt

    # Find exposed developer files
    waybackurls target.com | grep -E '\.(git/|svn/|hg/|bzr/|DS_Store)' \
        | anew version_control_exposures.txt

    # SMART VERIFICATION
    # Check if files are still live (fast)
    cat potential_sensitive_files.txt | httpx -status-code -title -o still_live_sensitive_files.txt

    # DEEP CONTENT SEARCH
    # Find PHP info files
    waybackurls target.com | grep -i 'phpinfo\.php' | anew phpinfo_files.txt

    # Find install/setup files
    waybackurls target.com | grep -iE '(install|setup)\.(php|asp|aspx)' \
        | anew installation_files.txt

    # ADVANCED TECHNIQUES

    # 1. Combine with gau for current+historical
    gau target.com | grep -E '\.env$' | anew all_env_files.txt

    # 2. Find database dumps
    waybackurls target.com | grep -E '\.sql$' | httpx -content-length -match-string "INSERT INTO" \
        | anew live_sql_dumps.txt

    # 3. Search for hardcoded credentials
    waybackurls target.com | while read url; do
        curl -s "$url" | grep -E 'password\s*=\s*["'\''][^"'\'' ]+["'\'']' \
            && echo "Found in: $url"
    done | anew hardcoded_creds.txt

    # PRO TIPS:
    # 1. Use '-j 20' in parallel to control threads
    # 2. Combine with 'gf patterns' for better filtering
    # 3. For large sites: add '| head -n 1000' to test first
    # 4. Use '-fs 0' in httpx to filter out 404s
    # 5. Store raw responses for later analysis:
    #  waybackurls target.com | httpx -json -o wayback_responses.json