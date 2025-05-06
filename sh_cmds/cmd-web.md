## Web Discovery & Content Crawling

### Sitemap Discovery & Parsing
    :- Finding and extracting URLs from sitemap.xml files
    
    curl -s https://target.com/sitemap.xml | grep "<loc>" | sed 's/<loc>//g;s/<\/loc>//g' > sitemap_urls.txt 
    :- Manually fetch and parse sitemap

    katana -u https://target.com -sitemap -o katana_sitemap_urls.txt     
    :- Use Katana to automatically find and parse sitemaps

    ffuf -w sitemap_paths.txt -u https://target.com/FUZZ -mc 200 -o ffuf_sitemap_check.txt 
    :- Fuzz common sitemap locations (sitemap.xml, sitemap_index.xml, etc.)

    gospider -s https://target.com --sitemap -o gospider_sitemap.txt      
    :- Gospider can also parse sitemaps

### Robots.txt Analysis
    :- Finding disallowed paths which might contain interesting endpoints or directories
    
    curl -s https://target.com/robots.txt                                
    :- Fetch robots.txt

    curl -s https://target.com/robots.txt | grep "Disallow:" | awk '{print $2}' > disallowed_paths.txt 
    :- Extract disallowed paths

    robotstxt-parser 'https://target.com/robots.txt'                    
    :- Use a dedicated parser tool (conceptual name)
    
    :- Manually check disallowed paths using curl or ffuf:

    while read path; do curl -s -o /dev/null -w "%{http_code} - $path\n" "https://target.com$path"; done < disallowed_paths.txt

### Favicon Hashing for Tech/Asset Identification
    :- Identifies sites/technologies by hashing the /favicon.ico file and comparing against known hashes
    
    :- 1. Get the favicon hash:

    python3 -c 'import mmh3; import requests; r = requests.get("https://target.com/favicon.ico", verify=False); print(mmh3.hash(r.content))'
    
    favfreak.py -i list_of_hosts.txt -o favicon_matches.json             
    :- Tool to automate favicon hashing and lookup (conceptual)
    
    nuclei -l live_urls.txt -t technologies/favicon-detection-template.yaml -o nuclei_favicon_tech.txt 
    :- Nuclei template for favicon tech detection (if available)
    
    Search hash on Shodan: http.favicon.hash:<hash_value>               
    :- Use Shodan to find other sites with the same favicon

### Source Code / VCS Exposure Discovery
    :- Finding exposed .git, .svn, .DS_Store files etc.
    
    git-dumper https://target.com/.git/ ./target_git_dump              
    :- Dump exposed .git repositories

    svn-extractor http://target.com/.svn/ ./target_svn_dump             
    :- Dump exposed .svn repositories

    dotds_finder -u https://target.com -o ds_store_files.txt            
    :- Find exposed .DS_Store files

    ffuf -w vcs_paths.txt -u https://target.com/FUZZ -mc 200,403 -o ffuf_vcs_check.txt 
    :- Fuzz common VCS paths (.git/HEAD, .svn/entries, etc.)
    
    nuclei -u https://target.com -t exposures/exposed-panels/            
    :- Nuclei templates often include checks for exposed VCS/source code

### HTTP Method Testing (Beyond standard GET/POST)
    :- Identifying allowed methods like PUT, DELETE, OPTIONS, etc.
    
    curl -X OPTIONS https://target.com/api/resource -i                  
    :- Check allowed methods using OPTIONS

    httpx -l live_urls.txt -silent -methods -o allowed_methods.txt      
    :- Use httpx to probe allowed methods for a list of URLs
    
    :- Use ffuf/wfuzz to test arbitrary methods:

    ffuf -w methods.txt:METHOD -u https://target.com/resource -X METHOD --hc 404 
    :- Fuzz methods from a list
    
    nuclei -u https://target.com -t exposures/http-verb-tampering.yaml 
    :- Use Nuclei templates for method tampering/testing

### Form Discovery
    :- Specifically identifying HTML forms for further testing - CSRF, XSS, SQLi etc.
    
    katana -u https://target.com -f form -o katana_forms.txt            
    :- Use Katana's field config to extract forms
    
    :- Use general crawlers (Katana, GoSpider, Hakrawler) and grep output for `<form` tags

    grep -rio "<form" ./crawl_output/                                 
    :- Grep crawl results for form tags

### Configuration File Discovery (Targeted Fuzzing)
    :- Looking for common config files like .env, web.config, .htaccess, server-status, etc.
    
    ffuf -w config_files.txt -u https://target.com/FUZZ -mc 200 -o ffuf_configs.txt 
    :- Fuzz common config file names/paths

    ffuf -w config_exts.txt -u https://target.com/config.FUZZ -mc 200 -o ffuf_config_exts.txt 
    :- Fuzz extensions for common config base names

    ffuf -w apache_files.txt -u https://target.com/FUZZ -H "Host: localhost" -mc 200 
    :- Check common Apache config/status files (e.g., /server-status, /server-info)
    
    nuclei -u https://target.com -t exposures/files/sensitive-files.yaml -o nuclei_sensitive_files.txt 
    :- Use Nuclei templates for sensitive file exposure

### Link Extraction & Analysis Tools
    linkfinder -i 'https://target.com/*.js' -o js_links.txt             - Re-iterated for focus on link finding

    getlinks.py https://target.com > page_links.txt                     
    :- Conceptual tool to extract all href/src links from a page

### Combining tools:
    katana -u https://target.com -silent | grep -Eo "(http|https)://[a-zA-Z0-9./?=_%:-]*" | sort -u > extracted_links.txt

    :- AJAX Crawling (Handling dynamically loaded content)
    :- Tools like Katana (-jc), GoSpider (--js) attempt this.
    :- For heavy JS sites, headless browsers driven by scripts are often needed.
    
    :- python3 -m playwright install                                     
    :- Install Playwright browser binaries
    
    :- node fetch_dynamic_content.js https://target.com                  
    :- Use a custom Node.js script with Puppeteer/Playwright
    :- Burp Suite's Navigation Recorder or manual Browse through a proxy is often required.

    :- HTTP Archive (HAR) File Analysis
    :- HAR files capture browser-website interaction; can be generated via browser DevTools
    
    :- Tools can parse HAR files for endpoints, parameters, headers etc.
    :- har-tools parse network_log.har --filter 'application/json'       
    :- Conceptual tool to parse HAR files
    :- jq '.log.entries[].request.url' network_log.har                   
    :- Use jq to extract URLs from HAR

### Response Header Analysis
    :- Inspecting headers for security configurations, technology info, and potential leaks
    
    curl -I https://target.com                                          
    :- Fetch headers only using HEAD request
 
    curl -s -D - https://target.com -o /dev/null                        
    :- Fetch headers using GET request, discard body
 
    httpx -l live_urls.txt -silent -H "User-Agent: MyScanner" -csp -hsts -security-headers -server -tech -o header_analysis.txt 
    :- httpx for security headers, server info etc.
    
### Manually inspect headers like:
    :- Server: Apache/2.4.41 (Ubuntu) -> Technology disclosure

    :- X-Powered-By: PHP/7.4.3 -> Technology disclosure

    :- Content-Security-Policy: ... -> Check for weak CSP

    :- Strict-Transport-Security: ... -> Check HSTS settings

    :- Access-Control-Allow-Origin: * -> Potential CORS misconfiguration

    :- Set-Cookie: ... -> Analyze cookie flags (HttpOnly, Secure, SameSite)

    :- X-Frame-Options: ... -> Clickjacking protection

    :- X-AspNet-Version: ... -> ASP.NET version disclosure

### Status Code & Content Analysis (Beyond basic checks)
    :- Analyzing non-200/404 codes and content properties for clues
    
    ffuf -w wordlist.txt -u https://target.com/FUZZ --sc 200,301,302,401,403,500 -o ffuf_interesting_codes.txt 
    :- Fuzz and record multiple interesting status codes

    httpx -l live_urls.txt -silent -status-code -content-length -o status_length.txt 
    :- Record status code and content length

### Analyze results for patterns:
    :- Consistent content length for custom 404s (use with ffuf -fs)

    :- 401/403 codes often indicate restricted areas worth noting

    :- 301/302 redirects might lead to new paths or domains

    :- 500 errors might indicate code issues, potential for info leaks via debug messages

### Content Similarity Analysis (for custom 404s, default pages)
    :- Requires tools that can calculate perceptual hashes or similarity scores

    pip install ssdeep tlsh
    
    :- Conceptual Workflow:
    :- 1. Get response body for a known non-existent page: curl https://target.com/nonexistent_page > baseline_404.html
    :- 2. Calculate hash: ssdeep baseline_404.html > baseline_hash.txt
    :- 3. During fuzzing, hash responses and compare:
    
    ffuf -w wordlist.txt -u https://target.com/FUZZ -of json -o ffuf_results.json
    python process_ffuf_output.py ffuf_results.json baseline_hash.txt 
    :- Custom script to hash results and compare

### Error Message Extraction & Analysis
    :- Looking for stack traces, database errors, file paths in error messages
    
    :- Combine crawling/fuzzing with grep:

    katana -u https://target.com -d 3 -o crawl.txt && cat crawl.txt | httpx -silent -status-code 500 -o error_pages.txt

    cat error_pages.txt | xargs -I{} curl -s {} | grep -E 'Exception|Error|Warning|Traceback|SQLSTATE| ORA-|path|Microsoft OLE DB|at line' > errors_found.txt
    
    nuclei -l live_urls.txt -t exposures/stacktrace-disclosure.yaml -o nuclei_stacktraces.txt 
    :- Use Nuclei templates for error detection

### Backup & Temporary File Fuzzing
    :- Systematic check for common backup extensions and temporary files
    
    ffuf -w wordlist.txt -u https://target.com/FUZZ -e .bak,.old,.zip,.txt,.tmp,.temp,~,.swp,_bkp,bkup -mc 200 -o ffuf_backups.txt 
    :- Fuzz common backup extensions
 
    ffuf -w common_filenames.txt -u https://target.com/FUZZ -e .bak,.old,.zip -mc 200 -o ffuf_common_backups.txt 
    :- Fuzz backups for common files (index, config, main, etc.)
 
    ffuf -w wordlist.txt -u https://target.com/~FUZZ -mc 200,403          
    :- Check for user directories via tilde (~) convention if applicable

### Hidden Input Field Discovery
    :- Finding form fields marked as type="hidden" which might contain sensitive info or be tamperable
 
    katana -u https://target.com -f hidden -o katana_hidden_inputs.txt  
    :- Use Katana's field config to extract hidden inputs
 
    gospider -s https://target.com --other-source --include-subs -o gospider_all_urls.txt
 
    cat gospider_all_urls.txt | httpx -silent | grep -rio '<input[^>]*type=[\" \']hidden[\" \']' 
    :- Grep crawled pages for hidden inputs

### Wayback Machine for Deleted/Old Content Analysis
    :- Specifically looking for content that is no longer live
    
    waybackurls target.com | grep -E '\.(bak|old|zip|sql|config|log|env)' | anew potential_old_sensitive_files.txt 
    :- Filter wayback results for sensitive extensions

    waybackurls target.com | while read url; do curl -s "$url" | grep "password\|api_key\|secret"; done 
    :- Curl old URLs found and grep for keywords (can be slow/noisy)

### Manually browse significant past versions of key pages on archive.org
    :- Common Crawl Data Querying (Advanced)

    :- Requires specialized tools or querying the Common Crawl index directly

    :- cc-index-tools query cdx-000XX.gz --query "url:target.com/login" 
    :- Example using index tools (conceptual)

    :- Use online services that provide Common Crawl interfaces if available.