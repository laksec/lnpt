### 1.2 DNS & Network Recon
    # RECOMMENDED WORKFLOW:
    # 1. Start with dnsx for basic enumeration (-a -aaaa -cname)
    # 2. Run dnscan for brute forcing
    # 3. Use fierce for deep traversal
    # 4. Perform DNS recon for special records
    # 5. Check for zone transfers
    # 6. Gather network info via whois/bgp

    # Always check for DNS zone transfers first (dig axfr)
    # Use dnsx -resp-chain to map CNAME chains
    # Combine with HTTP probing: cat dns_records.json | jq -r '.a[]?' | httpx

    # DNSX (Fast DNS toolkit)
    dnsx -l subs.txt -a -aaaa -cname -mx -txt -ptr -ns -soa -resp -json -o dns_records.json
    dnsx -d target.com -ns -cname -resp-chain -silent -o dns_relationships.txt
    dnsx -l subdomains.txt -type A,AAAA,CNAME,MX,TXT,NS,SOA,SRV -retry 3 -o all_records.txt

    # DNSCAN (Subdomain brute forcer)
    dnscan -d target.com -w subdomains-top1million-5000.txt -t 150 -o dnscan_brute.txt
    dnscan -d target.com -w custom_wordlist.txt -r -o dnscan_recursive.txt

    # FIERCE (Domain reconnaissance)
    fierce --domain target.com --wide --traverse 5 --subdomains subs.txt --dnsserver 1.1.1.1 -outfile fierce_scan.txt
    fierce --domain target.com --tcpport 53 --timeout 10 -outfile fierce_tcp.txt

    # DNSRECON (Comprehensive DNS)
    dnsrecon -d target.com -a -z -t brt -D wordlist.txt -xml dnsrecon_full.xml
    dnsrecon -d target.com -Axfr -n ns1.target.com -o zone_transfer.txt
    dnsrecon -d target.com -t srv -o srv_records.txt

    # DIG (Manual queries)
    dig any target.com @1.1.1.1 +short | anew dig_any.txt
    dig axfr target.com @ns1.target.com +nocookie | tee zone_transfer_raw.txt
    dig +trace target.com | tee dns_trace.txt

    # WHOIS/BGP
    whois target.com | tee whois_info.txt
    bgp.he.net search "Company Name" | tee bgp_asn.txt
    whois -h whois.radb.net '!gAS12345' | tee ip_ranges.txt

#### 1.2.1 DNS Reconnaissance
    # RECOMMENDED WORKFLOW:
    # 1. Start with dnsx comprehensive scan
    # 2. Check for zone transfers (dig axfr)
    # 3. Run targeted record queries
    # 4. Perform brute force enumeration
    # 5. Verify with manual dig/host commands

    # Always check TXT records for security policies (SPF/DKIM/DMARC)
    # Use -wd flag to filter out wildcard subdomains
    # For internal networks, try dnsrecon -t rvl for reverse lookups
    # Combine with HTTP probing: cat dns_a_records.txt | httpx -silent

    # Comprehensive DNS query (all record types)
    dnsx -l subdomains.txt -a -aaaa -cname -mx -txt -ptr -ns -soa -resp -json -o dns_records_full.json

    # Targeted record queries
    dnsx -l subdomains.txt -t A -resp -o dns_a_records.txt
    dnsx -l subdomains.txt -t CNAME -resp -o dns_cname_chains.txt
    dnsx -l subdomains.txt -t MX -o dns_mx_servers.txt
    dnsx -l subdomains.txt -t TXT -o dns_txt_records.txt

    # Special operations
    dnsx -l subdomains.txt -r resolvers.txt -o dns_reliable_results.txt
    dnsx -l subdomains.txt -wd target.com -o dns_clean_subdomains.txt
    dnsx -l subdomains.txt -ns-resolve -o dns_ns_ips.txt

    # DIG (Manual DNS queries)
    # Essential record types
    dig target.com ANY +noall +answer
    dig target.com MX +short
    dig target.com TXT +short
    dig target.com NS +short

    # Zone transfer attempts
    dig axfr target.com @ns1.target.com
    dig axfr target.com @ns2.target.com

    # Reverse DNS
    dig -x 1.1.1.1 +short

    # HOST (Quick lookups)
    host target.com
    host -t CNAME www.target.com
    host -t SOA target.com

    # FIERCE (Semi-active recon)
    fierce --domain target.com --subdomains subs.txt --threads 20
    fierce --domain target.com --wide --traverse 5 --dnsserver 1.1.1.1

    # DNSRECON (Comprehensive)
    # Standard enumeration
    dnsrecon -d target.com -t std -o dns_standard.txt

    # Specialized scans
    dnsrecon -d target.com -t axfr -o dns_zone_transfer.txt
    dnsrecon -d target.com -t brt -D subdomains-top1million.txt -o dns_bruteforce.txt
    dnsrecon -d target.com -t srv -o dns_srv_records.txt
    dnsrecon -d target.com -t zonewalk -o dns_nsec_walk.txt

#### 1.2.2 ASN and IP Range Discovery
    # RECOMMENDED WORKFLOW:
    # 1. Start with amass intel to discover ASNs
    # 2. Use whois to verify ASN details
    # 3. Query BGP tools for network ranges
    # 4. Trace network paths to target
    # 5. Map all nameserver IPs

    # Use amass viz to visualize relationships (requires SQLite output)
    # Combine with masscan for large network scans: masscan -p1-65535 -iL ip_ranges_as12345.txt
    # For IPv6: amass intel -asn AS12345 -6 or whois -h whois.radb.net -- '-i origin AS12345' | grep route6

    # PRO TIP: Combine with nmap for network mapping
    # nmap --script targets-asn --script-args targets-asn.asn=AS12345 > nmap_asn_scan.txt


    # AMASS INTEL (Best for ASN discovery)
    # Find ASNs by organization name
    amass intel -org "Target Company" -whois -ip -asn -o asn_discovery.txt

    # Get all IP ranges for an ASN
    amass intel -asn AS12345 -cidr -o ip_ranges_as12345.txt

    # Reverse Whois lookup for CIDR
    amass intel -cidr 192.168.0.0/16 -o reverse_whois.txt

    # WHOIS COMMANDS (Direct queries)
    # Get ASN details
    whois -h whois.radb.net -- '-i origin AS12345' | grep -E 'route:|route6:' > radb_routes.txt

    # Get domain whois with ASN
    whois target.com | grep -i 'originas:\|asn:' | awk '{print $2}' | sort -u > domain_asns.txt

    # Get IP whois info
    whois 1.2.3.4 | grep -i 'netname\|originas\|asn' > ip_whois.txt

    # BGP TOOLS (Network mapping)
    # Get prefixes from BGPView API
    curl -s "https://api.bgpview.io/asn/12345/prefixes" | jq '.data.ipv4_prefixes[].prefix' > bgpview_prefixes.txt

    # Get ASN details from ipinfo.io
    curl -s "https://ipinfo.io/AS12345/json" | jq '.asn,.name,.country' > ipinfo_asn.json

    # NETWORK TRACING
    # Get IPs from DNS trace
    dig +trace target.com | grep -E 'IN\s+A|IN\s+AAAA' | awk '{print $5}' | sort -u > dns_trace_ips.txt

    # Get IPs from TCP traceroute (port 80)
    traceroute -n -T -p 80 target.com | awk '$2~/[0-9]/{print $2}' | sort -u > tcp_trace_ips.txt

    # NS LOOKUP
    # Get all nameserver IPs
    dig +short ns target.com | xargs -I{} dig +short {} | sort -u > all_ns_ips.txt


    # ZeroTrace is a powerful command-line anonymization tool I created using Python.
    sudo zerotrace --start [--auto] [--time 3] [--stop]
      
# Using Masscan to verify HTTP servers
masscan -p80,443 -iL subdomains.txt -oG masscan.txt --rate 10000

# Using HTTPX for live hosts
cat subdomains.txt | httpx -title -status-code -tech-detect -o httpx_results.txt

# Using Anew to merge results
cat *.txt | anew all_subdomains.txt

# 5. CLOUD-SPECIFIC ENUMERATION
# -----------------------------

# AWS Bucket Enumeration
aws s3 ls s3:// --no-sign-request | grep target
s3scanner scan -l domains.txt -o s3_results.txt

# Azure Blob Scanning
az storage account list --query [].primaryEndpoints.blob -o tsv | grep target

# Google Cloud Enumeration
gsutil ls gs:// | grep target

# 6. SUBDOMAIN TAKEOVER TESTING
# -----------------------------

# Using Subjack
subjack -w subdomains.txt -t 100 -timeout 30 -o subjack_results.txt -ssl

# Using Nuclei
nuclei -l subdomains.txt -t ~/nuclei-templates/takeovers/ -o nuclei_takeovers.txt

# Using HostileSubBruteforcer
python3 HostileSubBruteforcer.py -d target.com -l 2 -t 100 -o takeover_results.txt

# 7. VISUALIZATION & ANALYSIS
# ---------------------------

# Using EyeWitness
eyewitness -f subdomains.txt -d screenshots/ --web

# Using Aquatone
cat subdomains.txt | aquatone -out aquatone_report -ports 80,443,8080,8443

# 8. AUTOMATED WORKFLOWS
# ----------------------

# Using PureDNS
puredns bruteforce ~/wordlists/subdomains.txt target.com -r ~/wordlists/resolvers.txt -w puredns_results.txt

# Using Chaos Client
chaos -d target.com -key YOUR_API_KEY -o chaos_results.txt

# Using Automated Recon
amass enum -d target.com -passive -o amass.txt
subfinder -d target.com -o subfinder.txt
assetfinder --subs-only target.com > assetfinder.txt
cat *.txt | anew all_subs.txt | httpx -title -status-code -tech-detect -o final_results.txt

# ==============================================
# TIPS:
# 1. Always use multiple tools for best coverage
# 2. Verify all findings with DNS resolution
# 3. Check for subdomain takeovers
# 4. Respect rate limits and terms of service
# ==============================================

# RECOMMENDED WORDLISTS:
# ----------------------
# ~/wordlists/subdomains.txt
# ~/wordlists/permutations.txt
# ~/wordlists/resolvers.txt