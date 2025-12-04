# DNS RESOLUTION - COMMAND REFERENCE (MULTI-DOMAIN)

## 1. BASIC DNS RESOLUTION - ONE LINERS

# Resolve A records for all domains in file (with response)
dnsx -dL dml.txt -a -resp -o dns_results.txt

# Fast silent resolution (only output resolved domains)
dnsx -dL dml.txt -a -silent > live_dml.txt

# Resolve multiple record types at once
dnsx -dL dml.txt -a -aaaa -cname -mx -txt -ns -o all_records.txt

# Resolve with custom DNS servers
dnsx -dL dml.txt -a -r resolvers.txt -o custom_resolved.txt


## 2. BULK SUBDOMAIN RESOLUTION

# Resolve list of subdomains from file
dnsx -l sub_dml.txt -a -resp -o resolved_subs.txt

# Filter only successful resolutions (remove NXDOMAIN)
dnsx -l sub_dml.txt -a -silent | grep -v "NXDOMAIN" > successfully_resolved.txt

# Parallel DNS resolution with retry
cat sub_dml.txt | dnsx -a -retry 3 -silent > parallel_resolved.txt


## 3. MASS DNS RESOLUTION

# High-performance MassDNS resolution
massdns -r resolvers.txt -t A -o S -w massdns_results.txt sub_dml.txt

# MassDNS with wildcard filtering
massdns -r resolvers.txt -t A -o S -i /dev/null -w massdns_filtered.txt sub_dml.txt

# PureDNS resolution with wildcard detection
puredns resolve sub_dml.txt -r resolvers.txt -w puredns_output.txt


## 4. SPECIFIC DNS QUERIES

# Get only A records using dig
while read dm; do dig A "$dm" +short; done < dml.txt > dig_a.txt

# Get A and AAAA records
while read dm; do echo "$dm: $(dig A "$dm" +short) $(dig AAAA "$dm" +short)"; done < dml.txt > ipv4_ipv6.txt

# Get CNAME records
while read dm; do cname=$(dig CNAME "$dm" +short); [ -n "$cname" ] && echo "$dm -> $cname"; done < sub_dml.txt > cnames.txt

# Get MX records for domains
while read dm; do mx=$(dig MX "$dm" +short); [ -n "$mx" ] && echo "$dm: $mx"; done < dml.txt > mx_records.txt


## 5. DNS BRUTEFORCING RESOLUTION

# DNS bruteforce with resolution
dnsx -dL dml.txt -w wordlist.txt -a -resp -o brute_resolved.txt

# PureDNS bruteforce with wildcard detection
while read dm; do puredns bruteforce wordlist.txt "$dm" -r resolvers.txt -w "brute_$dm.txt"; done < dml.txt

# MassDNS bruteforce
massdns -r resolvers.txt -t A -o S -w massdns_brute.txt -s 100 wordlist.txt


## 6. DATA EXTRACTION & FORMATTING

# Extract only IP addresses from DNS results
cat dns_results.txt | awk '{print $2}' | sort -u > unique_ips.txt

# Create domain:IP mapping
cat dns_results.txt | awk '{print $1 ":" $2}' > domain_ip_map.txt

# Count resolutions per domain
cat dns_results.txt | awk '{print $1}' | awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c > domain_counts.txt

# Filter by IP range
cat dns_results.txt | grep -E "10\.[0-9]+\.[0-9]+\.[0-9]+" > internal_ips.txt
cat dns_results.txt | grep -E "(192\.168|172\.(1[6-9]|2[0-9]|3[0-1]))" > rfc1918_ips.txt


## 7. ADVANCED DNS ANALYSIS

# Check for DNS wildcards
while read dm; do random=$(head /dev/urandom | tr -dc a-z0-9 | head -c 8); dig A "$random.$dm" +short | grep -q -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" && echo "$dm: WILDCARD DETECTED"; done < dml.txt

# Find shared IPs (virtual hosting detection)
cat resolved_subs.txt | awk '{print $2, $1}' | sort | uniq -c | sort -rn | head -20 > shared_hosting.txt

# Reverse DNS lookup on found IPs
cat unique_ips.txt | while read ip; do host "$ip" | grep -v "not found" | awk '{print $NF}'; done > reverse_dns.txt

# Check for CDN IPs (common CDN ranges)
cat unique_ips.txt | grep -E "(104\.16|104\.24|23\.[0-9]+|52\.[0-9]+|54\.[0-9]+|34\.[0-9]+)" > cdn_ips.txt


## 8. OUTPUT FORMATS

# JSON output
cat dns_results.txt | jq -R 'split(" ") | {domain: .[0], ip: .[1]}' | jq -s '.' > dns_results.json

# CSV output
echo "Domain,IP Address" > dns_results.csv
cat dns_results.txt | awk '{print $1 "," $2}' >> dns_results.csv

# Simple list format
cat dns_results.txt | sed 's/ / -> /' > simple_list.txt

# Markdown table
echo "| Domain | IP Address |" > dns_table.md
echo "|--------|------------|" >> dns_table.md
cat dns_results.txt | awk '{print "| " $1 " | " $2 " |"}' >> dns_table.md


## 9. QUICK COMMANDS FOR DAILY USE

# Quick check if domains resolve
dnsx -dL dml.txt -a -silent | wc -l

# Resolve and immediately filter interesting IPs
dnsx -l sub_dml.txt -a -resp | grep -v "127.0.0.1\|192.168\|10\." > public_ips.txt

# One-liner: Resolve and save with timestamp
date +%Y%m%d_%H%M%S | xargs -I {} dnsx -l sub_dml.txt -a -resp -o "dns_scan_{}.txt"

# Resolve and sort by IP
dnsx -l sub_dml.txt -a -resp | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n > sorted_by_ip.txt


## 10. SPECIALIZED DNS LOOKUPS

# Check for SPF records
while read dm; do spf=$(dig TXT "$dm" +short | grep -i "spf"); [ -n "$spf" ] && echo "$dm: $spf"; done < dml.txt > spf_records.txt

# Check for DMARC records
while read dm; do dmarc=$(dig TXT "_dmarc.$dm" +short); [ -n "$dmarc" ] && echo "$dm: $dmarc"; done < dml.txt > dmarc_records.txt

# Check for DKIM records (common selectors)
for selector in default google selector1 selector2; do while read dm; do dkim=$(dig TXT "$selector._domainkey.$dm" +short); [ -n "$dkim" ] && echo "$dm ($selector): $dkim"; done < dml.txt; done > dkim_records.txt

# DNS zone transfer test
while read dm; do echo "=== Testing $dm ==="; dig AXFR "$dm" @ns1."$dm"; done < dml.txt > zone_transfer_test.txt


## 11. COMBINATION PIPELINES

# Find subdomains and immediately resolve them
subfinder -dL dml.txt -silent | dnsx -a -silent > subfinder_resolved.txt

# Cert transparency -> DNS resolution pipeline
while read dm; do curl -s "https://crt.sh/?q=%25.$dm&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g'; done < dml.txt | dnsx -a -silent > crt_resolved.txt

# Assetfinder -> DNSx pipeline
while read dm; do assetfinder --subs-only "$dm"; done < dml.txt | dnsx -a -silent > assetfinder_resolved.txt

# Combine multiple sources and resolve
cat subfinder.txt assetfinder.txt crtsh.txt | sort -u | dnsx -a -silent > combined_resolved.txt


## 12. PERFORMANCE OPTIMIZED COMMANDS

# Fastest resolution (no additional output)
dnsx -l sub_dml.txt -a -silent -retry 1 -timeout 3 > fast_resolve.txt

# Batch processing with progress
pv sub_dml.txt | dnsx -a -silent -o dnsx_with_progress.txt

# Resolve with concurrency control
dnsx -l sub_dml.txt -a -silent -t 50 -o concurrent_resolve.txt

# MassDNS with high performance
massdns -r resolvers.txt -t A -o S -w output.txt -s 500 sub_dml.txt
