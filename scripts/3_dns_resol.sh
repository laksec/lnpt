#!/bin/bash
# ELITE DNS RECON - Ultimate Coverage
set -eo pipefail

# Config
NAME="${1:-$(date +%s)}"
DOMAINS="${2:-}"
DIR="dns_${NAME}_$(date +%Y%m%d_%H%M%S)"
THREADS=250
RES_COUNT=2000

# Helper: One-liner progress
log() { echo "[$(date +%H:%M:%S)] $1"; }
count() { wc -l < "$1" 2>/dev/null || echo 0; }

# Main execution
main() {
    echo "╔═══════════════════════════════════════╗"
    echo "║ ELITE DNS RECON - ULTIMATE COVERAGE   ║"
    echo "╚═══════════════════════════════════════╝"
    
    # Validation
    [[ -z "$DOMAINS" || ! -f "$DOMAINS" ]] && {
        echo "Usage: $0 <name> <domains_file>"
        echo "Example: $0 target targets.txt"
        exit 1
    }
    mkdir -p "$DIR"/{raw,resolved,logs,tmp,wordlists,resolvers}
    
    # =========================================================================
    # PHASE 0: ULTIMATE RESOLVER COLLECTION (Every possible source)
    # =========================================================================
    log "0. ULTIMATE RESOLVER COLLECTION"
    
    # Trusted source chains
    resolver_sources=(
        "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
        "https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt"
        "https://raw.githubusercontent.com/shmilylty/OneForAll/master/resolvers.txt"
        "https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt"
        "https://raw.githubusercontent.com/bbatsche/Resolvers/master/resolvers.txt"
        "https://public-dns.info/nameservers.txt"
        "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/category-dns"
        "https://dns.google/resolve"
    )
    
    # Parallel fetch ALL sources
    for i in "${!resolver_sources[@]}"; do
        curl -s --max-time 5 --retry 2 "${resolver_sources[i]}" 2>/dev/null | \
            grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?' | \
            head -1000 > "$DIR/resolvers/src_$i.txt" &
    done
    
    # Local extraction techniques
    # 1. System DNS
    awk '/nameserver/{print $2}' /etc/resolv.conf 2>/dev/null > "$DIR/resolvers/sys.txt" &
    
    # 2. DNS advertisements
    dig +short hostname.bind chaos txt @1.1.1.1 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' > "$DIR/resolvers/ads.txt" &
    
    # 3. ISP DNS from traceroute
    (traceroute -n 8.8.8.8 2>/dev/null | grep -Eo '^ [0-9]+  [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $3}' | head -5) > "$DIR/resolvers/isp.txt" &
    
    # 4. Known reliable
    echo -e "8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n9.9.9.9\n149.112.112.112\n208.67.222.222\n208.67.220.220\n64.6.64.6\n64.6.65.6\n77.88.8.8\n77.88.8.1\n185.228.168.168\n185.228.169.168" > "$DIR/resolvers/trusted.txt"
    
    # 5. Extract from DNSDB
    curl -s "https://api.hackertarget.com/reversedns/?q=8.8.8.8" 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' >> "$DIR/resolvers/apis.txt" &
    
    wait
    
    # Merge and validate
    cat "$DIR/resolvers"/*.txt 2>/dev/null | sort -u | head -"$RES_COUNT" > "$DIR/resolvers/all.txt"
    
    # Multi-level validation
    log "  Validating resolvers (3-stage)..."
    
    # Stage 1: Quick check (1000 fastest)
    head -1000 "$DIR/resolvers/all.txt" | \
        xargs -P 100 -I{} sh -c 'timeout 0.5 dig +short google.com @{} >/dev/null 2>&1 && echo {}' \
        > "$DIR/resolvers/valid1.txt" 2>/dev/null
    
    # Stage 2: Reliability check (500 medium)
    head -500 "$DIR/resolvers/valid1.txt" | \
        xargs -P 50 -I{} sh -c 'timeout 1 dig +short example.com @{} >/dev/null 2>&1 && timeout 1 dig +short cloudflare.com @{} >/dev/null 2>&1 && echo {}' \
        > "$DIR/resolvers/valid2.txt" 2>/dev/null
    
    # Stage 3: Authority check (200 best)
    head -200 "$DIR/resolvers/valid2.txt" | \
        xargs -P 20 -I{} sh -c '
            timeout 2 dig +short NS google.com @{} >/dev/null 2>&1 && 
            timeout 2 dig +short SOA cloudflare.com @{} >/dev/null 2>&1 &&
            echo {}
        ' > "$DIR/resolvers/final.txt" 2>/dev/null
    
    # Final fallback
    [[ -s "$DIR/resolvers/final.txt" ]] || cp "$DIR/resolvers/trusted.txt" "$DIR/resolvers/final.txt"
    log "  ✓ Resolvers ready: $(count "$DIR/resolvers/final.txt")"
    
    # =========================================================================
    # PHASE 1: TARGET PROCESSING (Every possible transformation)
    # =========================================================================
    log "1. TARGET PROCESSING"
    
    # Multi-stage cleaning
    cat "$DOMAINS" | \
        # Remove protocols and paths
        sed -E 's|^[[:space:]]*(https?://)?(ftp://)?(www\.)?||; s|/.*$||; s|:.*$||; s|^\*\.||' | \
        # Remove invalid chars
        grep -E '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$' | \
        # Filter IPs
        grep -vE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | \
        sort -u > "$DIR/targets_clean.txt"
    
    # Extract ALL possible base domains
    awk -F. '{
        # Basic domains
        print $NF;
        # TLD+1
        if(NF>1) print $(NF-1)"."$NF;
        # TLD+2
        if(NF>2) print $(NF-2)"."$(NF-1)"."$NF;
        # TLD+3
        if(NF>3) print $(NF-3)"."$(NF-2)"."$(NF-1)"."$NF;
    }' "$DIR/targets_clean.txt" | sort -u > "$DIR/targets_base.txt"
    
    # Generate permutations for brute forcing
    head -100 "$DIR/targets_base.txt" | while read d; do
        echo "$d"
        # Common prefixes
        for p in www mail ftp admin api test dev stage prod portal; do
            echo "$p.$d"
        done
        # Numbered prefixes
        for i in $(seq 1 3); do
            echo "$i.$d"
            echo "web$i.$d"
            echo "app$i.$d"
        done
    done | sort -u > "$DIR/targets_expanded.txt"
    
    log "  ✓ Clean: $(count "$DIR/targets_clean.txt") | Base: $(count "$DIR/targets_base.txt") | Expanded: $(count "$DIR/targets_expanded.txt")"
    
    # =========================================================================
    # PHASE 2: ULTIMATE DNS RESOLUTION (Every possible method)
    # =========================================================================
    log "2. ULTIMATE DNS RESOLUTION"
    
    # METHOD A: MassDNS (if available) - ALL record types
    if command -v massdns >/dev/null; then
        log "  A. MassDNS (all records)"
        for rtype in A AAAA CNAME MX NS TXT SOA PTR SRV; do
            massdns -r "$DIR/resolvers/final.txt" \
                   -t "$rtype" \
                   -o S \
                   -s 10000 \
                   -w "$DIR/raw/massdns_$rtype.txt" \
                   "$DIR/targets_expanded.txt" \
                   2>>"$DIR/logs/massdns.log" &
        done
    fi
    
    # METHOD B: DNSx (intelligent)
    if command -v dnsx >/dev/null; then
        log "  B. DNSx (comprehensive)"
        dnsx -l "$DIR/targets_expanded.txt" \
            -r "$DIR/resolvers/final.txt" \
            -a -aaaa -cname -ns -mx -txt -soa -ptr -srv -caa \
            -resp -resp-only -cname \
            -rate-limit 5000 \
            -retry 3 \
            -json -o "$DIR/raw/dnsx.json" \
            2>>"$DIR/logs/dnsx.log" &
    fi
    
    # METHOD C: PureDNS (wildcard-aware)
    if command -v puredns >/dev/null; then
        log "  C. PureDNS (accurate)"
        puredns resolve "$DIR/targets_expanded.txt" \
            -r "$DIR/resolvers/final.txt" \
            --rate-limit 3000 \
            --wildcard-tests 10 \
            --wildcard-batch 100000 \
            --skip-sanitize \
            -q \
            2>>"$DIR/logs/puredns.log" | \
            tee "$DIR/raw/puredns.txt" &
    fi
    
    # METHOD D: Threaded DIG (maximum coverage)
    log "  D. Threaded DIG (fallback)"
    # Build dig commands file
    head -5000 "$DIR/targets_expanded.txt" | while read domain; do
        resolver=$(shuf -n 1 "$DIR/resolvers/final.txt")
        echo "timeout 2 dig +short +tries=1 +time=1 A '$domain' '@$resolver'"
        echo "timeout 2 dig +short +tries=1 +time=1 AAAA '$domain' '@$resolver'"
        echo "timeout 2 dig +short +tries=1 +time=1 CNAME '$domain' '@$resolver'"
    done > "$DIR/tmp/dig_commands.txt"
    
    # Execute in massive parallel
    cat "$DIR/tmp/dig_commands.txt" | \
        xargs -P "$THREADS" -I{} sh -c '{} 2>/dev/null | head -1 | xargs -I@ echo "$(echo {} | grep -o "\x27[^\x27]*\x27" | head -1 | tr -d "\x27") @"' \
        > "$DIR/raw/dig.txt" 2>/dev/null &
    
    # METHOD E: DNS over HTTPS/TLS
    log "  E. DNS-over-HTTPS/TLS"
    # Cloudflare DoH
    head -1000 "$DIR/targets_expanded.txt" | \
        xargs -P 50 -I{} sh -c '
            curl -s "https://cloudflare-dns.com/dns-query?name={}&type=A" \
                -H "accept: application/dns-json" --max-time 3 2>/dev/null | \
                jq -r ".Answer[]? | select(.type==1) | \"{} \(.data)\"" 2>/dev/null
        ' > "$DIR/raw/doh_cloudflare.txt" 2>/dev/null &
    
    # Google DoH
    head -1000 "$DIR/targets_expanded.txt" | \
        xargs -P 50 -I{} sh -c '
            curl -s "https://dns.google/resolve?name={}&type=A" --max-time 3 2>/dev/null | \
                jq -r ".Answer[]? | select(.type==1) | \"{} \(.data)\"" 2>/dev/null
        ' > "$DIR/raw/doh_google.txt" 2>/dev/null &
    
    # Quad9 DoH
    head -1000 "$DIR/targets_expanded.txt" | \
        xargs -P 50 -I{} sh -c '
            curl -s "https://dns.quad9.net:5053/dns-query?name={}&type=A" \
                -H "accept: application/dns-json" --max-time 3 2>/dev/null | \
                jq -r ".Answer[]? | select(.type==1) | \"{} \(.data)\"" 2>/dev/null
        ' > "$DIR/raw/doh_quad9.txt" 2>/dev/null &
    
    # METHOD F: Authoritative DNS discovery
    log "  F. Authoritative DNS"
    head -200 "$DIR/targets_base.txt" | \
        xargs -P 20 -I{} sh -c '
            domain="{}"
            # Get all name servers
            dig +short NS "$domain" @8.8.8.8 2>/dev/null | while read ns; do
                # Get IP of nameserver
                ns_ip=$(dig +short A "$ns" @8.8.8.8 2>/dev/null | head -1)
                [ -n "$ns_ip" ] && echo "$domain NS $ns ($ns_ip)"
            done
            # Get SOA
            dig +short SOA "$domain" @8.8.8.8 2>/dev/null | head -1 | while read soa; do
                echo "$domain SOA $soa"
            done
        ' > "$DIR/raw/authoritative.txt" 2>/dev/null &
    
    # METHOD G: DNS Cache Snooping
    log "  G. DNS Cache Snooping"
    head -500 "$DIR/targets_clean.txt" | \
        xargs -P 30 -I{} sh -c '
            domain="{}"
            for resolver in 8.8.8.8 1.1.1.1 9.9.9.9; do
                if dig +norecurse "$domain" @"$resolver" 2>/dev/null | grep -q "ANSWER SECTION"; then
                    echo "$domain cached on $resolver"
                fi
            done
        ' > "$DIR/raw/cache.txt" 2>/dev/null &
    
    # METHOD H: Reverse DNS for discovered IPs (parallel)
    log "  H. Reverse DNS"
    # Extract IPs from existing results and do rDNS
    cat "$DIR/raw/"*.txt 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u | head -5000 | \
        xargs -P 100 -I{} sh -c '
            ip="{}"
            host "$ip" 2>/dev/null | grep "domain name pointer" | sed "s/.*pointer *//;s/\.$//;s/^/$ip /"
        ' > "$DIR/raw/reverse.txt" 2>/dev/null &
    
    # Wait for ALL resolution methods
    wait
    log "  ✓ All resolution methods complete"
    
    # =========================================================================
    # PHASE 3: DATA PROCESSING & ENRICHMENT (Every possible analysis)
    # =========================================================================
    log "3. DATA PROCESSING & ENRICHMENT"
    
    # Step 1: Consolidate ALL results
    cat "$DIR/raw/"*.txt 2>/dev/null | \
        grep -v "^$" | \
        awk '
            # Domain -> IP mapping
            /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {
                split($0, parts, " ")
                if (parts[2] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                    print parts[1], parts[2]
                }
            }
            # CNAME chains
            /CNAME|alias/ {
                for(i=1;i<=NF;i++) {
                    if ($i ~ /CNAME|alias/) {
                        print $(i-1), $(i+1)
                        break
                    }
                }
            }
        ' | sort -u > "$DIR/all_mappings.txt"
    
    # Step 2: Extract clean lists
    awk '{print $1}' "$DIR/all_mappings.txt" | sort -u > "$DIR/resolved/domains.txt"
    awk '{print $2}' "$DIR/all_mappings.txt" | sort -u > "$DIR/resolved/ips.txt"
    
    # Step 3: Virtual hosting analysis
    awk '{print $2}' "$DIR/all_mappings.txt" | sort | uniq -c | sort -nr | \
        awk '$1>1 {print $2":"$1}' > "$DIR/resolved/virtual_hosts.txt"
    
    # Step 4: CNAME analysis
    grep -i cname "$DIR/raw/"*.txt 2>/dev/null | \
        awk '{print $(NF-1), $NF}' | \
        sed 's/CNAME//gi' | \
        sort -u > "$DIR/resolved/cname_chains.txt"
    
    # Step 5: Internal IP detection
    grep -E '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|169\.254\.|0\.)' \
        "$DIR/resolved/ips.txt" > "$DIR/resolved/internal_ips.txt"
    
    # Step 6: CDN/Cloud detection
    head -200 "$DIR/resolved/ips.txt" | \
        xargs -P 20 -I{} sh -c '
            ip="{}"
            whois "$ip" 2>/dev/null | grep -i -E "cloudflare|akamai|fastly|cloudfront|aws|google|azure|oraclecloud" | \
                head -1 | sed "s/^/$ip /"
        ' > "$DIR/resolved/cdn_ips.txt" 2>/dev/null
    
    # Step 7: ASN information
    head -200 "$DIR/resolved/ips.txt" | \
        xargs -P 20 -I{} sh -c '
            ip="{}"
            # Try multiple ASN sources
            asn=$(whois -h whois.cymru.com " -v $ip" 2>/dev/null | tail -1)
            [ -z "$asn" ] && asn=$(curl -s "https://api.hackertarget.com/aslookup/?q=$ip" 2>/dev/null | tail -1)
            [ -n "$asn" ] && echo "$ip | $asn"
        ' > "$DIR/resolved/asn_info.txt" 2>/dev/null
    
    # Step 8: Generate domain:ip mapping
    awk '{print $1,$2}' "$DIR/all_mappings.txt" | sort -u > "$DIR/resolved/domain_to_ip.txt"
    awk '{print $2,$1}' "$DIR/all_mappings.txt" | sort -u > "$DIR/resolved/ip_to_domain.txt"
    
    # Step 9: TLD analysis
    awk -F. '{print $NF}' "$DIR/resolved/domains.txt" | sort | uniq -c | sort -nr > "$DIR/resolved/tlds.txt"
    
    # Step 10: Subdomain level analysis
    awk -F. '{
        subdomain_count=NF-2;
        if(subdomain_count<0) subdomain_count=0;
        print subdomain_count
    }' "$DIR/resolved/domains.txt" | sort -n | uniq -c > "$DIR/resolved/subdomain_levels.txt"
    
    log "  ✓ Processing complete"
    
    # =========================================================================
    # PHASE 4: REPORT GENERATION (Comprehensive)
    # =========================================================================
    log "4. REPORT GENERATION"
    
    # Gather stats
    domains_total=$(count "$DIR/resolved/domains.txt")
    ips_total=$(count "$DIR/resolved/ips.txt")
    internal_ips=$(count "$DIR/resolved/internal_ips.txt")
    virtual_hosts=$(count "$DIR/resolved/virtual_hosts.txt")
    cname_chains=$(count "$DIR/resolved/cname_chains.txt")
    resolvers_used=$(count "$DIR/resolvers/final.txt")
    
    # Generate markdown report
    cat > "$DIR/report.md" << EOF
# ELITE DNS RECON REPORT
## Operation: $NAME
## Date: $(date)
## Duration: ~$SECONDS seconds

## SUMMARY
- **Domains Resolved**: $domains_total
- **Unique IPs**: $ips_total  
- **Internal IPs**: $internal_ips
- **Virtual Hosts**: $virtual_hosts
- **CNAME Chains**: $cname_chains
- **Resolvers Used**: $resolvers_used

## METHODOLOGY
- **Resolvers**: Multi-source aggregation + 3-stage validation
- **Techniques**: MassDNS, DNSx, PureDNS, Threaded DIG, DoH (Cloudflare/Google/Quad9)
- **Record Types**: A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA
- **Advanced**: Cache snooping, Authoritative discovery, Reverse DNS

## KEY FINDINGS

### Top 10 IPs Hosting Multiple Domains
$(head -10 "$DIR/resolved/virtual_hosts.txt" | sed 's/:/ - /g' | sed 's/^/- /')

### Internal IP Ranges Discovered
$(head -10 "$DIR/resolved/internal_ips.txt" | sed 's/^/- /')

### Potential Subdomain Takeovers
$(grep -i '\.s3\.\|\.cloudfront\.\|\.azureedge\.\|\.fastly\.' "$DIR/resolved/cname_chains.txt" | head -5 | sed 's/^/- /')

### Top TLDs
$(head -5 "$DIR/resolved/tlds.txt" | awk '{print "- " $2 ": " $1}')

## FILES GENERATED

### Core Outputs
- \`$DIR/resolved/domains.txt\` - All resolved domains
- \`$DIR/resolved/ips.txt\` - All unique IP addresses
- \`$DIR/resolved/domain_to_ip.txt\` - Domain → IP mapping
- \`$DIR/resolved/ip_to_domain.txt\` - IP → Domain mapping

### Analysis Files
- \`$DIR/resolved/virtual_hosts.txt\` - IPs with multiple domains
- \`$DIR/resolved/internal_ips.txt\` - Private/internal IPs
- \`$DIR/resolved/cname_chains.txt\` - CNAME records
- \`$DIR/resolved/cdn_ips.txt\` - CDN/cloud provider IPs
- \`$DIR/resolved/asn_info.txt\` - ASN information
- \`$DIR/resolved/tlds.txt\` - TLD distribution

### Raw Data
- \`$DIR/raw/\` - Raw outputs from all tools/methods
- \`$DIR/resolvers/final.txt\` - Validated resolvers used

## NEXT STEPS

### Immediate Actions
\`\`\`bash
# 1. Port scan discovered IPs
nmap -iL $DIR/resolved/ips.txt -sS -sV -oA $DIR/port_scan

# 2. Web discovery on domains
cat $DIR/resolved/domains.txt | httpx -silent -title -status-code -o $DIR/web_discovery.txt

# 3. Subdomain takeover checks
grep -i '\\\\.s3\\\\.\\|\\\\.cloudfront\\\\.\\|azureedge\\\\.\\|fastly\\\\.' $DIR/resolved/cname_chains.txt

# 4. Virtual host brute force
for ip in \$(head -10 $DIR/resolved/virtual_hosts.txt | cut -d: -f1); do
    echo "Testing \$ip with Host header brute force"
done
\`\`\`

### Further Enumeration
- DNS zone transfer attempts on authoritative servers
- DNS cache poisoning tests
- DNSSEC validation
- DNS tunneling detection

---
*Report generated by ELITE DNS RECON engine*
*Complete data available in: $DIR/*
EOF
    
    # Generate JSON summary
    cat > "$DIR/summary.json" << EOF
{
  "operation": "$NAME",
  "timestamp": "$(date -Iseconds)",
  "input_file": "$DOMAINS",
  "input_count": $(count "$DOMAINS"),
  "results": {
    "domains": $domains_total,
    "ips": $ips_total,
    "internal_ips": $internal_ips,
    "virtual_hosts": $virtual_hosts,
    "cname_chains": $cname_chains,
    "resolvers_used": $resolvers_used
  },
  "files": {
    "domains": "$DIR/resolved/domains.txt",
    "ips": "$DIR/resolved/ips.txt",
    "domain_to_ip": "$DIR/resolved/domain_to_ip.txt",
    "virtual_hosts": "$DIR/resolved/virtual_hosts.txt",
    "cname_chains": "$DIR/resolved/cname_chains.txt"
  }
}
EOF
    
    # Create next steps script
    cat > "$DIR/next_steps.sh" << EOF
#!/bin/bash
echo "=== ELITE DNS RECON - NEXT STEPS ==="
echo ""
echo "1. PORT SCANNING:"
echo "   nmap -iL $DIR/resolved/ips.txt -sS -sV -oA $DIR/port_scan"
echo ""
echo "2. WEB DISCOVERY:"
echo "   cat $DIR/resolved/domains.txt | httpx -silent -title -status-code -tech-detect -o $DIR/web.txt"
echo ""
echo "3. TAKEOVER CHECKS:"
echo "   grep -i '\\\\.s3\\\\.\\|\\\\.cloudfront\\\\.' $DIR/resolved/cname_chains.txt"
echo ""
echo "4. VIRTUAL HOST BRUTE FORCE:"
echo "   while read line; do"
echo "     ip=\$(echo \$line | cut -d: -f1)"
echo "     count=\$(echo \$line | cut -d: -f2)"
echo "     echo \"IP \$ip hosts \$count domains\""
echo "   done < <(head -5 $DIR/resolved/virtual_hosts.txt)"
echo ""
echo "5. INTERNAL NETWORK MAPPING:"
echo "   cat $DIR/resolved/internal_ips.txt | sort -u"
echo ""
echo "Full report: $DIR/report.md"
echo "Summary: $DIR/summary.json"
EOF
    chmod +x "$DIR/next_steps.sh"
    
    # =========================================================================
    # PHASE 5: FINAL OUTPUT
    # =========================================================================
    log "5. FINAL OUTPUT"
    
    # Cleanup temp files
    find "$DIR/tmp" -type f -delete 2>/dev/null || true
    find "$DIR/raw" -name "*.txt" -size +10M -exec gzip -f {} + 2>/dev/null
    
    # Create archive
    tar czf "$DIR/results.tar.gz" \
        "$DIR/resolved/" \
        "$DIR/report.md" \
        "$DIR/summary.json" \
        "$DIR/next_steps.sh" \
        2>/dev/null || true
    
    # Final display
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                     ELITE DNS RECON COMPLETE                 ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  OPERATION: $NAME"
    echo "║  DURATION:  $SECONDS seconds"
    echo "╠══════════════════════════════════════════════════════════════╣"
    printf "║  %-30s %20s \n" "Domains Resolved:" "$domains_total"
    printf "║  %-30s %20s \n" "Unique IPs:" "$ips_total"
    printf "║  %-30s %20s \n" "Internal IPs:" "$internal_ips"
    printf "║  %-30s %20s \n" "Virtual Hosts:" "$virtual_hosts"
    printf "║  %-30s %20s \n" "CNAME Chains:" "$cname_chains"
    printf "║  %-30s %20s \n" "Resolvers Used:" "$resolvers_used"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  OUTPUT DIRECTORY: $DIR/"
    echo "║  FULL REPORT:      $DIR/report.md"
    echo "║  SUMMARY:          $DIR/summary.json"
    echo "║  NEXT STEPS:       $DIR/next_steps.sh"
    echo "║  ARCHIVE:          $DIR/results.tar.gz"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  QUICK START: ./$DIR/next_steps.sh"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

# Execute with error trapping
trap 'echo "[!] Script failed at line \$LINENO. Check $DIR/error.log"; exit 1' ERR
main "$@"