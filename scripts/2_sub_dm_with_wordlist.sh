#!/bin/bash
# ELITE SUBDOMAIN ENUMERATOR with Wordlist
set -eo pipefail

# Config
NAME="${1:-recon}"
DOMAINS_FILE="${2:-domains.txt}"
WORDLIST="${3:-/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt}"
DIR="subs_${NAME}_$(date +%Y%m%d_%H%M%S)"
THREADS=250
TIMEOUT=10

# One-liner helpers
log() { echo "[$(date +%H:%M:%S)] $1"; }
count() { wc -l < "$1" 2>/dev/null || echo 0; }
exists() { command -v "$1" >/dev/null 2>&1; }

# Main
main() {
    echo "╔══════════════════════════════════════════════╗"
    echo "║   ELITE SUBDOMAIN ENUMERATION                ║"
    echo "║   With Wordlist Bruteforce                   ║"
    echo "╚══════════════════════════════════════════════╝"
    
    # Validate
    [[ -z "$DOMAINS_FILE" || ! -f "$DOMAINS_FILE" ]] && {
        echo "Usage: $0 <name> <domains_file> [wordlist]"
        echo "Example: $0 target targets.txt wordlist.txt"
        exit 1
    }
    
    [[ ! -f "$WORDLIST" ]] && {
        echo "[!] Wordlist not found: $WORDLIST"
        echo "Using built-in wordlist..."
        generate_wordlist
        WORDLIST="$DIR/wordlists/builtin.txt"
    }
    
    mkdir -p "$DIR"/{raw,results,logs,wordlists,tmp}
    
    # =====================================================================
    # PHASE 1: RESOLVER COLLECTION (One-liner optimized)
    # =====================================================================
    log "1. GATHERING RESOLVERS"
    
    # Fast resolver collection (parallel)
    (
        # Public sources
        curl -s "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" 2>/dev/null | \
            grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?$' | head -1000 &
        
        curl -s "https://public-dns.info/nameservers.txt" 2>/dev/null | head -1000 &
        
        # System
        awk '/nameserver/{print $2}' /etc/resolv.conf 2>/dev/null &
        
        # Trusted
        echo -e "8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n9.9.9.9\n208.67.222.222\n208.67.220.220" &
        
        wait
    ) | sort -u | head -5000 > "$DIR/resolvers_all.txt"
    
    # Fast validation
    log "  Validating..."
    head -1000 "$DIR/resolvers_all.txt" | \
        xargs -P 100 -I{} sh -c 'timeout 1 dig +short google.com @{} >/dev/null 2>&1 && echo {}' \
        > "$DIR/resolvers.txt" 2>/dev/null
    
    [[ -s "$DIR/resolvers.txt" ]] || echo -e "8.8.8.8\n1.1.1.1" > "$DIR/resolvers.txt"
    log "  ✓ Resolvers: $(count "$DIR/resolvers.txt")"
    
    # =====================================================================
    # PHASE 2: TARGET PREPARATION (One-liner)
    # =====================================================================
    log "2. PREPARING TARGETS"
    
    # Clean domains
    sed -E 's|^https?://||; s|/.*$||; s|^\*\.||; s|:.*$||' "$DOMAINS_FILE" | \
        grep -E '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$' | \
        grep -vE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
        sort -u > "$DIR/domains.txt"
    
    # Extract base domains for permutation
    awk -F. '{print $(NF-1)"."$NF}' "$DIR/domains.txt" | sort -u > "$DIR/base_domains.txt"
    
    # Generate permutations file for mass bruteforce
    log "  Generating permutations..."
    while read domain; do
        cat "$WORDLIST" | sed "s/^/$domain /"
    done < "$DIR/base_domains.txt" > "$DIR/permutations.txt"
    
    total_targets=$(( $(count "$DIR/base_domains.txt") * $(count "$WORDLIST") ))
    log "  ✓ Domains: $(count "$DIR/domains.txt") | Base: $(count "$DIR/base_domains.txt") | Total permutations: $total_targets"
    
    # =====================================================================
    # PHASE 3: MULTI-METHOD ENUMERATION (Ultimate Coverage)
    # =====================================================================
    log "3. ENUMERATION"
    
    # METHOD A: DNS BRUTEFORCE (Primary - Fastest)
    log "  A. MassDNS Bruteforce"
    
    # Use massdns if available
    if exists massdns; then
        massdns -r "$DIR/resolvers.txt" \
                -t A \
                -o S \
                -s 10000 \
                -w "$DIR/raw/massdns_brute.txt" \
                "$DIR/permutations.txt" \
                2>>"$DIR/logs/massdns.log" &
    else
        # Alternative: puredns
        if exists puredns; then
            puredns resolve "$WORDLIST" \
                -d "$DIR/base_domains.txt" \
                -r "$DIR/resolvers.txt" \
                --rate-limit 5000 \
                --wildcard-tests 5 \
                --write "$DIR/raw/puredns.txt" \
                --write-wildcards "$DIR/wildcards.txt" \
                2>>"$DIR/logs/puredns.log" &
        fi
    fi
    
    # METHOD B: DNSx Permutations
    log "  B. DNSx Permutations"
    if exists dnsx; then
        dnsx -dL "$DIR/base_domains.txt" \
            -w "$WORDLIST" \
            -r "$DIR/resolvers.txt" \
            -a -aaaa -cname \
            -rate-limit 3000 \
            -silent \
            -o "$DIR/raw/dnsx_permute.txt" \
            2>>"$DIR/logs/dnsx.log" &
    fi
    
    # METHOD C: Gobuster DNS
    log "  C. Gobuster DNS"
    if exists gobuster; then
        while read domain; do
            gobuster dns -d "$domain" \
                -w "$WORDLIST" \
                -r "$DIR/resolvers.txt" \
                -t "$THREADS" \
                -o "$DIR/raw/gobuster_${domain//./_}.txt" \
                2>>"$DIR/logs/gobuster.log" &
        done < <(head -20 "$DIR/base_domains.txt")
    fi
    
    # METHOD D: Threaded DIG Bruteforce (Universal)
    log "  D. Threaded DIG (Universal)"
    
    # Create dig commands file
    head -50000 "$DIR/permutations.txt" | while read sub domain; do
        resolver=$(shuf -n 1 "$DIR/resolvers.txt")
        echo "timeout 2 dig +short +tries=1 '$sub.$domain' '@$resolver' | grep -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 | xargs -I@ echo '$sub.$domain @'"
    done > "$DIR/tmp/dig_commands.txt"
    
    # Execute massively parallel
    cat "$DIR/tmp/dig_commands.txt" | \
        xargs -P "$THREADS" -I{} sh -c 'eval {}' 2>/dev/null \
        > "$DIR/raw/dig_brute.txt" &
    
    # METHOD E: Fierce-style enumeration (Smart)
    log "  E. Fierce-style (Smart)"
    if exists fierce; then
        while read domain; do
            fierce --domain "$domain" \
                --dns-file "$DIR/resolvers.txt" \
                --subdomain-file "$WORDLIST" \
                --traverse 5 \
                --wide 2>>"$DIR/logs/fierce.log" | \
                grep -E '^Found:' | cut -d' ' -f2- >> "$DIR/raw/fierce.txt" &
        done < <(head -10 "$DIR/base_domains.txt")
    fi
    
    # METHOD F: DNS Recon (Python)
    log "  F. DNS Recon"
    if exists dnsrecon; then
        while read domain; do
            dnsrecon -d "$domain" \
                -D "$WORDLIST" \
                -t brt \
                -j "$DIR/raw/dnsrecon_${domain//./_}.json" \
                2>>"$DIR/logs/dnsrecon.log" &
        done < <(head -10 "$DIR/base_domains.txt")
    fi
    
    # METHOD G: Alterations (Common patterns)
    log "  G. Alterations Generation"
    head -100 "$DIR/domains.txt" | while read domain; do
        # Common patterns
        for prefix in dev- test- stage- prod- api- admin- www- mail- ftp-; do
            echo "${prefix}${domain}"
        done
        # Number patterns
        for i in $(seq 1 5); do
            echo "web${i}.${domain}"
            echo "app${i}.${domain}"
            echo "${i}.${domain}"
        done
        # Common suffixes
        for suffix in -test -dev -stage -prod -api -admin; do
            echo "${domain}${suffix}"
        done
    done > "$DIR/raw/alterations.txt"
    
    # Resolve alterations
    if exists dnsx; then
        dnsx -l "$DIR/raw/alterations.txt" \
            -r "$DIR/resolvers.txt" \
            -silent \
            -o "$DIR/raw/alterations_resolved.txt" \
            2>/dev/null &
    fi
    
    # METHOD H: Certificate Transparency
    log "  H. Certificate Transparency"
    while read domain; do
        # crt.sh
        curl -s "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null | \
            jq -r '.[].name_value' 2>/dev/null | \
            sed 's/\*\.//g' | sort -u &
        
        # CertSpotter
        curl -s "https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names" 2>/dev/null | \
            jq -r '.[].dns_names[]' 2>/dev/null | \
            sed 's/"//g' | sort -u &
    done < "$DIR/base_domains.txt" > "$DIR/raw/cert_transparency.txt" 2>/dev/null &
    
    # METHOD I: Wayback Machine
    log "  I. Wayback Machine"
    if exists waybackurls; then
        cat "$DIR/base_domains.txt" | \
            waybackurls 2>/dev/null | \
            grep -oE "[a-zA-Z0-9._-]+\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | \
            sort -u > "$DIR/raw/wayback.txt" &
    fi
    
    # METHOD J: DNS Cache Snooping
    log "  J. DNS Cache Snooping"
    head -1000 "$DIR/permutations.txt" | while read sub domain; do
        for resolver in 8.8.8.8 1.1.1.1 9.9.9.9; do
            if dig +norecurse "${sub}.${domain}" @"$resolver" 2>/dev/null | grep -q "ANSWER SECTION"; then
                echo "${sub}.${domain} cached on $resolver"
            fi
        done
    done > "$DIR/raw/cache.txt" 2>/dev/null &
    
    wait
    log "  ✓ All enumeration methods complete"
    
    # =====================================================================
    # PHASE 4: DATA PROCESSING (One-liner optimized)
    # =====================================================================
    log "4. PROCESSING RESULTS"
    
    # Combine all results
    cat "$DIR/raw/"*.txt "$DIR/raw/"*.json 2>/dev/null | \
        tr ' ' '\n' | \
        grep -E '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$' | \
        grep -vE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
        sort -u > "$DIR/all_subdomains_raw.txt"
    
    # Filter valid subdomains for our target domains
    grep -F -f "$DIR/base_domains.txt" "$DIR/all_subdomains_raw.txt" | \
        sort -u > "$DIR/subdomains.txt"
    
    # Resolve discovered subdomains
    log "  Resolving discovered subdomains..."
    if exists dnsx; then
        dnsx -l "$DIR/subdomains.txt" \
            -r "$DIR/resolvers.txt" \
            -a -aaaa -cname \
            -silent \
            -json \
            -o "$DIR/results/resolved.json" \
            2>/dev/null
        
        # Extract from JSON
        jq -r 'select(.a or .aaaa or .cname) | "\(.host) \(.a//.aaaa//.cname)"' \
            "$DIR/results/resolved.json" 2>/dev/null > "$DIR/results/resolved.txt"
    else
        # Fallback dig
        head -5000 "$DIR/subdomains.txt" | \
            xargs -P 50 -I{} sh -c '
                resolver=$(shuf -n 1 "$DIR/resolvers.txt")
                ip=$(timeout 2 dig +short A "{}" @"$resolver" 2>/dev/null | head -1)
                [ -n "$ip" ] && echo "{} $ip"
            ' > "$DIR/results/resolved.txt" 2>/dev/null
    fi
    
    # Extract clean lists
    awk '{print $1}' "$DIR/results/resolved.txt" 2>/dev/null | sort -u > "$DIR/results/subdomains_final.txt"
    grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$DIR/results/resolved.txt" 2>/dev/null | sort -u > "$DIR/results/ips.txt"
    
    # Generate domain->ip mapping
    awk '/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1,$2}' "$DIR/results/resolved.txt" 2>/dev/null | sort -u > "$DIR/results/domain_ip.txt"
    
    # Virtual hosting analysis
    awk '{print $2}' "$DIR/results/domain_ip.txt" 2>/dev/null | sort | uniq -c | sort -nr | \
        awk '$1>1 {print $2":"$1}' > "$DIR/results/virtual_hosts.txt"
    
    # CNAME analysis
    grep -i cname "$DIR/raw/"*.txt 2>/dev/null | \
        awk '{print $(NF-1), $NF}' | \
        sort -u > "$DIR/results/cname_chains.txt"
    
    # Wildcard detection
    if [[ -f "$DIR/wildcards.txt" ]]; then
        cp "$DIR/wildcards.txt" "$DIR/results/wildcards.txt"
    fi
    
    log "  ✓ Subdomains: $(count "$DIR/results/subdomains_final.txt")"
    log "  ✓ IPs: $(count "$DIR/results/ips.txt")"
    
    # =====================================================================
    # PHASE 5: GENERATE REPORT
    # =====================================================================
    log "5. GENERATING REPORT"
    
    total_subs=$(count "$DIR/results/subdomains_final.txt")
    total_ips=$(count "$DIR/results/ips.txt")
    total_virtual=$(count "$DIR/results/virtual_hosts.txt")
    
    cat > "$DIR/report.md" << EOF
# ELITE SUBDOMAIN ENUMERATION REPORT
## Operation: $NAME
## Date: $(date)
## Wordlist: $WORDLIST ($(count "$WORDLIST") entries)

## SUMMARY
- **Total Subdomains Found**: $total_subs
- **Unique IPs**: $total_ips
- **Virtual Hosts**: $total_virtual
- **Resolvers Used**: $(count "$DIR/resolvers.txt")
- **Base Domains**: $(count "$DIR/base_domains.txt")

## METHODOLOGY
### Techniques Used:
1. **DNS Bruteforce** (MassDNS/DNSx)
2. **Permutations** (Wordlist × Domains)
3. **Certificate Transparency** (crt.sh, CertSpotter)
4. **Wayback Machine** (Historical DNS)
5. **Alterations** (Common patterns)
6. **Cache Snooping** (Public DNS caches)
7. **Multiple Tools** (Gobuster, Fierce, DNSRecon)

### Wordlist Stats:
- Entries: $(count "$WORDLIST")
- Permutations: $total_targets
- Coverage: $(echo "$total_subs $total_targets" | awk '{printf "%.4f%%", ($1/$2)*100}')

## TOP FINDINGS
### Most Common Subdomain Patterns:
$(awk -F. '{print $1}' "$DIR/results/subdomains_final.txt" 2>/dev/null | sort | uniq -c | sort -nr | head -10 | awk '{print "- " $2 ": " $1}')

### Top IPs (Virtual Hosting):
$(head -10 "$DIR/results/virtual_hosts.txt" | sed 's/:/ - /g' | sed 's/^/- /')

### Potential Takeover Targets:
$(grep -i '\.s3\.\|\.cloudfront\.\|\.azureedge\.' "$DIR/results/cname_chains.txt" 2>/dev/null | head -5 | sed 's/^/- /')

## FILES
### Core Results:
- \`$DIR/results/subdomains_final.txt\` - All discovered subdomains
- \`$DIR/results/ips.txt\` - Unique IP addresses
- \`$DIR/results/domain_ip.txt\` - Subdomain → IP mapping
- \`$DIR/results/resolved.json\` - Full DNS resolution data

### Analysis:
- \`$DIR/results/virtual_hosts.txt\` - IPs with multiple subdomains
- \`$DIR/results/cname_chains.txt\` - CNAME records
- \`$DIR/results/wildcards.txt\` - Wildcard DNS detected

### Raw Data:
- \`$DIR/raw/\` - Raw outputs from all tools
- \`$DIR/permutations.txt\` - Wordlist × domains combinations
- \`$DIR/resolvers.txt\` - Validated DNS resolvers

## NEXT STEPS
\`\`\`bash
# 1. HTTP Discovery
cat $DIR/results/subdomains_final.txt | httpx -silent -o $DIR/web_discovery.txt

# 2. Port Scanning
nmap -iL $DIR/results/ips.txt -sS -sV -oA $DIR/port_scan

# 3. Takeover Checks
grep -i '\\\\.s3\\\\.\\|\\\\.cloudfront\\\\.' $DIR/results/cname_chains.txt

# 4. Subdomain Bruteforce (Second Pass)
./subdomain_brute.sh $NAME $DIR/results/subdomains_final.txt $WORDLIST

# 5. Generate Visual Map
cat $DIR/results/domain_ip.txt | awk '{print \$2,\$1}' | sort > $DIR/network_map.txt
\`\`\`
EOF
    
    # Create next steps script
    cat > "$DIR/next.sh" << EOF
#!/bin/bash
echo "=== SUBDOMAIN ENUMERATION - NEXT STEPS ==="
echo ""
echo "1. HTTP DISCOVERY:"
echo "   cat $DIR/results/subdomains_final.txt | httpx -silent -title -status-code -o $DIR/web.txt"
echo ""
echo "2. PORT SCANNING:"
echo "   nmap -iL $DIR/results/ips.txt -sS -sV -p- -oA $DIR/nmap_scan"
echo ""
echo "3. TAKEOVER CHECK:"
echo "   grep -i '\\\\.s3\\\\.\\|\\\\.cloudfront\\\\.' $DIR/results/cname_chains.txt"
echo ""
echo "4. VISUALIZE:"
echo "   echo 'IP -> Subdomains:'"
echo "   sort $DIR/results/domain_ip.txt | awk '{print \$2}' | uniq -c | sort -nr | head -10"
echo ""
echo "Full report: $DIR/report.md"
EOF
    chmod +x "$DIR/next.sh"
    
    # =====================================================================
    # PHASE 6: FINAL OUTPUT
    # =====================================================================
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          SUBDOMAIN ENUMERATION COMPLETE                      ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    printf "║  %-35s %15s \n" "Subdomains Found:" "$total_subs"
    printf "║  %-35s %15s \n" "Unique IPs:" "$total_ips"
    printf "║  %-35s %15s \n" "Virtual Hosts:" "$total_virtual"
    printf "║  %-35s %15s \n" "Wordlist Entries:" "$(count "$WORDLIST")"
    printf "║  %-35s %15s \n" "Base Domains:" "$(count "$DIR/base_domains.txt")"
    printf "║  %-35s %15s \n" "Permutations Tested:" "$total_targets"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  OUTPUT: $DIR/"
    echo "║  REPORT: $DIR/report.md"
    echo "║  SUBDOMAINS: $DIR/results/subdomains_final.txt"
    echo "║  IPS: $DIR/results/ips.txt"
    echo "║  NEXT: ./$DIR/next.sh"
    echo "╚══════════════════════════════════════════════════════════════╝"
}

# Generate wordlist if none provided
generate_wordlist() {
    mkdir -p "$DIR/wordlists"
    cat > "$DIR/wordlists/builtin.txt" << 'EOF'
www
mail
ftp
admin
api
test
dev
stage
prod
portal
blog
web
app
mobile
m
beta
alpha
staging
demo
secure
vpn
owa
exchange
cpanel
whm
webmail
smtp
pop
imap
git
svn
jenkins
docker
kubernetes
monitor
status
dashboard
grafana
prometheus
elk
kibana
log
logs
backup
db
database
sql
mysql
mongo
redis
cache
cdn
assets
static
media
upload
download
cdn
cloud
aws
azure
gcp
s3
storage
bucket
repo
registry
npm
packages
docs
wiki
help
support
kb
knowledgebase
forum
community
chat
irc
slack
discord
status
monitor
alert
alerts
metrics
analytics
stats
statistics
report
reports
api-docs
swagger
openapi
graphql
rest
soap
rpc
grpc
EOF
}

# Run
trap 'echo "[!] Failed at line \$LINENO" > "$DIR/error.log" 2>/dev/null; exit 1' ERR
main "$@"