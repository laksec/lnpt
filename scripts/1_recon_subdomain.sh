#!/bin/bash

# Check arguments
[[ -z "$1" ]] || [[ -z "$2" ]] && { 
    echo "Usage: $0 <output_prefix> <domains_file> [wordlist]"; 
    echo "Example: $0 project_name domains_in_scope.txt subdomains.txt"; 
    exit 1; 
}

# Global variables
OUTPUT_DIR="0_${1}"
TARGET_FILE="$2"
WORDLIST="${3:-/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt}"
THREADS=50
DATE_TAG=$(date +%Y%m%d_%H%M%S)

# Create directory structure
# mkdir -p "${OUTPUT_DIR}/"{raw,filtered,resolved,live,dns,ports,takeover,reports}
for vl in 1_raw 2_filtered 3_dns 4_resolved 5_live 6_ports 7_takeover 8_reports; do
    mkdir -p ${OUTPUT_DIR}/$vl
done


# Setup log file
LOG_FILE="${OUTPUT_DIR}/enum_${DATE_TAG}.log"
exec 2>"${OUTPUT_DIR}/errors.log"

log() {
    echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# ============================================
# FUNCTION 1: SUBDOMAIN ENUMERATION
# ============================================

subdomain_enum() {
    local domains_file="$1"
    local output_dir="$2"
    
    log "Starting subdomain enumeration"
    
    # 1. Subfinder (one-liner)
    subfinder -dL "$domains_file" -all -silent -o "${output_dir}/1_raw/subfinder.txt" 2>/dev/null
    
    # 2. Assetfinder (one-liner per domain)
    while read -r domain; do 
        assetfinder --subs-only "$domain" 2>/dev/null; 
    done < "$domains_file" > "${output_dir}/1_raw/assetfinder.txt"
    
    # 3. Chaos (if available)
    [[ -x "$(command -v chaos)" ]] && chaos -dL "$domains_file" -silent -o "${output_dir}/1_raw/chaos.txt" 2>/dev/null
    
    # # 4. Amass (passive)
    # [[ -x "$(command -v amass)" ]] && amass enum -passive -df "$domains_file" -o "${output_dir}/1_raw/amass.txt" 2>/dev/null
    
    # 5. crt.sh queries (one-liner per domain)
    while read -r domain; do 
        curl -s "https://crt.sh/?q=%25.${domain}&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g'; 
    done < "$domains_file" | sort -u > "${output_dir}/1_raw/crtsh.txt"
    
    # 6. CertSpotter API
    while read -r domain; do 
        curl -s "https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' 2>/dev/null; 
    done < "$domains_file" | sort -u > "${output_dir}/1_raw/certspotter.txt"
    
    # 7. Wayback URLs
    [[ -x "$(command -v waybackurls)" ]] && while read -r domain; do 
        waybackurls "$domain" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.${domain}"; 
    done < "$domains_file" | sort -u > "${output_dir}/1_raw/wayback.txt"
    
    # 8. Bufferover API
    while read -r domain; do 
        curl -s "https://dns.bufferover.run/dns?q=.${domain}" | jq -r '.FDNS_A[],.RDNS[]' 2>/dev/null | cut -d',' -f2; 
        done < "$domains_file" | sort -u > "${output_dir}/1_raw/bufferover.txt"
    
    # 9. Sublist3r
    [[ -x "$(command -v sublist3r)" ]] && while read -r domain; do 
        sublist3r -d "$domain" -o "${output_dir}/1_raw/sublist3r_${domain}.txt" 2>/dev/null; 
    done < "$domains_file"
    
    # 10. Findomain
    [[ -x "$(command -v findomain)" ]] && findomain -f "$domains_file" -u "${output_dir}/1_raw/findomain.txt" 2>/dev/null
    
    # Combine all results
    cat "${output_dir}/1_raw/"*.txt 2>/dev/null | sort -u | grep -v "^\*\." | grep -E '^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+$' > "${output_dir}/2_filtered/all_subdomains.txt"
    
    log "Subdomain enumeration completed: $(wc -l < "${output_dir}/2_filtered/all_subdomains.txt") found"
}

# ============================================
# FUNCTION 2: BRUTEFORCE SUBDOMAINS
# ============================================

bruteforce_subs() {
    local domains_file="$1"
    local wordlist="$2"
    local output_dir="$3"
    
    local resolver_file="${3:-/usr/share/massdns/lists/resolvers.txt}"

    log "Starting subdomain bruteforce"
    
    [[ ! -f "$wordlist" ]] && { log "Wordlist not found: $wordlist"; return 1; }
    
    # MassDNS for fast bruteforce (one-liner)
    [[ -x "$(command -v massdns)" ]] && {
        while read -r domain; do
            cat "$wordlist" | sed "s/$/.${domain}/" | massdns -r "${resolver_file}" -t A -o S -w "${output_dir}/1_raw/massdns_${domain}.txt" 2>/dev/null
        done < "$domains_file"
        cat "${output_dir}/1_raw/massdns_"*.txt 2>/dev/null | grep -E " A " | awk '{print $1}' | sed 's/\.$//' | sort -u >> "${output_dir}/2_filtered/all_subdomains.txt"
    }
    
    # Pure DNS bruteforce (one-liner alternative)
    # while read -r domain; do
    #     cat "$wordlist" | xargs -I{} -P $THREADS sh -c 'host {}.'"$domain"' 2>/dev/null | grep "has address" | awk "{print \$1}"'
    # done < "$domains_file" >> "${output_dir}/2_filtered/bruteforce.txt"
    puredns bruteforce "${wordlist}" "${domains_file}" -r "${resolver_file}" -o "${output_dir}/2_filtered/bruteforce.txt"
    
    # Update combined list
    cat "${output_dir}/2_filtered/all_subdomains.txt" "${output_dir}/2_filtered/bruteforce.txt" 2>/dev/null | sort -u > "${output_dir}/2_filtered/all_subdomains_final.txt"
    mv "${output_dir}/2_filtered/all_subdomains_final.txt" "${output_dir}/2_filtered/all_subdomains.txt"
    
    log "Bruteforce completed"
}

# ============================================
# FUNCTION 3: DNS RESOLUTION
# ============================================
dns_resolve() {
    local subdomains_file="$1"
    local output_dir="$2"
    local resolver_file="${3:-/usr/share/massdns/lists/resolvers.txt}"
    
    log "DNS resolution started"
    
    # Create output dirs
    mkdir -p "${output_dir}/3_dns" "${output_dir}/4_resolved"
    
    # 1. MASS DNS - Fast A/AAAA/CNAME resolution (single command)
    [[ -f "$resolver_file" ]] && massdns -r "$resolver_file" -t A -o S -w "${output_dir}/3_dns/massdns_raw.txt" "$subdomains_file" 2>/dev/null
    
    # Parse massdns output
    [[ -f "${output_dir}/3_dns/massdns_raw.txt" ]] && {
        # Extract A records
        grep " A " "${output_dir}/3_dns/massdns_raw.txt" | awk '{print $1" A "$3}' | sed 's/\.$//' > "${output_dir}/3_dns/a_records.txt"
        
        # Extract CNAME records  
        grep " CNAME " "${output_dir}/3_dns/massdns_raw.txt" | awk '{print $1" CNAME "$3}' | sed 's/\.$//' > "${output_dir}/3_dns/cname_records.txt"
        
        # Extract AAAA records
        grep " AAAA " "${output_dir}/3_dns/massdns_raw.txt" | awk '{print $1" AAAA "$3}' | sed 's/\.$//' > "${output_dir}/3_dns/aaaa_records.txt"
    }
    
    # 2. PURE-DNS - Alternative for A records (single command)
    [[ -x "$(command -v puredns)" ]] && puredns resolve "$subdomains_file" -r "$resolver_file" --write "${output_dir}/3_dns/puredns_resolved.txt" 2>/dev/null
    
    # 3. DIG - Manual fallback (parallel processing)
    [[ ! -f "${output_dir}/3_dns/a_records.txt" ]] && cat "$subdomains_file" | xargs -P $THREADS -I{} dig +short A {} 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | awk '{print "{} A "$0}' > "${output_dir}/3_dns/a_records.txt"
    
    # 4. Extract unique IPs (single command)
    awk '{print $3}' "${output_dir}/3_dns/a_records.txt" 2>/dev/null | sort -u > "${output_dir}/4_resolved/ips.txt"
    
    # 5. Host-to-IP mapping (single command)
    awk '{if($3!="") ips[$1]=ips[$1]" "$3} END{for(h in ips) print h":"ips[h]}' "${output_dir}/3_dns/a_records.txt" 2>/dev/null | tr -s ' ' > "${output_dir}/4_resolved/host_ip_map.txt"
    
    # 6. DNS record counts (single command)
    echo "A: $(wc -l < "${output_dir}/3_dns/a_records.txt" 2>/dev/null || echo 0)" > "${output_dir}/3_dns/stats.txt"
    echo "CNAME: $(wc -l < "${output_dir}/3_dns/cname_records.txt" 2>/dev/null || echo 0)" >> "${output_dir}/3_dns/stats.txt"
    echo "AAAA: $(wc -l < "${output_dir}/3_dns/aaaa_records.txt" 2>/dev/null || echo 0)" >> "${output_dir}/3_dns/stats.txt"
    echo "Unique IPs: $(wc -l < "${output_dir}/4_resolved/ips.txt" 2>/dev/null || echo 0)" >> "${output_dir}/3_dns/stats.txt"
    
    log "DNS resolution completed: $(wc -l < "${output_dir}/4_resolved/ips.txt" 2>/dev/null || echo 0) IPs found"

    # # Resolve A records (standalone)
    # massdns -r "$resolver_file" -t A -o S "$domain_list" 2>/dev/null | grep " A " | awk '{print $1" "$3}' | sed 's/\.$//' > "$output_file"
    # # Resolve CNAME records (standalone)
    # cat "$domain_list" | xargs -P 50 -I{} dig +short CNAME {} 2>/dev/null | grep -v '^$' | awk '{print "{} "$0}' > "$output_file"
    # # Bulk resolve with puredns (standalone)
    # puredns resolve "$domain_list" -r "$resolver_file" --write "$output_file" 2>/dev/null
    # # Extract IPs from DNS results (standalone)
    # awk '{print $NF}' "$dns_file" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > "$output_file"
    # # Create host-to-IP mapping (standalone)
    # awk '{ips[$1]=ips[$1]" "$3} END{for(h in ips) print h":"ips[h]}' "$dns_file" | tr -s ' ' > "$output_file"
    # # Reverse DNS lookup (standalone)
    # cat "$ip_list" | xargs -P 30 -I{} sh -c 'host {} 2>/dev/null | grep "pointer" | awk "{print \$1\" -> \"\$NF}"' | sed 's/\.$//' > "$output_file"
    # # Check DNS delegation (standalone)
    # cat "$domain_list" | xargs -P 20 -I{} dig +short NS {} 2>/dev/null | sort -u > "$output_file"
    # # Get MX records (standalone)
    # cat "$domain_list" | xargs -P 20 -I{} dig +short MX {} 2>/dev/null | sort -u > "$output_file"
    # # Get TXT records (standalone)
    # cat "$domain_list" | xargs -P 20 -I{} dig +short TXT {} 2>/dev/null | grep -v '^$' > "$output_file"
    # # Fast parallel host resolution (standalone)
    # cat "$domain_list" | xargs -P 100 -I{} host {} 2>/dev/null > "$output_file"
}

# ============================================
# FUNCTION 4: LIVE HOSTS DETECTION
# ============================================

find_live_hosts() {
    local subdomains_file="$1"
    local output_dir="$2"
    local live_dir="${output_dir}/5_live"
    
    # Create directory and log start
    log "Starting live host discovery"
    
    # SINGLE COMMAND: httpx scan with all features, output to JSON for easy processing
    if command -v httpx &>/dev/null && command -v jq &>/dev/null; then
        # Modern approach with httpx and jq - fastest and most comprehensive
        httpx -l "$subdomains_file" -silent -sc -title -tech-detect -server -cdn -probe -json \
              -threads "${THREADS:-100}" -timeout 5 -rate-limit 200 \
              -ports 80,443,8080,8443,3000,8000,8888,9000,9001 \
              -o "${live_dir}/scan_results.json" 2>/dev/null
        
        # Process JSON results into all needed files (efficient single-pass)
        jq -r 'select(.status_code|tostring|match("^[2345]")) | 
               "\(.url) \(.status_code)"' "${live_dir}/scan_results.json" | sort > "${live_dir}/live_hosts_with_status.txt"
        
        # Extract individual files from the processed data
        grep "^http://" "${live_dir}/live_hosts_with_status.txt" > "${live_dir}/http_hosts.txt"
        grep "^https://" "${live_dir}/live_hosts_with_status.txt" > "${live_dir}/https_hosts.txt"
        cut -d' ' -f1 "${live_dir}/live_hosts_with_status.txt" | sort -u > "${live_dir}/all_live_hosts.txt"
        
        # Extract titles
        jq -r 'select(.status_code|tostring|match("^[2345]")) | 
               "\(.url) : \(.title // "No Title")"' "${live_dir}/scan_results.json" | grep -v "No Title" > "${live_dir}/page_titles.txt"
        
        # Extract technologies and server info
        jq -r 'select(.status_code|tostring|match("^[2345]")) | 
               .tech[]?' "${live_dir}/scan_results.json" 2>/dev/null | sort -u > "${live_dir}/technologies.txt"
        jq -r 'select(.status_code|tostring|match("^[2345]")) | 
               .webserver // empty' "${live_dir}/scan_results.json" 2>/dev/null | sort -u > "${live_dir}/server_info.txt"
        
        # Create hosts without protocol for tools that need just domains
        jq -r 'select(.status_code|tostring|match("^[2345]")) | 
               .host' "${live_dir}/scan_results.json" 2>/dev/null | sort -u > "${live_dir}/hosts_no_proto.txt"
        
        # Create comprehensive summary file
        jq -r 'select(.status_code|tostring|match("^[2345]")) | 
               "URL: \(.url)\nStatus: \(.status_code)\nTitle: \(.title // "N/A")\nServer: \(.webserver // "N/A")\nCDN: \(.cdn // "false")\nTech: \(.tech // [] | join(","))\n---"' \
               "${live_dir}/scan_results.json" > "${live_dir}/full_summary.txt"            
    fi
    
    # Final count and log
    local live_count=$(wc -l < "${live_dir}/all_live_hosts.txt" 2>/dev/null || echo 0)
    log "Live hosts discovered: ${live_count}"
    
    # Clean up if no results
    [[ ! -s "${live_dir}/all_live_hosts.txt" ]] && log "No live hosts found" && rm -f "${live_dir}"/*.txt
    
    return 0
}


# ============================================
# FUNCTION 5: PORT SCANNING
# ============================================
port_scan() {
    local ips_file="$1"
    local output_dir="$2"
    local ports_dir="${output_dir}/6_ports"
    
    mkdir -p "$ports_dir"
    log "Starting port scanning"
    
    # Fast comprehensive scan with naabu (primary)
    if command -v naabu &>/dev/null; then
        log "Running naabu scan (top 1000 ports)"
        naabu -list "$ips_file" -silent -top-ports 1000 -rate 1000 \
              -o "${ports_dir}/naabu_tcp.txt" 2>/dev/null
        
        # Additional scan for common web ports
        naabu -list "$ips_file" -silent -p 80,443,8080,8443,8888,9443 \
              -rate 2000 -o "${ports_dir}/naabu_web.txt" 2>/dev/null
    fi
    
    # Parallel nmap scans with better one-liner
    if command -v nmap &>/dev/null; then
        log "Running targeted nmap scans"
        
        # Single efficient nmap command for all IPs
        nmap -iL "$ips_file" -T4 --open --min-rate 1000 \
             -p 21-23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1723,3306,3389,5432,5900,5901,6379,8080,8443,8888,9000,9200,27017 \
             -oG "${ports_dir}/nmap_scan.gnmap" 2>/dev/null
        
        # Parse nmap output to consolidated file
        grep "Ports:" "${ports_dir}/nmap_scan.gnmap" 2>/dev/null | \
        awk -F"[\t ]" '{ip=$2; gsub(/\/.*?(,|$)/," ",$4); gsub(/Ports:/,"",$4); print ip ":" $4}' \
        > "${ports_dir}/open_ports_summary.txt"
        
        # Extract just open ports list
        grep -oP 'Ports: \K.*' "${ports_dir}/nmap_scan.gnmap" 2>/dev/null | \
        tr ',' '\n' | grep open | cut -d'/' -f1 | sort -nu > "${ports_dir}/all_open_ports.txt"
    fi
    
    # Merge and deduplicate results
    cat "${ports_dir}/"*.txt 2>/dev/null | grep -E '^[0-9]' | sort -uV > "${ports_dir}/combined_ports.txt"
    
    # Create IP:PORT format file for tools like httpx
    grep -E ':[0-9]+$' "${ports_dir}/combined_ports.txt" 2>/dev/null > "${ports_dir}/hosts_with_ports.txt"
    
    # Count results
    local count=$(wc -l < "${ports_dir}/hosts_with_ports.txt" 2>/dev/null | tr -d ' ')
    log "Port scanning completed. Found $count open ports"
}

# ============================================
# FUNCTION 6: REVERSE DNS LOOKUP
# ============================================
reverse_lookup() {
    local ips_file="$1"
    local output_file="${2}/3_dns/reverse_dns.txt"
    
    log "Starting reverse DNS lookups"
    
    # ELITE ONE-LINER: Use dig if available, otherwise fallback to host
    if command -v dig &>/dev/null; then
        # Using dig - most reliable and clean output
        xargs -P "${THREADS:-20}" -a "$ips_file" -I{} bash -c \
            'ptr=$(dig +time=2 +short -x {} 2>/dev/null | sed "s/\.$//"); \
             [[ -n "$ptr" ]] && echo "{} -> $ptr"' > "$output_file"
    else
        # Fallback to host command
        xargs -P "${THREADS:-20}" -a "$ips_file" -I{} bash -c \
            'host {} 2>/dev/null | grep -oP "pointer \K.*(?=\.$)" | \
             xargs -r -I@ echo "{} -> @"' > "$output_file"
    fi
    
    # Clean up and count results
    sed -i '/^$/d' "$output_file" 2>/dev/null
    sort -u "$output_file" -o "$output_file" 2>/dev/null
    local count=$(wc -l < "$output_file" 2>/dev/null | tr -d ' ')
    
    log "Reverse DNS completed. Found $count PTR records"
    # PTR lookups (one-liner)
    # cat "$ips_file" | xargs -I{} -P $THREADS sh -c 'host {} 2>/dev/null | grep "domain name pointer" | while read line; do echo "{} -> $(echo "$line" | awk "{print \$NF}" | sed "s/\.$//")"; done' > "${output_dir}/3_dns/reverse_dns.txt"
}

# ============================================
# FUNCTION 7: TAKEOVER DETECTION
# ============================================
check_takeover() {
    [[ -f "$1" ]] || return
    mkdir -p "${2}/7_takeover"
    
    grep -hiE '(github\.io|\.?s3[\.-]|cloudfront\.net|azurewebsites\.net|herokuapp\.com|\.firebaseapp\.com|\.surge\.sh|readme\.io|uservoice\.com|statuspage\.io)' "$1" | \
    awk '!a[tolower($0)]++' | sort > "${2}/7_takeover/takeovers.txt"
    
    [[ -s "${2}/7_takeover/takeovers.txt" ]] && \
    log "Takeovers found: $(wc -l < "${2}/7_takeover/takeovers.txt")"
}

# ============================================
# FUNCTION 8: DNS ZONE TRANSFER
# ============================================
dns_zone_transfer() {
    local domains_file="$1"
    local output_dir="${2}/3_dns"
    
    mkdir -p "$output_dir"
    log "Starting DNS zone transfer attempts"
    
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        echo "[*] Testing: $domain"
        
        ns_list=$(dig +short NS "$domain" 2>/dev/null | sort -u)
        [[ -z "$ns_list" ]] && continue
        
        # Clear temp file first
        > "${output_dir}/axfr_${domain//./_}.tmp"
        
        echo "$ns_list" | xargs -P "${THREADS:-10}" -I{} bash -c '
            ns="$1"; dom="$2"
            output=$(dig @"$ns" "$dom" AXFR +noall +answer +tries=1 +time=3 2>/dev/null)
            if echo "$output" | grep -qE "^[a-zA-Z0-9]"; then
                echo "[+] SUCCESS: $dom from $ns" >&2
                echo "$output" | grep -E "^[a-zA-Z0-9]" | awk -v ns="$ns" "{print \$0 \" # NS:\" ns}"
            fi
        '\' _ {} "$domain"
        
        # Check if we got results (redirect stderr to stdout to capture success messages too)
        echo "$ns_list" | xargs -P "${THREADS:-10}" -I{} bash -c '
            ns="$1"; dom="$2"
            dig @"$ns" "$dom" AXFR +noall +answer +tries=1 +time=3 2>/dev/null | \
            grep -E "^[a-zA-Z0-9]" | awk -v ns="$ns" "{print \$0 \" # NS:\" ns}"
        '\' _ {} "$domain" > "${output_dir}/axfr_${domain//./_}.tmp" 2>/dev/null
        
        if [[ -s "${output_dir}/axfr_${domain//./_}.tmp" ]]; then
            mv "${output_dir}/axfr_${domain//./_}.tmp" "${output_dir}/axfr_${domain//./_}.txt"
            echo "[+] Zone transfer successful for $domain"
        else
            rm -f "${output_dir}/axfr_${domain//./_}.tmp"
        fi
    done < "$domains_file"
    
    success_count=$(find "$output_dir" -name "axfr_*.txt" -type f -size +0 2>/dev/null | wc -l)
    log "Zone transfers completed. Successful: $success_count"
}

# ============================================
# FUNCTION 9: GENERATE REPORTS
# ============================================

generate_reports() {
    local output_dir="$1"
    
    log "Generating reports"
    
    # Summary report (one-liner sections)
    echo "# Subdomain Enumeration Report" > "${output_dir}/8_reports/summary.md"
    echo "Generated: $(date)" >> "${output_dir}/8_reports/summary.md"
    echo "## Statistics" >> "${output_dir}/8_reports/summary.md"
    echo "- Total subdomains: $(wc -l < "${output_dir}/2_filtered/all_subdomains.txt" 2>/dev/null || echo 0)" >> "${output_dir}/8_reports/summary.md"
    echo "- Resolved IPs: $(wc -l < "${output_dir}/4_resolved/all_ips.txt" 2>/dev/null || echo 0)" >> "${output_dir}/8_reports/summary.md"
    echo "- Live hosts: $(wc -l < "${output_dir}/5_live/all_live_hosts.txt" 2>/dev/null || echo 0)" >> "${output_dir}/8_reports/summary.md"
    echo "- HTTP hosts: $(wc -l < "${output_dir}/5_live/http_hosts.txt" 2>/dev/null || echo 0)" >> "${output_dir}/8_reports/summary.md"
    echo "- HTTPS hosts: $(wc -l < "${output_dir}/5_live/https_hosts.txt" 2>/dev/null || echo 0)" >> "${output_dir}/8_reports/summary.md"
    
    # CSV export (one-liner)
    echo "subdomain,ip,is_live,http_status,https_status" > "${output_dir}/8_reports/subdomains.csv"
    while read -r sub; do
        ip=$(grep "^$sub A " "${output_dir}/3_dns/a_records.txt" 2>/dev/null | head -1 | awk '{print $3}')
        live=$(grep -c "^$sub$" "${output_dir}/5_live/all_live_hosts.txt" 2>/dev/null)
        http_status=$(grep "^$sub http" "${output_dir}/5_live/http_hosts.txt" 2>/dev/null | head -1 | awk '{print $3}')
        https_status=$(grep "^$sub https" "${output_dir}/5_live/https_hosts.txt" 2>/dev/null | head -1 | awk '{print $3}')
        echo "\"$sub\",\"$ip\",\"$live\",\"$http_status\",\"$https_status\"" >> "${output_dir}/8_reports/subdomains.csv"
    done < "${output_dir}/2_filtered/all_subdomains.txt"
    
    # Top subdomains by level (one-liner)
    cat "${output_dir}/2_filtered/all_subdomains.txt" | awk -F. '{print $(NF-2)"."$(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head -20 > "${output_dir}/8_reports/top_subdomains.txt"
    
    log "Reports generated in ${output_dir}/8_reports/"
}

# ============================================
# FUNCTION 10: CLEAN AND VALIDATE
# ============================================

clean_and_validate() {
    local input_file="$1"
    local output_file="$2"
    
    log "Cleaning and validating subdomains"
    
    # Remove wildcards, invalid chars, and sort (one-liner)
    cat "$input_file" 2>/dev/null | grep -v "^\*\." | grep -E '^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+$' | sed 's/^\.//;s/\.$//' | sort -u > "$output_file"
    
    log "Cleaned: $(wc -l < "$output_file") valid subdomains"
}

# ============================================
# MAIN EXECUTION
# ============================================

main() {
    log "Starting subdomain enumeration pipeline"
    log "Output directory: $OUTPUT_DIR"
    log "Target domains: $(wc -l < "$TARGET_FILE")"
    
    # Clean target file
    dos2unix "$TARGET_FILE" 2>/dev/null
    
    # Step 1: Subdomain enumeration
    subdomain_enum "$TARGET_FILE" "$OUTPUT_DIR"
    
    # Step 2: Bruteforce (if wordlist provided)
    [[ -f "$WORDLIST" ]] && bruteforce_subs "$TARGET_FILE" "$WORDLIST" "$OUTPUT_DIR"
    
    # Step 3: Clean results
    clean_and_validate "${OUTPUT_DIR}/2_filtered/all_subdomains.txt" "${OUTPUT_DIR}/2_filtered/clean_subdomains.txt"
    mv "${OUTPUT_DIR}/2_filtered/clean_subdomains.txt" "${OUTPUT_DIR}/2_filtered/all_subdomains.txt"
    
    # Step 4: DNS resolution
    dns_resolve "${OUTPUT_DIR}/2_filtered/all_subdomains.txt" "$OUTPUT_DIR"
    
    # Step 5: Live hosts
    find_live_hosts "${OUTPUT_DIR}/2_filtered/all_subdomains.txt" "$OUTPUT_DIR"
    
    # Step 6: Reverse DNS
    [[ -f "${OUTPUT_DIR}/4_resolved/all_ips.txt" ]] && reverse_lookup "${OUTPUT_DIR}/4_resolved/all_ips.txt" "$OUTPUT_DIR"
    
    # Step 7: Port scanning
    [[ -f "${OUTPUT_DIR}/4_resolved/all_ips.txt" ]] && port_scan "${OUTPUT_DIR}/4_resolved/all_ips.txt" "$OUTPUT_DIR"
    
    # Step 8: Takeover detection
    [[ -f "${OUTPUT_DIR}/3_dns/cname_records.txt" ]] && check_takeover "${OUTPUT_DIR}/3_dns/cname_records.txt" "$OUTPUT_DIR"
    
    # Step 9: DNS zone transfer
    dns_zone_transfer "$TARGET_FILE" "$OUTPUT_DIR"
    
    # Step 10: Generate reports
    generate_reports "$OUTPUT_DIR"
    
    # Final summary
    log "========================================"
    log "ENUMERATION COMPLETE"
    log "Total subdomains: $(wc -l < "${OUTPUT_DIR}/2_filtered/all_subdomains.txt" 2>/dev/null || echo 0)"
    log "Live hosts: $(wc -l < "${OUTPUT_DIR}/5_live/all_live_hosts.txt" 2>/dev/null || echo 0)"
    log "Unique IPs: $(wc -l < "${OUTPUT_DIR}/4_resolved/all_ips.txt" 2>/dev/null || echo 0)"
    log "Reports: ${OUTPUT_DIR}/8_reports/"
    log "========================================"
}

# Run main function
main