#!/bin/bash

# Enhanced DNS Reconnaissance Script
# Version: 2.6
# Usage: ./dns_recon.sh <domains.txt> <output_directory>
# Features: 
# - Comprehensive DNS enumeration
# - Creates output file in specified directory
# - All results in single organized file

# Configuration
THREADS=5                    # Number of concurrent processes
TIMEOUT=10                   # DNS query timeout in seconds
RETRIES=2                    # Number of retry attempts
RESOLVERS_FILE="/usr/lib/python3/dist-packages/theHarvester/lib/resolvers.txt"  # DNS resolvers file
OUTPUT_DIR=""                # Will be set from parameter
OUTPUT_FILE=""               # Will be generated automatically

# Initialize script and validate parameters
init() {
    # Check for correct number of arguments
    if [ $# -ne 2 ]; then
        echo "Usage: $0 <domains.txt> <output_directory>"
        exit 1
    fi

    INPUT_FILE="$1"
    OUTPUT_DIR="$2"

    # Validate input file exists
    if [ ! -f "$INPUT_FILE" ]; then
        echo "Error: Input file $INPUT_FILE not found"
        exit 1
    fi

    # Create output directory if it doesn't exist
    output_dir=$(dirname "$OUTPUT_FILE")
    mkdir -p "$output_dir" || {
        echo "Error: Failed to create output directory"
        exit 1
    }

    # Set output filename with timestamp
    OUTPUT_FILE="${OUTPUT_DIR}/dns_recon_$(date +%Y%m%d_%H%M%S).txt"

    # Check for DNS resolvers file or download fresh ones
    if [ ! -f "$RESOLVERS_FILE" ]; then
        echo "Fetching public DNS resolvers..."
        curl -s https://public-dns.info/nameservers.txt -o "$RESOLVERS_FILE" 2>/dev/null || {
            echo "Error: Failed to get resolvers"
            exit 1
        }
    fi

    # Initialize output file with header
    echo "# DNS Reconnaissance Report" > "$OUTPUT_FILE"
    echo "# Generated: $(date)" >> "$OUTPUT_FILE"
    echo "# Resolvers: $(wc -l < "$RESOLVERS_FILE")" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
}

# Perform DNS query with retries and random resolver
dns_query() {
    local type=$1 domain=$2 resolver
    resolver=$(shuf -n 1 "$RESOLVERS_FILE")
    
    # Try query with timeout and retries
    for _ in $(seq $RETRIES); do
        result=$(dig +time=$TIMEOUT +tries=1 +nocookie +nocomments +noquestion +nostats \
            @"$resolver" "$domain" "$type" +short 2>/dev/null | grep -v '^$')
        [ -n "$result" ] && break
        sleep 1
    done
    
    echo "${result:-None}"  # Return results or "None" if empty
}

# Check all possible DNS record types
check_all_records() {
    local domain=$1
    echo "## All DNS Record Types for $domain" >> "$OUTPUT_FILE"
    
    # Test all common DNS record types
    for type in A AAAA MX TXT NS SOA CNAME PTR HINFO MINFO RP SIG KEY LOC SRV CERT DNSKEY DS NAPTR NSEC NSEC3 RRSIG; do
        results=$(dns_query "$type" "$domain")
        if [ "$results" != "None" ]; then
            echo "[$type]" >> "$OUTPUT_FILE"
            echo "$results" >> "$OUTPUT_FILE"
            echo "" >> "$OUTPUT_FILE"
        fi
    done
}

# Attempt DNS zone transfer (AXFR)
attempt_zone_transfer() {
    local domain=$1
    echo "## Zone Transfer Attempt for $domain" >> "$OUTPUT_FILE"
    
    nameservers=$(dns_query NS "$domain")
    if [ "$nameservers" = "None" ]; then
        echo "No nameservers found" >> "$OUTPUT_FILE"
        return
    fi
    
    for ns in $nameservers; do
        echo "### Trying $ns" >> "$OUTPUT_FILE"
        dig @"$ns" "$domain" AXFR +nocookie 2>/dev/null | grep -v '^;' >> "$OUTPUT_FILE" || \
            echo "Transfer failed" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    done
}

# Analyze DNSSEC configuration
analyze_dnssec() {
    local domain=$1
    echo "## DNSSEC Analysis for $domain" >> "$OUTPUT_FILE"
    
    echo "### DNSKEY Records" >> "$OUTPUT_FILE"
    dns_query DNSKEY "$domain" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    echo "### RRSIG Records" >> "$OUTPUT_FILE"
    dns_query RRSIG "$domain" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    echo "### DNSSEC Validation" >> "$OUTPUT_FILE"
    delv @"$(shuf -n 1 "$RESOLVERS_FILE")" "$domain" 2>/dev/null >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
}

# Enumerate subdomains using various techniques
enumerate_subdomains() {
    local domain=$1
    echo "## Subdomain Enumeration for $domain" >> "$OUTPUT_FILE"
    
    echo "### From NS Records" >> "$OUTPUT_FILE"
    dns_query NS "$domain" | sed 's/\.$//' >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    echo "### From MX Records" >> "$OUTPUT_FILE"
    dns_query MX "$domain" | awk '{print $2}' | sed 's/\.$//' >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    echo "### From Certificate Transparency" >> "$OUTPUT_FILE"
    curl -s "https://crt.sh/?q=%25.$domain&output=json" 2>/dev/null | \
        jq -r '.[].name_value' 2>/dev/null | sort -u >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
}

# Main DNS reconnaissance function for a single domain
perform_dns_recon() {
    local domain=$1
    
    echo "# Domain: $domain" >> "$OUTPUT_FILE"
    echo "## Basic Records" >> "$OUTPUT_FILE"
    echo "[A]" >> "$OUTPUT_FILE"; dns_query A "$domain" >> "$OUTPUT_FILE"; echo "" >> "$OUTPUT_FILE"
    echo "[AAAA]" >> "$OUTPUT_FILE"; dns_query AAAA "$domain" >> "$OUTPUT_FILE"; echo "" >> "$OUTPUT_FILE"
    echo "[MX]" >> "$OUTPUT_FILE"; dns_query MX "$domain" >> "$OUTPUT_FILE"; echo "" >> "$OUTPUT_FILE"
    echo "[TXT]" >> "$OUTPUT_FILE"; dns_query TXT "$domain" >> "$OUTPUT_FILE"; echo "" >> "$OUTPUT_FILE"
    echo "[NS]" >> "$OUTPUT_FILE"; dns_query NS "$domain" >> "$OUTPUT_FILE"; echo "" >> "$OUTPUT_FILE"
    echo "[SOA]" >> "$OUTPUT_FILE"; dns_query SOA "$domain" >> "$OUTPUT_FILE"; echo "" >> "$OUTPUT_FILE"
    
    # Advanced checks
    check_all_records "$domain"
    attempt_zone_transfer "$domain"
    analyze_dnssec "$domain"
    enumerate_subdomains "$domain"
    
    echo "## End of report for $domain" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    echo "----------------------------------------" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
}

# Main execution flow
main() {
    init "$@"
    
    echo "Starting DNS reconnaissance..."
    echo "Input file: $INPUT_FILE"
    echo "Output directory: $OUTPUT_DIR"
    echo "Output file: $OUTPUT_FILE"
    echo "Threads: $THREADS"
    echo ""
    
    # Process each domain in input file
    while IFS= read -r domain || [[ -n "$domain" ]]; do
        domain=$(echo "$domain" | tr -d '\r\n' | sed 's/^[[:blank:]]*//;s/[[:blank:]]*$//')
        [[ -z "$domain" ]] && continue
        [[ "$domain" =~ ^# ]] && continue
        
        echo "Processing domain: $domain"
        perform_dns_recon "$domain" &
        
        # Limit concurrent processes
        while [ $(jobs -r -p | wc -l) -ge $THREADS ]; do
            sleep 1
        done
    done < "$INPUT_FILE"
    
    wait
    
    echo ""
    echo "DNS reconnaissance completed."
    echo "Results saved to $OUTPUT_FILE"
}

# Start the script
main "$@"