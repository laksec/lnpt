#!/bin/bash

# Enhanced Wildcard Subdomain Enumeration Script
# Version: 5.2
# Usage: ./subdomain_enum.sh <project_path> <input_file>
# Features:
# - Focused wildcard enumeration
# - Robust DNS resolver handling
# - Clean text output organization
# - Efficient parallel processing

# Configuration
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
RESOLVERS_FILE="/usr/share/seclists/Miscellaneous/dns-resolvers.txt"
ALT_WORDLIST="/usr/share/seclists/Discovery/DNS/namelist.txt"
THREADS=50
TIMEOUT=15
RATE_LIMIT=300
WILDCARD_DIR="wildcard"

# Initialize with basic checks
init() {
    [[ $# -ne 2 ]] && { echo "Usage: $0 <project_path> <input_file>"; exit 1; }

    PROJECT_PATH="$1"
    INPUT_FILE="$2"
    INFO_DIR="$PROJECT_PATH/info"
    OUT_DIR="$PROJECT_PATH/out"
    WILDCARD_OUT_DIR="$OUT_DIR/$WILDCARD_DIR"
    
    mkdir -p "$WILDCARD_OUT_DIR" || { echo "[-] Failed to create output dir"; exit 1; }

    INPUT_PATH="$INFO_DIR/$INPUT_FILE"
    [[ ! -f "$INPUT_PATH" ]] && { echo "[-] Input file not found"; exit 1; }

    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUTPUT_FILE="$WILDCARD_OUT_DIR/subdomains_$TIMESTAMP.txt"
    RESOLVED_FILE="$WILDCARD_OUT_DIR/resolved_$TIMESTAMP.txt"
    TEMP_DIR=$(mktemp -d)
}

# Robust DNS resolver acquisition
get_resolvers() {
    declare -a sources=(
        "https://public-dns.info/nameservers.txt"
        "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
    )

    for source in "${sources[@]}"; do
        if curl -s --connect-timeout 10 "$source" | \
           grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' > "$RESOLVERS_FILE"; then
            [[ $(wc -l < "$RESOLVERS_FILE") -ge 50 ]] && return 0
        fi
    done

    # Fallback to local resolvers
    grep -E '^nameserver\s+' /etc/resolv.conf | awk '{print $2}' > "$RESOLVERS_FILE"
    [[ -s "$RESOLVERS_FILE" ]] || { echo "[-] No resolvers available"; exit 1; }
}

# Wildcard expansion with pattern preservation
expand_wildcard() {
    local wildcard="$1"
    [[ "$wildcard" == *"*"* ]] && echo "${wildcard#\*}" | sed 's/^\.//;s/\*\.//g' || echo "$wildcard"
}

# Parallel passive enumeration
passive_enum() {
    local wildcard="$1" domain="$2"
    (
        subfinder -d "$domain" -silent 
        assetfinder --subs-only "$domain"
        findomain -t "$domain" -q
        amass enum -passive -d "$domain"
    ) | sed "s/^\([^.]*\)\./\\1.${wildcard/\*/}/" | sort -u
}

# Active enumeration with wildcard handling
active_enum() {
    local wildcard="$1" domain="$2"
    local wordlist="$TEMP_DIR/wordlist_${wildcard//\*/_}.txt"
    
    # Prepare wordlist with wildcard pattern
    cat "$WORDLIST" "$ALT_WORDLIST" 2>/dev/null | sort -u | \
        sed "s/$/.${wildcard/\*/.}/" > "$wordlist"
    
    # Resolve with wildcard detection
    puredns resolve "$wordlist" -r "$RESOLVERS_FILE" \
        --wildcard-tests 10 --rate-limit "$RATE_LIMIT" -q | \
        awk '{print $1}' | sed 's/\.$//' | sort -u
    
    rm "$wordlist"
}

# Process each wildcard domain
process_wildcard() {
    local wildcard="$1"
    local domain=$(expand_wildcard "$wildcard")
    local output="$TEMP_DIR/${wildcard//\*/_}.txt"
    
    echo "[*] Processing: $wildcard"
    
    # Run enumerations in parallel
    passive_enum "$wildcard" "$domain" > "$output.passive" &
    active_enum "$wildcard" "$domain" > "$output.active" &
    wait
    
    # Combine and resolve results
    cat "$output.passive" "$output.active" | sort -u | \
        puredns resolve -r "$RESOLVERS_FILE" -q 2>/dev/null | \
        awk '{print $1}' | sed 's/\.$//' | sort -u > "$output.resolved"
    
    # Save to main output
    echo -e "\n# $wildcard" >> "$OUTPUT_FILE"
    cat "$output.resolved" >> "$OUTPUT_FILE"
    
    # Cleanup
    rm "$output".{passive,active,resolved}
}

main() {
    init "$@"
    echo "[+] Starting enumeration - $(date)"
    get_resolvers
    
    # Process all wildcards
    while read -r wildcard; do
        [[ -z "$wildcard" || "$wildcard" =~ ^# ]] && continue
        process_wildcard "$wildcard" &
        
        # Limit concurrent processes
        while (( $(jobs -r | wc -l) >= THREADS )); do sleep 1; done
    done < "$INPUT_PATH"
    wait
    
    # Finalize output
    sort -u "$OUTPUT_FILE" -o "$OUTPUT_FILE"
    echo -e "\n# Completed: $(date)" >> "$OUTPUT_FILE"
    echo "[+] Found $(grep -vc '^#' "$OUTPUT_FILE") subdomains"
    echo "[+] Results saved to $OUTPUT_FILE"
}

main "$@"