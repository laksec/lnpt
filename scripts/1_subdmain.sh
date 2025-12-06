#!/bin/bash

# Check if both arguments are provided
# [[ -z "$1" ]] || [[ -z "$2" ]] || [[ -z "$3" ]] && { 
[[ -z "$1" ]] || [[ -z "$2" ]] && { 
    echo "Usage: $0 <out_file_name> <domain_file> <wordlist>"; 
    echo "Example: $0 wildcard_subdomains domains.txt wordlist.txt"; 
    exit 1; 
}

# Setup
echo "Subdomain Enum Started:  $(date '+%A, %B %d, %Y %H:%M:%S')" >> "${INFO}"

# for vl in $(seq 0 2); do mkdir -p "${OUTPUT}/0$vl"; done
OUTPUT="0_$1"
mkdir -p "${OUTPUT_DIR}"

TARGET="${OUTPUT}/0_target"
INFO="${OUTPUT}/0_init"

# Copy and convert domain file
cp "${2}" "${TARGET}" && dos2unix "${TARGET}"

echo "Processing $(wc -l < "${TARGET}") assets from $TARGET"
echo

echo "[*] Starting multi-domain enumeration"
echo "[*] LAYER 00: Collecting raw tool outputs..."

# 1. Subfinder
echo "  [-] Running Subfinder..."
subfinder -dL "${TARGET}" -all -silent -o "${OUTPUT}/1_subfinder"

# 2. Assetfinder  
echo "  [-] Running Assetfinder..."
    while read dm; do assetfinder --subs-only "$dm" 2>/dev/null; 
done < "${TARGET}" > "${OUTPUT}/1_assetfinder"

# 3. Chaos
echo "  [-] Running Chaos..."
chaos-client -dL "${TARGET}" -silent -o "${OUTPUT}/1_chaos"

# 4. crt.sh
echo "  [-] Querying crt.sh..."
while read dm; 
    do curl -s "https://crt.sh/?q=%25.$dm&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g';
done < "${TARGET}" | sort -u | tee "${OUTPUT}/1_crtsh"

# 5. CertSpotter
echo "  [-] Querying CertSpotter..."
while read dm; 
    do curl -s "https://api.certspotter.com/v1/issuances?domain=$dm&include_subdomains=true&expand=dns_names" 2>/dev/null | jq -r '.[].dns_names[]' 2>/dev/null | sed 's/"//g'; 
done < "${TARGET}" | sort -u > "${OUTPUT}/1_certspotter"

# 6. Wayback Machine
echo "  [-] Querying Wayback Machine..."
while read dm; 
    do waybackurls "$dm" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$dm"; 
done < "${TARGET}" | sort -u > "${OUTPUT}/1_wayback"

echo "[+] LAYER 00 complete - Individual tool outputs stored in ${OUTPUT}/"

# Process raw domains
echo "[*] LAYER 00: Processing raw domains..."
RAW_LIST="${OUTPUT}/2_raw_domains"
RAW_NWC="${OUTPUT}/2_domains"

cat "${OUTPUT}/"1_* 2>/dev/null | sort -u | uniq | tee "${RAW_LIST}"

# Count raw subdomains per domain
echo "# Raw subdomain counts per domain" >> "${INFO}"
while read dm; 
    do count=$(grep -c "$dm$" "${RAW_LIST}"); echo "$dm: $count" >> "${INFO}"; 
done < "${TARGET}"

# Filter valid subdomain patterns
echo "[*] Filtering valid subdomains..."
grep -v "^\*\." "${RAW_LIST}" | grep -E '^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+$' | sort -u > "${RAW_NWC}"

echo "[+] LAYER 01 complete - Valid domains stored in ${OUTPUT}/01/"
echo "[*] Found $(wc -l < "${RAW_NWC}") unique valid subdomains"

echo "Subdomain Enum Completed:  $(date '+%A, %B %d, %Y %H:%M:%S')" >> "${INFO}"
