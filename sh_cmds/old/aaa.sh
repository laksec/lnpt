#!/bin/bash

# Advanced Search Engine Discovery and Reconnaissance Script
# Usage: ./recon.sh domains.txt
# Output: Creates directory with individual domain files containing recon data

# Configuration
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
DELAY_BETWEEN_REQUESTS=2  # seconds to avoid rate limiting
MAX_THREADS=5             # concurrent processes
TIMEOUT=10                # seconds for curl requests

# Create output directory with timestamp
OUTPUT_DIR="recon_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

# Check if input file exists
if [ ! -f "$1" ]; then
    echo "Error: Input file $1 not found!"
    echo "Usage: $0 domains.txt"
    exit 1
fi

# Function to perform recon on a single domain
perform_recon() {
    local domain=$1
    local output_file="${OUTPUT_DIR}/${domain}_recon.txt"
    
    echo "====================================================================" > "$output_file"
    echo "Reconnaissance Report for: $domain" >> "$output_file"
    echo "Start Time: $(date)" >> "$output_file"
    echo "====================================================================" >> "$output_file"
    
    # 1. Basic DNS Recon
    echo -e "\n[+] DNS Information:\n" >> "$output_file"
    {
        echo "A Records:"
        dig +short "$domain" A | grep -v '^$' || echo "None found"
        echo -e "\nMX Records:"
        dig +short "$domain" MX | grep -v '^$' || echo "None found"
        echo -e "\nTXT Records:"
        dig +short "$domain" TXT | grep -v '^$' || echo "None found"
        echo -e "\nNS Records:"
        dig +short "$domain" NS | grep -v '^$' || echo "None found"
    } >> "$output_file"
    
    # 2. Google Dorking Simulation
    echo -e "\n[+] Google Dorking Results (Simulated):\n" >> "$output_file"
    {
        echo "Site: $domain"
        echo "Potential index of directories:"
        curl -s -A "$USER_AGENT" -L --connect-timeout $TIMEOUT "https://www.google.com/search?q=site:$domain+intitle:index.of" | grep -Eo "https?://[^'\"]+" | grep "$domain" | sort -u || echo "None found"
        
        echo -e "\nPotential configuration files:"
        curl -s -A "$USER_AGENT" -L --connect-timeout $TIMEOUT "https://www.google.com/search?q=site:$domain+ext:xml+|+ext:conf+|+ext:cnf+|+ext:reg+|+ext:inf+|+ext:rdp+|+ext:cfg+|+ext:txt+|+ext:ora+|+ext:ini" | grep -Eo "https?://[^'\"]+" | grep "$domain" | sort -u || echo "None found"
        
        echo -e "\nPotential database files:"
        curl -s -A "$USER_AGENT" -L --connect-timeout $TIMEOUT "https://www.google.com/search?q=site:$domain+ext:sql+|+ext:dbf+|+ext:mdb" | grep -Eo "https?://[^'\"]+" | grep "$domain" | sort -u || echo "None found"
    } >> "$output_file"
    
    # 3. Check common files and directories
    echo -e "\n[+] Common Files and Directories Check:\n" >> "$output_file"
    {
        common_files=("/robots.txt" "/.git/HEAD" "/.env" "/.htaccess" "/.well-known/security.txt" "/phpinfo.php" "/test.php")
        for path in "${common_files[@]}"; do
            url="https://$domain$path"
            echo -n "Checking $url... "
            status=$(curl -s -A "$USER_AGENT" -L -o /dev/null -w "%{http_code}" --connect-timeout $TIMEOUT "$url")
            if [ "$status" -eq 200 ]; then
                echo "FOUND (200)" >> "$output_file"
                echo "Content:" >> "$output_file"
                curl -s -A "$USER_AGENT" -L --connect-timeout $TIMEOUT "$url" | head -n 20 >> "$output_file"
                echo -e "\n" >> "$output_file"
            else
                echo "Not found ($status)" >> "$output_file"
            fi
        done
    } >> "$output_file"
    
    # 4. Check for subdomains using crt.sh
    echo -e "\n[+] Subdomains from crt.sh:\n" >> "$output_file"
    curl -s -A "$USER_AGENT" "https://crt.sh/?q=%25.$domain" | grep -Eo "[a-zA-Z0-9.-]+\.$domain" | sort -u >> "$output_file" || echo "None found" >> "$output_file"
    
    # 5. Check Wayback Machine URLs
    echo -e "\n[+] Wayback Machine URLs:\n" >> "$output_file"
    curl -s -A "$USER_AGENT" "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" | sort -u >> "$output_file" || echo "None found" >> "$output_file"
    
    # 6. Check security headers
    echo -e "\n[+] Security Headers:\n" >> "$output_file"
    curl -s -A "$USER_AGENT" -I -L "https://$domain" --connect-timeout $TIMEOUT | grep -E "Strict-Transport-Security:|X-Frame-Options:|X-Content-Type-Options:|Content-Security-Policy:|X-XSS-Protection:" >> "$output_file" || echo "No security headers found" >> "$output_file"
    
    # 7. Check for open ports (basic)
    echo -e "\n[+] Common Ports Scan:\n" >> "$output_file"
    {
        ports=(21 22 23 25 53 80 443 3306 3389 8080 8443)
        for port in "${ports[@]}"; do
            (echo >/dev/tcp/"$domain"/"$port") &>/dev/null && echo "Port $port: OPEN" || echo "Port $port: closed/filtered"
        done
    } >> "$output_file" 2>&1
    
    echo -e "\n[+] Recon completed for $domain at $(date)" >> "$output_file"
    echo "Results saved to $output_file"
}

# Main execution
echo "Starting reconnaissance on domains from $1"
echo "Output will be saved in $OUTPUT_DIR directory"
echo ""

# Process domains with limited concurrency
count=0
while IFS= read -r domain || [[ -n "$domain" ]]; do
    # Remove http:// or https:// if present
    domain=$(echo "$domain" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
    
    # Skip empty lines
    if [ -z "$domain" ]; then
        continue
    fi
    
    # Skip comments
    if [[ "$domain" =~ ^# ]]; then
        continue
    fi
    
    ((count++))
    echo "Processing $count: $domain"
    
    # Run recon in background with limited concurrency
    perform_recon "$domain" &
    
    # Limit number of concurrent processes
    if [[ $(jobs -r -p | wc -l) -ge $MAX_THREADS ]]; then
        wait -n
    fi
    
    sleep $DELAY_BETWEEN_REQUESTS
done < "$1"

# Wait for all background processes to complete
wait

echo -e "\nReconnaissance completed for $count domains."
echo "Results saved in $OUTPUT_DIR directory"



# DNS Reconnaissance: Checks A, MX, TXT, and NS records
# Google Dorking Simulation: Searches for sensitive files and directories
# Common Files Check: Tests for robots.txt, .git, .env, etc.
# Subdomain Discovery: Uses crt.sh certificate transparency logs
# Wayback Machine: Checks historical URLs
# Security Headers: Verifies important security headers
# Basic Port Scanning: Checks common ports