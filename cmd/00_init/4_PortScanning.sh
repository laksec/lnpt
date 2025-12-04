# PORT SCANNING - COMMAND LINE TOOLS ONLY

## 1. NAABU (FAST PORT SCANNER)

# Basic scan for list of targets
naabu -l dml.txt -o ports.txt

# Scan top ports (1000 most common)
naabu -l dml.txt -top-ports 1000 -o top_ports.txt

# Scan specific ports
naabu -l dml.txt -p 80,443,8080,8443,22,21,25,3306,5432 -o common_ports.txt

# Scan port range
naabu -l dml.txt -p 1-10000 -o full_range.txt

# Fast scan with timing
naabu -l dml.txt -p 80,443 -T 4 -o fast_scan.txt


## 2. NMAP (COMPREHENSIVE SCANNING)

# Quick TCP scan
nmap -iL dml.txt -p 80,443,8080 -oN quick_scan.txt

# Top 1000 ports TCP
nmap -iL dml.txt --top-ports 1000 -oN top1000_tcp.txt

# Full TCP port scan
nmap -iL dml.txt -p- -oN full_tcp_scan.txt

# UDP port scan
nmap -iL dml.txt -sU -p 53,67,68,69,123,161,162,500,514 -oN udp_scan.txt

# Service detection
nmap -iL dml.txt -sV -p 1-1000 -oN service_scan.txt

# OS detection
nmap -iL dml.txt -O -p 80,443 -oN os_detection.txt

# Aggressive scan
nmap -iL dml.txt -A -p 80,443 -oN aggressive_scan.txt

# Script scanning
nmap -iL dml.txt -sC -p 80,443 -oN script_scan.txt


## 3. MASSCAN (ULTRA-FAST)

# Fast TCP scan
masscan -p80,443,8080,8443 -iL dml.txt -oL masscan_results.txt --rate 10000

# Range scan with high rate
masscan -p1-10000 -iL dml.txt -oL full_masscan.txt --rate 5000

# UDP scan
masscan -pU:53,161,162,500,4500 -iL dml.txt -oL udp_masscan.txt --rate 1000

# Banner grabbing
masscan -p80,443 -iL dml.txt --banners -oL banners.txt --rate 1000


## 4. RUSTSCAN (VERY FAST RUST-BASED)

# Basic scan
rustscan -a dml.txt -p 1-1000 -o rustscan.txt

# Scan with nmap integration
rustscan -a dml.txt -p 1-1000 -- -A -sV -oN rust_nmap.txt

# Ultra-fast scan
rustscan -a dml.txt -p 1-1000 -t 5000 -o ultrafast.txt

# Specific ports
rustscan -a dml.txt -p 80,443,8080,8443 -o web_ports.txt


## 5. NETCAT (MANUAL SCANNING)

# Quick port check
while read target; do nc -zv $target 80 2>&1 | grep "succeeded" && echo "$target:80"; done < dml.txt

# Multiple ports
while read target; do for port in 21 22 23 25 80 443 3306; do nc -zv $target $port 2>&1 | grep "succeeded" && echo "$target:$port"; done; done < dml.txt

# Timeout scan
while read target; do timeout 1 nc -zv $target 22 2>&1 | grep "succeeded" && echo "$target:22 open"; done < dml.txt


## 6. HOST COMMAND

# Simple port check
while read target; do (echo >/dev/tcp/$target/80) &>/dev/null && echo "$target:80 open"; done < dml.txt

# Multiple ports
for port in 80 443 8080; do while read target; do timeout 1 bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null && echo "$target:$port"; done < dml.txt; done


## 7. TELNET (OLD SCHOOL)

# Port check with telnet
while read target; do echo "quit" | telnet $target 80 2>&1 | grep "Connected" && echo "$target:80 open"; done < dml.txt


## 8. UNICORNSCAN

# TCP scan
unicornscan -i dml.txt -p 1-1000 -o unicorn_tcp.txt

# UDP scan
unicornscan -i dml.txt -mU -p 1-1000 -o unicorn_udp.txt


## 9. ZMAP (INTERNET-SCALE)

# Single port internet scan
zmap -p 443 -o zmap_443.txt

# Multiple ports
zmap -p 80,443,8080 -o zmap_web.txt

# With banner grabbing
zmap -p 80 -B 10M -o zmap_80.txt


## 10. SCAN OUTPUT PROCESSING

# Extract open ports from nmap
grep "open" nmap_scan.txt | awk '{print $1,$2}' > open_ports.txt

# Get host:port format
cat naabu_results.txt | awk '{print $1":"$2}' > host_port.txt

# Count open ports per host
cat scan_results.txt | grep "open" | awk '{print $1}' | sort | uniq -c > ports_per_host.txt

# Filter by port number
cat scan_results.txt | grep ":80\|:443\|:8080" > web_ports_filtered.txt

# Convert masscan to nmap format
masscan -p80,443 -iL dml.txt -oX masscan.xml


## 11. SCAN PIPELINES

# DNS resolve → Port scan
dnsx -l dml.txt -a -silent | naabu -p 80,443 -o resolved_scan.txt

# Subdomain discovery → Port scan
subfinder -dL domains.txt -silent | naabu -p 80,443 -o subdomain_scan.txt

# Certificate transparency → Port scan
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | naabu -p 80,443 -o crt_scan.txt

# Multiple tool comparison
cat <(naabu -l dml.txt -p 80,443) <(rustscan -a dml.txt -p 80,443) | sort -u > combined_scan.txt


## 12. PERFORMANCE TUNING

# Fast scan (naabu)
naabu -l dml.txt -p 1-1000 -rate 5000 -c 500 -o fast_naabu.txt

# Parallel scanning with xargs
cat dml.txt | xargs -P 10 -I {} nmap -p 80,443 {} -oN scan_{}.txt

# Batch processing
pv dml.txt | while read target; do naabu -host $target -p 80,443 -silent; done > batch_scan.txt

# Resume interrupted scan
naabu -l dml.txt -p 1-1000 -resume -o resumed_scan.txt


## 13. SERVICE-SPECIFIC SCANS

# Web server ports
naabu -l dml.txt -p 80,443,8080,8443,3000,5000,8000,8008,8081,8888 -o all_web.txt

# Database ports
naabu -l dml.txt -p 3306,5432,27017,6379,9200,9300,11211,1433,1521 -o database_scan.txt

# Windows ports
naabu -l dml.txt -p 135,139,445,3389,5985,5986,49152-65535 -o windows_scan.txt

# IoT/Industrial
naabu -l dml.txt -p 502,102,161,162,47808,20000,44818 -o iot_scan.txt


## 14. SCAN TECHNIQUES

# SYN scan (stealth)
nmap -iL dml.txt -sS -p 80,443 -oN syn_scan.txt

# Connect scan
nmap -iL dml.txt -sT -p 80,443 -oN connect_scan.txt

# ACK scan
nmap -iL dml.txt -sA -p 80,443 -oN ack_scan.txt

# FIN scan
nmap -iL dml.txt -sF -p 80,443 -oN fin_scan.txt

# XMAS scan
nmap -iL dml.txt -sX -p 80,443 -oN xmas_scan.txt

# NULL scan
nmap -iL dml.txt -sN -p 80,443 -oN null_scan.txt


## 15. OUTPUT FORMATS

# Nmap formats
nmap -iL dml.txt -p 80,443 -oA scan_results  # All formats
nmap -iL dml.txt -p 80,443 -oN normal.txt    # Normal
nmap -iL dml.txt -p 80,443 -oX xml.txt       # XML
nmap -iL dml.txt -p 80,443 -oG grep.txt      # Greppable

# JSON outputs
naabu -l dml.txt -p 80,443 -json -o naabu.json
rustscan -a dml.txt -p 80,443 -oJ rustscan.json

# CSV output
naabu -l dml.txt -p 80,443 -o csv -o naabu.csv


## 16. QUICK COMMANDS

# Check if port 80/443 are open
echo "target.com" | naabu -p 80,443 -silent

# Quick service check
echo "target.com" | rustscan -p 22,80,443 -- -sV -sC

# Fast web port check
cat dml.txt | naabu -p 80,443 -silent | wc -l

# Single target full scan
echo "target.com" | rustscan -a - -p 1-65535 -- -A -sV -oN full_target.txt


## 17. SCAN VALIDATION

# Verify with multiple tools
cat naabu_results.txt | awk '{print $1}' | sort -u | rustscan -a - -p 80,443 -o verification.txt

# Compare scans
comm -12 <(sort naabu.txt) <(sort nmap.txt) > confirmed_ports.txt

# Remove false positives
naabu -l dml.txt -p 80,443 -verify -o verified.txt


## 18. CUSTOM SCRIPTS

# Port scan with progress bar
pv dml.txt | while read target; do echo $target | naabu -p 80,443 -silent; done > progress_scan.txt

# Scheduled scanning
while true; do naabu -l dml.txt -p 80,443 -o "scan_$(date +%s).txt"; sleep 3600; done

# Differential scanning
old="old_ports.txt"; new="new_ports.txt"
naabu -l dml.txt -p 80,443 -o $new
comm -13 <(sort $old) <(sort $new) > new_ports_found.txt
mv $new $old
