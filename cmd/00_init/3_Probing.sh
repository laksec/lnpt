
# PORT SCANNING & PROBING - COMMAND REFERENCE

## 1. NAABU PORT SCANNING - ONE LINERS

# Basic port scan for list of domains/subdomains
naabu -l dml.txt -o naabu_scan.txt

# Scan top 100 ports
naabu -l dml.txt -top-ports 100 -o top_ports.txt

# Scan specific ports
naabu -l dml.txt -p 80,443,8080,8443,22,21,25 -o specific_ports.txt

# Scan port range
naabu -l dml.txt -p 1-1000 -o range_scan.txt

# Fast scan with timing template
naabu -l dml.txt -p 80,443 -T 4 -o fast_scan.txt


## 2. ADVANCED NAABU SCANNING

# Scan with service detection
naabu -l dml.txt -p 80,443,22,21,25,3306,5432 -sV -o services.txt

# Scan with banner grabbing
naabu -l dml.txt -p 21,22,23,25,110,143 -sV -version-intensity 9 -o banners.txt

# Scan with rate limiting
naabu -l dml.txt -p 1-1000 -rate 1000 -o rate_limited.txt

# Exclude ports from scan
naabu -l dml.txt -p - -exclude-ports 22,25,53 -o excluded_ports.txt


## 3. NAABU WITH PROBING

# Port scan → HTTP probe pipeline
naabu -l dml.txt -p 80,443,8080,8443 -silent | httpx -title -status-code -o http_services.txt

# Scan and filter by service
naabu -l dml.txt -p 80,443,8080 -sV | grep "http" | cut -d' ' -f1 > http_hosts.txt

# Scan for databases
naabu -l dml.txt -p 3306,5432,27017,6379,9200 -o databases.txt

# Scan for management ports
naabu -l dml.txt -p 22,3389,5900,5985,5986 -o management_ports.txt


## 4. MASSCAN ALTERNATIVE

# Fast masscan scan
masscan -p80,443,8080,8443 -iL dml.txt -oL masscan_results.txt --rate 1000

# Masscan with specific ports
masscan -p1-1000 -iL dml.txt -oL full_scan.txt --rate 5000

# Masscan to file
masscan -pU:53,161,162,500,4500 -iL dml.txt -oL udp_scan.txt


## 5. NMAP ALTERNATIVE

# Quick nmap scan
nmap -iL dml.txt -p 80,443,8080 -oA quick_scan

# Top 1000 ports nmap
nmap -iL dml.txt --top-ports 1000 -oA top1000_scan

# Nmap with service detection
nmap -iL dml.txt -sV -p 1-100 -oA service_scan

# Nmap aggressive scan
nmap -iL dml.txt -A -p- -oA aggressive_scan


## 6. PORT SCAN PIPELINES

# Naabu → HTTP probing
naabu -l dml.txt -p 80,443 -silent | httpx -title -tech-detect -o web_apps.txt

# Masscan → Naabu verification
masscan -p1-1000 -iL dml.txt --rate 10000 | grep "open" | cut -d' ' -f4 | naabu -p- -o verified_ports.txt

# Multiple scans combination
cat <(naabu -l dml.txt -p 80,443) <(naabu -l dml.txt -p 8080,8443) | sort -u > all_web_ports.txt

# Port scan with DNS resolution
dnsx -l dml.txt -a -silent | naabu -p 80,443 -o resolved_scan.txt


## 7. SCAN OPTIMIZATION

# Skip host discovery
naabu -l dml.txt -p 80,443 -sn -o no_host_discovery.txt

# Use specific source port
naabu -l dml.txt -p 80,443 -source-port 53 -o source_port_scan.txt

# Retry failed connections
naabu -l dml.txt -p 1-1000 -retries 3 -o retry_scan.txt

# Custom timeout
naabu -l dml.txt -p 80,443 -timeout 2 -o timeout_scan.txt


## 8. OUTPUT FORMATS

# JSON output
naabu -l dml.txt -p 80,443 -json -o scan.json

# CSV output
naabu -l dml.txt -p 80,443 -o scan.csv

# Greppable output
naabu -l dml.txt -p 80,443 -oG greppable_scan.txt

# Multiple formats
naabu -l dml.txt -p 80,443 -oA complete_scan


## 9. FILTERING RESULTS

# Filter by open ports only
naabu -l dml.txt -p 80,443 | grep "open" > open_ports.txt

# Extract just host:port
naabu -l dml.txt -p 80,443 | awk '{print $1 ":" $2}' > host_port.txt

# Count open ports per host
naabu -l dml.txt -p 1-1000 | grep "open" | awk '{print $1}' | sort | uniq -c > ports_per_host.txt

# Find uncommon ports
naabu -l dml.txt -p 1-1000 | grep -v "80\|443\|22\|21\|25\|53" > uncommon_ports.txt


## 10. SPECIALIZED SCANS

# HTTP/HTTPS only
naabu -l dml.txt -p http,https -o web_ports.txt

# Common web ports
naabu -l dml.txt -p 80,443,8080,8443,3000,5000,8000,8008 -o all_web_ports.txt

# Database ports
naabu -l dml.txt -p 3306,5432,27017,6379,9200,9300,11211 -o database_ports.txt

# Windows ports
naabu -l dml.txt -p 135,139,445,3389,5985,5986 -o windows_ports.txt


## 11. QUICK COMMANDS

# Quick check for web servers
naabu -l dml.txt -p 80,443 -silent | wc -l

# Scan and immediately probe
naabu -l dml.txt -p 80,443 -silent | httpx -silent

# Check if ports are open
echo "target.com" | naabu -p 80,443 -silent

# Scan single target
echo "target.com" | naabu -p- -o single_target.txt


## 12. COMBINATION TECHNIQUES

# Subfinder → Naabu → HTTPX
subfinder -dL domains.txt -silent | naabu -p 80,443 -silent | httpx -title -o discovered_web.txt

# Certificate transparency → Port scan
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | naabu -p 80,443 -o crt_scan.txt

# Assetfinder → Port scan
assetfinder target.com | naabu -p 80,443 -o assetfinder_scan.txt


## 13. PERFORMANCE TUNING

# High performance scan
naabu -l dml.txt -p 1-1000 -rate 5000 -c 1000 -o high_perf.txt

# Low and slow scan
naabu -l dml.txt -p 1-1000 -rate 100 -c 50 -o slow_scan.txt

# Batch processing
pv dml.txt | naabu -p 80,443 -silent > scan_results.txt

# Resume scan
naabu -l dml.txt -p 1-1000 -resume -o resumed_scan.txt


## 14. ALTERNATIVE TOOLS

# RustScan (very fast)
rustscan -a dml.txt -p 1-1000 -o rustscan.txt

# Unicornscan
unicornscan -i dml.txt -p 1-1000

# ZMap (Internet-scale)
zmap -p 443 -o zmap_results.txt

# Scan with netcat
while read target; do for port in 80 443 8080; do nc -zv $target $port 2>&1 | grep "succeeded" && echo "$target:$port"; done; done < dml.txt
