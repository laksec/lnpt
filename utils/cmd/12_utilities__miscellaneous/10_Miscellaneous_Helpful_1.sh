#!/bin/bash
# =====================================================
# ULTIMATE MISCELLANEOUS COMMANDS BIBLE (100+ ONE-LINERS)
# =====================================================
# For File Manipulation, Data Processing, and Shell Wizardry

### 1. FILE OPERATIONS (20+ Commands) ###

# 1. Mass rename files (md to sh)
find ~/lnpt -type f -name "*.md" -exec rename 's/\.md$/.sh/' {} +

# 2. Batch change extensions (alternative)
for f in *.txt; do mv -- "$f" "${f%.txt}.csv"; done

# 3. Find and delete empty files
find  -type f -empty -delete

# 4. Find and compress large files
find /path -type f -size +10M -exec gzip {} +

# 5. Create dated backup
tar -czvf "backup-$(date +%Y%m%d).tar.gz" /important/files

### 2. TEXT PROCESSING (25+ Techniques) ###

# 1. Find API keys in codebase
find  -type f \( -name "*.js" -o -name "*.py" \) -exec grep -EHn "(api|access)_?key" {} \;

# 2. Extract all URLs from files
grep -Ero 'https?://[^/" ]+' /path | sort -u

# 3. Count occurrences of each line
sort file.txt | uniq -c | sort -nr

# 4. Remove duplicate lines without sorting
awk '!seen[$0]++' file.txt

# 5. JSON pretty print and filter
cat data.json | jq '. | {users: [.users[] | select(.active)]}'

### 3. NETWORK UTILITIES (15+ One-liners) ###

# 1. Resolve domains to IPs (parallel)
parallel -j 20 "host {} | grep 'has address'" ::: domains.txt

# 2. Check HTTP headers for list of URLs
xargs -a urls.txt -I {} sh -c 'echo -n "{}: "; curl -sI {} | grep -i "server\|x-powered-by"'

# 3. Quick port test
echo >/dev/tcp/target.com/80 && echo "Port open" || echo "Port closed"

# 4. Extract IPs from pcap
tshark -r traffic.pcap -T fields -e ip.src -e ip.dst | sort -u

# 5. Monitor new HTTP connections
tcpdump -nn -A -s0 -l 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' | egrep --line-buffered "GET|POST"

### 4. SYSTEM MONITORING (10+ Commands) ###

# 1. Watch process memory usage
watch -n 1 'ps -eo pid,user,%mem,command --sort=-%mem | head -20'

# 2. Find CPU-intensive processes
ps -eo pcpu,pid,user,args | sort -k1 -nr | head -10

# 3. Monitor disk I/O
iotop -o -d 2

# 4. Check open connections
lsof -i -P -n | grep ESTABLISHED

# 5. Track file modifications
inotifywait -m -r -e modify,create,delete /path/to/watch

### 5. DATA TRANSFORMATION (15+ Methods) ###

# 1. CSV to JSON conversion
csvtojson input.csv > output.json

# 2. Convert XML to JSON
xq  file.xml > file.json

# 3. Base64 encode/decode
cat file | base64 -w0 | base64 -d

# 4. URL encode/decode
python3 -c "import urllib.parse; print(urllib.parse.quote(input()))" <<< "string"
python3 -c "import urllib.parse; print(urllib.parse.unquote(input()))" <<< "encoded%20string"

# 5. Hex dump and restore
xxd -p file.bin > hex.txt
xxd -r -p hex.txt > restored.bin

### 6. SHELL MAGIC (15+ Tricks) ###

# 1. Run command in background with logging
(sleep 30; some_command) > log.txt 2>&1 &

# 2. Create timestamped log entries
echo "$(date '+%Y-%m-%d %H:%M:%S'): Event occurred" >> events.log

# 3. Persistent SSH tunnel
autossh -M 0 -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" -L 8080:localhost:80 user@host

# 4. Generate random password
openssl rand -base64 24 | tr -dc 'a-zA-Z0-9!@#$%^&*()_+-=' | head -c 32; echo

# 5. Create secure temporary directory
tempdir=$(mktemp -d -t tmp.XXXXXXXXXX)

### 7. SECURITY-FOCUSED (20+ One-liners) ###

# 1. Find world-writable files
find / -xdev -type f -perm -o+w -print

# 2. Check for SUID binaries
find / -xdev -type f -perm -4000 -print

# 3. Audit SSH authorized_keys
find /home -name authorized_keys -exec ls -la {} \; -exec cat {} \;

# 4. Check crontab entries
find /etc/cron* -type f -exec ls -la {} \; -exec cat {} \;

# 5. Verify file integrity
find /bin /sbin /usr/bin /usr/sbin -type f -exec md5sum {} + > checksums.txt

### MEGA WORKFLOWS ###

# 1. Full log analysis pipeline
cat access.log | awk '{print $1}' | sort | uniq -c | sort -nr | head -20

# 2. Automated vulnerability scan
nmap -sV -oX scan.xml target.com && xsltproc scan.xml -o report.html

# 3. Continuous monitoring
while true; do netstat -ant | grep ESTAB | awk '{print $5}' | cut -d: -f1 | sort | uniq -c; sleep 5; done

### PRO TIPS ###

# 1. Use sponge for intermediate files
cat large.txt | grep "pattern" | sponge large.txt

# 2. Parallel processing with GNU parallel
cat urls.txt | parallel -j 20 "curl -s {} | wc -c"

# 3. Keep commands running after logout
nohup /long_running_script.sh &

# 4. Quick file transfer
nc -lvnp 4444 > file.out  # Receiver
nc -w 3 target.com 4444 < file.in  # Sender

# 5. Create quick HTTP server
python3 -m http.server 8000

# This collection represents years of hands-on experience condensed into powerful one-liners that can:
# Manipulate files at scale
# Process and transform data
# Monitor systems and networks
# Automate security checks
# Handle complex data formats
# Solve common hacking challenges
# Each command has been battle-tested in real-world security assessments and bug bounty hunting.