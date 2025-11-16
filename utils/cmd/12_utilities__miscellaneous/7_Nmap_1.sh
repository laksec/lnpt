
# Basic Scans
nmap 192.168.1.1                     # Basic TCP SYN scan
nmap -sT 192.168.1.1                 # Full TCP connect scan
nmap -sU 192.168.1.1                 # UDP scan
nmap -sn 192.168.1.0/24              # Ping sweep only
nmap -p 80,443 192.168.1.1           # Scan specific ports

# Advanced Discovery
nmap -A 192.168.1.1                  # Aggressive scan (OS/version detection)
nmap -O 192.168.1.1                  # OS detection
nmap -sV 192.168.1.1                 # Service version detection
nmap --script banner 192.168.1.1     # Grab simple banners
nmap --top-ports 100 192.168.1.1     # Scan top 100 ports

# Port Specification
nmap -p- 192.168.1.1                 # Scan all ports (1-65535)
nmap -p 1-1000 192.168.1.1           # Port range
nmap -p http,https 192.168.1.1       # Named ports
nmap -p U:53,T:80 192.168.1.1        # Mix TCP/UDP
nmap -p smtp* 192.168.1.1            # Wildcard port names

# Output Formats
nmap -oN output.txt 192.168.1.1      # Normal output
nmap -oX output.xml 192.168.1.1      # XML format
nmap -oG output.gnmap 192.168.1.1    # Greppable format
nmap -oA output 192.168.1.1          # All formats at once
nmap -v -d 192.168.1.1               # Increased verbosity

# Performance Optimization
nmap -T4 192.168.1.1                 # Aggressive timing
nmap -T0 192.168.1.1                 # Paranoid timing (slowest)
nmap --min-rate 1000 192.168.1.1     # Send at least 1k pps
nmap --max-retries 1 192.168.1.1     # Reduce retransmissions
nmap --min-hostgroup 100 192.168.1.0/24 # Parallel scanning

# NSE Scripting Engine
nmap --script=safe 192.168.1.1       # Run safe scripts
nmap --script vuln 192.168.1.1       # Vulnerability scripts
nmap --script=http* 192.168.1.1      # All HTTP scripts
nmap --script-args=unsafe=1 192.168.1.1 # Enable risky scripts
nmap --script-updatedb               # Update script database

# Firewall Evasion
nmap -f 192.168.1.1                  # Fragment packets
nmap --mtu 16 192.168.1.1            # Custom MTU size
nmap -D RND:10 192.168.1.1           # Decoy scan
nmap --source-port 53 192.168.1.1    # Spoof source port
nmap --data-length 200 192.168.1.1   # Add random data

# Host Discovery
nmap -PS 192.168.1.0/24              # TCP SYN ping
nmap -PA 192.168.1.0/24              # TCP ACK ping
nmap -PE 192.168.1.0/24              # ICMP echo ping
nmap -PP 192.168.1.0/24              # ICMP timestamp ping
nmap -PR 192.168.1.0/24              # ARP ping (local nets)

# Advanced Techniques
nmap -sI zombie.com 192.168.1.1      # Idle scan
nmap -b ftp.proxy.com 192.168.1.1    # FTP bounce scan
nmap --traceroute 192.168.1.1        # Trace network path
nmap --packet-trace 192.168.1.1      # Show all packets sent
nmap --reason 192.168.1.1            # Display port reason

# Useful Combinations
nmap -sS -sV -O -T4 -p- 192.168.1.1 # Full stealth scan
nmap -sU -sS -p- -T4 192.168.1.1    # Complete TCP/UDP scan
nmap -Pn -A -sS -T4 192.168.1.1     # Assume host is up
nmap --script vuln -sV -T4 192.168.1.1 # Vulnerability assessment
nmap -iL hosts.txt -oA scan_results  # Input from file