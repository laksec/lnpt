### 12.3 Network Utilities
    # Scan through proxychains (replace nmap command as needed)
    proxychains4 -q nmap -sT -Pn -n target.com
    
    # Intercept and log traffic, allow all
    mitmproxy -w traffic_log.mitm --set "block_global=false"
    
    # Run mitmproxy with a custom Python script on port 8081
    mitmproxy -s "script.py --param value" -p 8081
    
    # Port forwarding / pivoting
    socat TCP-LISTEN:4443,fork TCP:your_listener_ip:4444

    proxychains -q nmap -sT -Pn -n target.com
    mitmproxy -w traffic.mitm -s script.py
    curl -I https://target.com
    ------
    proxychains4 -q nmap -sT -Pn -n target.com -p 1080
    mitmproxy -w traffic_full.mitm -s advanced_script.py
    socat TCP-LISTEN:8080,fork TCP:127.0.0.1:80
    ssh -D 1080 user@proxy.server # SOCKS proxy
    ------
    proxychains4 -q nmap -sT -Pn -n target.com -p 1080 -i -c proxychains.conf
    mitmproxy -w traffic_ultimate.mitm -s advanced_script.py --ssl-insecure --anticache
    socat TCP-LISTEN:4433,fork OPENSSL:127.0.0.1:443,cert=server.pem,key=server.key
    tcpdump -i eth0 -nn -vv -X port 80 or port 443 -w traffic.pcap
    tshark -r traffic.pcap -T fields -e http.request.method -e http.request.uri | sort -u