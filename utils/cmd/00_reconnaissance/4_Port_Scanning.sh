### 1.4 Port Scanning
    # COMPREHENSIVE TCP SCAN (Nmap)
    # Full port scan with service detection
    nmap -sV -T4 -p- -oA full_scan target.com

    # Fast top ports scan
    nmap -sV -T4 --top-ports 100 -oA quick_scan target.com

    # UDP top ports scan
    nmap -sU -T4 --top-ports 50 -oA udp_scan target.com

    # FAST PORT SCANNERS
    # Naabu (rapid port discovery)
    naabu -host target.com -p - -silent -o naabu_full.txt

    # RustScan (blazing fast)
    rustscan -a target.com --ulimit 5000 -- -sV -oN rustscan.txt

    # Masscan (Internet-scale)
    masscan -p1-65535 target.com --rate=10000 -oG masscan.out

    # SSL/TLS TESTING
    # Comprehensive SSL check
    testssl.sh -e -E -f -U -S -P -Q --json target.com.json target.com

    # Fast TLS inspection
    tlsx -u target.com -san -cn -silent -o tlsx_results.txt

    # RECOMMENDED WORKFLOW:
    # 1. Start with RustScan/Naabu for quick discovery
    # 2. Run Nmap on found ports for service detection
    # 3. Perform SSL/TLS checks on web ports
    # 4. Use Masscan for large scope scans

    # PRO TIPS:
    # For internal networks: Add '-Pn' to skip host discovery
    # For stealth: Use '-sS -T2' in Nmap
    # To scan multiple targets: 'nmap -iL targets.txt'
    # For web services: Combine with httpx for HTTP verification