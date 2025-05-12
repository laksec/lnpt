
## 1. Information Gathering & Reconnaissance


### 1.1 Passive Reconnaissance (Gathering publicly available information)
    subfinder         # Subdomain enumeration using passive online sources
    amass             # In-depth subdomain discovery and network mapping
    findomain         # Fast and reliable subdomain enumeration tool
    assetfinder       # Finds domains and subdomains potentially related to a target
    chaos             # Subdomain enumeration and monitoring using Chaos CDN data
    sublist3r         # Subdomain enumeration tool that uses OSINT
    whois             # Querying domain registration information
    ripe-dbase        # Querying the RIPE NCC database for IP and ASN information
    bgp.he            # Looking glass for BGP routing information
    cloud_enum        # Enumerating cloud resources across various providers
    scout             # Multi-cloud security auditing tool
    cfr               # Cloudflare reconnaissance tool
    waybackurls       # Fetching historical URLs from the Wayback Machine
    domain-analyzer   # Analyze domain infrastructure and related information

### 1.2 Active Reconnaissance (Direct interaction with the target)
    dig               # DNS lookup utility
    host              # DNS lookup utility
    dnsx              # Fast and versatile DNS toolkit
    dnscan            # Fast DNS subdomain scanner
    fierce            # DNS reconnaissance tool
    dnsrecon          # Powerful DNS enumeration and analysis tool
    shuffledns        # Mass DNS resolver and subdomain bruteforcer
    altdns            # Generates potential subdomains using permutations
    dnsgen            # Generates subdomain wordlists based on a given domain
    nmap              # Network mapper for host discovery and service enumeration
    naabu             # Fast port scanner
    rustscan          # Modern port scanner known for its speed
    masscan           # High-speed port scanner
    traceroute        # Trace the route packets take to a network host
    ping              # Test network connectivity

### 1.3 Directory & File Discovery
    gobuster          # Directory and file brute-forcer
    ffuf              # Fast web fuzzer
    feroxbuster       # Fast, recursive content discovery tool
    dirsearch         # Advanced command-line web directory/file scanner

### 1.4 Parameter & URL Discovery
    arjun             # Discovers hidden parameters in web applications
    paramspider       # Mining parameters from web archives and JavaScript files
    waybackparam      # Extract parameters from Wayback Machine captures
    parameth          # Guessing and bruteforcing web parameters
    qsreplace         # Replace query string parameters in URLs
    linkfinder        # Find links in JavaScript files
    gau               # Get all known URLs from AlienVault's Open Threat Exchange, Wayback Machine, and Common Crawl
    gospider          # Fast web spider written in Go
    hakrawler         # Simple, fast web crawler with JavaScript rendering

### 1.5 JavaScript Analysis
    jsanalyze.py      # Static analysis of JavaScript files for sensitive information
    secretfinder      # Find secrets and API keys in web content
    getjs             # Fetch JavaScript files from target URLs
    subjs             # Fetch subdomains from JavaScript files

### 1.6 Cloud Reconnaissance
    gcpbucketbrute    # Google Cloud Storage bucket brute-forcer
    s3scanner         # Scan for open S3 buckets and their contents
    prowler           # Security assessment tool for AWS


## 2. Vulnerability Scanning & Analysis


### 2.1 Web Application Scanners
    nikto             # Web server scanner to find vulnerabilities
    zap               # OWASP ZAP, an integrated penetration testing tool for web applications
    wpscan            # WordPress security scanner
    arachni           # Modular, high-performance web application security scanner
    nuclei            # Fast and customizable vulnerability scanner based on YAML templates
    dalfox            # Parameter Analysis and Exploitation Tool for XSS

### 2.2 Specific Vulnerability Scanners
    xsstrike          # Cross Site Scripting detection suite
    xsser             # Automated Cross Site Scripting (XSS) scanner
    kxsstester        # Simple XSS testing tool
    sqlmap            # Automatic SQL injection and database takeover tool
    nosqli            # NoSQL injection testing tool
    nosqlmap          # Automated NoSQL database injection and takeover tool
    ghauri            # Blind SQL injection detection tool
    jsql              # Java SQL injection tool
    sqli-detector     # Lightweight SQL injection detection tool
    ssrfmap           # Automatic SSRF (Server Side Request Forgery) detection and exploitation tool
    xxeinjector       # Automatic XXE (XML External Entity) vulnerability detection and exploitation tool

### 2.3 API Security Scanners
    restler           # State-based REST API fuzzing tool
    swagger-cli       # Command-line interface for working with Swagger/OpenAPI definitions
    graphqlmap        # GraphQL endpoint and schema discovery tool
    clairvoyance      # GraphQL endpoint scanning and security testing tool
    inql              # GraphQL security testing toolset
    graphw00f         # GraphQL fingerprinting and information gathering tool
    wsdlfuzz          # Web Services Description Language (WSDL) fuzzing tool
    soapui            # Open-source cross-platform API testing tool (supports SOAP and REST)

### 2.4 Cloud Security Scanners
    scoutsuite        # Security assessment tool for AWS, GCP, and Azure


## 3. Exploitation Tools


### 3.1 Web Application Exploitation
    gopherus          # Generate gopher link for various SSRF and related attacks
    ground-control      # Tool to orchestrate SSRF exploitation
    docem             # Proof-of-concept exploit tool for various vulnerabilities
    lfisuite          # Local File Inclusion exploitation suite
    fimap             # Local and Remote File Inclusion parameters audit and exploitation tool
    dotdotpwn         # Directory traversal fuzzer
    tplmap            # Server-Side Template Injection detection and exploitation tool
    crlfuzz           # CRLF injection scanner and exploiter
    corsy             # CORS misconfiguration scanner
    kiterunner        # Contextual HTTP request sender

### 3.2 API Exploitation
    postman-smuggler  # HTTP Request Smuggling via Postman

### 3.3 General Exploitation Frameworks
    arachni           # (Also a scanner, but can be used for exploitation)

### 3.4 Privilege Escalation (Local)
    linpeas.sh        # Linux Privilege Escalation Awesome Script
    linux-exploit     # Collection of Linux privilege escalation exploits
    pspy64            # Monitor processes without root privileges
    SUID3NUM          # Enumerate SUID/GUID executables and potential abuse
    winpeas.exe       # Windows Privilege Escalation Awesome Script
    windows-exploit   # Collection of Windows privilege escalation exploits
    Watson.exe        # Windows privilege escalation reconnaissance tool
    accesschk.exe     # Microsoft Sysinternals tool to view file system, registry, and other object security settings

### 3.5 Post-Exploitation & Lateral Movement
    evil-winrm        # The ultimate WinRM shell for hacking/pentesting
    ssh               # Secure Shell for remote access and command execution
    mimikatz.exe      # Credentials extraction tool for Windows
    LaZagne.exe       # Credentials recovery tool
    reg               # Windows registry manipulation tool
    python            # Versatile scripting language for various post-exploitation tasks
    net               # Windows command-line tool for managing network resources
    copy              # File copying utility (useful for moving payloads)


## 4. Password Cracking


    hashcat           # Powerful password cracking utility
    john              # John the Ripper password cracker
    crackmapexec      # Swiss Army Knife for pentesting networks (includes credential testing)


## 5. Fuzzing


    radamsa           # General-purpose black-box fuzzer
    afl-fuzz          # Coverage-guided evolutionary fuzzing


## 6. Reverse Engineering (Tools for analyzing software and hardware)

### 6.1 Disassemblers & Debuggers
    IDA Pro           # Powerful disassembler and debugger (commercial)
    Ghidra            # Free and open-source software reverse engineering framework
    radare2           # Portable reversing framework with a command-line interface
    x64dbg            # Open-source x64/x32 debugger for Windows
    OllyDbg           # x86 debugger for Windows (older but still relevant)
    lldb              # Next generation debugger (often used on macOS and Linux)
    gdb               # GNU Debugger

### 6.2 Decompilers
    IDA Pro             # (Also has decompilation capabilities for various architectures)
    Ghidra              # (Includes a powerful decompiler)
    JD-GUI              # Standalone Java Decompiler
    CFR                 # Java decompiler
    Procyon             # Open-source Java decompiler
    uncompyle6          # Python bytecode decompiler

### 6.3 Network Protocol Analyzers (for understanding application behavior)
    Wireshark         # Popular network protocol analyzer
    tcpdump           # (Already listed, but crucial for network RE)
    tshark            # (Already listed, command-line version of Wireshark)

### 6.4 File Format Analysis
    Binwalk           # Tool for searching binary images for embedded files and code
    strings           # Prints printable strings found in files
    file              # Determines file type

### 6.5 Mobile Application Reverse Engineering
    Apktool           # Tool for reverse engineering Android APK files
    dex2jar           # Converts Dalvik Executable (DEX) files to JAR
    jadx              # Dex to Java decompiler
    Frida             # Dynamic instrumentation toolkit for various platforms (including mobile)
    Objection         # Runtime mobile exploration toolkit powered by Frida
    iRetr0spect        # iOS reverse engineering toolkit

### 6.6 Hardware Reverse Engineering (More specialized)
    ChipWhisperer     # Open-source tool for side-channel power analysis and fault injection
    Bus Pirate        # Open-source hardware debugging and interaction tool
    Saleae Logic Analyzers # Hardware debugging tools for capturing digital and analog signals

## 7. Social Engineering 
    - Tools and resources to aid information gathering and delivery of social engineering attacks - use with extreme caution and only with explicit permission for ethical purposes

### 7.1 Information Gathering (OSINT for Social Engineering)
    theHarvester      # Email, subdomain, people, and port discovery tool
    recon-ng          # Web reconnaissance framework
    sherlock          # Hunt down social media accounts by username
    Social-Engineer Toolkit (SET) # Framework with various social engineering modules
    Maltego           # Proprietary software for link analysis and data mining

### 7.2 Phishing & Credential Harvesting
    Social-Engineer Toolkit (SET) # Includes phishing attack vectors
    GoPhish           # Open-source phishing framework
    Evilginx2         # Standalone man-in-the-middle attack framework for credential harvesting
    CredSniper        # Credential harvester for various services

### 7.3 Payload Generation & Delivery
    Social-Engineer Toolkit (SET) # Includes payload generation
    Metasploit Framework # (While primarily for exploitation, can generate payloads for SE)
    msfvenom          # Payload generator (part of Metasploit)

### 7.4 Wireless Social Engineering
    Aircrack-ng       # Suite of tools for Wi-Fi security auditing (can be used in SE scenarios)
    bettercap         # Modular, portable and easily extensible multi-tool aimed at network attacks

### 7.5 Physical Social Engineering Aids
    USB Drop tools    # Custom USB devices for delivering payloads (e.g., Rubber Ducky)
    RFID Cloners      # Tools for reading and cloning RFID tags

### 7.6 Frameworks & Resources
    Social-Engineer Toolkit (SET) # Comprehensive framework
    Kali Linux        # Distribution with many pre-installed social engineering tools
    OWASP Resources   # Guidance and best practices for social engineering awareness

## 8. Cloud Security Tools
    aws-nuke          # Utility to nuke (delete) all resources in an AWS account
    gcloud            # Google Cloud CLI
    az                # Microsoft Azure CLI


## 9. Utility & Scripting Tools (General purpose, often used in workflows)
    cewl              # Custom wordlist generator
    kwprocessor       # Wordlist generation and manipulation tool
    seclists          # Collection of various types of lists used during security assessments
    gf                # Grep for bug bounty hunters
    anew              # Performs HTTP requests and intelligent filtering of the results
    urldedupe         # Deduplicates lists of URLs
    sed               # Stream editor for text manipulation
    awk               # Text processing tool
    cut               # Utility for cutting out sections of each line of files


## 10. Proxy & Traffic Analysis
    proxychains       # Force TCP connections through SOCKS4a/5 or HTTP proxies
    mitmproxy         # Interactive HTTP proxy
    curl              # Command-line tool for transferring data with URLs
    proxychains4      # Updated version of proxychains
    socat             # Multipurpose relay tool
    tcpdump           # Network packet analyzer
    tshark            # Command-line network protocol analyzer


## 11. Bug Bounty & Automation Frameworks (Tools that integrate multiple tools)
    bugbounty-auto    # Framework for automating bug bounty workflows
    reconftw          # Automated reconnaissance framework
    interlace         # Modular reconnaissance framework

## Important Ethical Considerations for Social Engineering:
    Always obtain explicit permission before conducting any social engineering exercises.
    Clearly define the scope and objectives of the engagement.
    Focus on education and awareness, not harm.
    Handle sensitive information responsibly.
    Adhere to all legal and ethical guidelines.
