### 2.9 Virtual Host (VHOST) Fuzzing
    # 1. FFUF VHOST FUZZING (Most effective)
    # Basic VHOST discovery
    ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -u http://TARGET_IP \
    -H "Host: FUZZ.target.com" \
    -fs $(curl -s -o /dev/null -w "%{size_download}" http://TARGET_IP -H "Host: nonexistent.target.com") \
    -o vhosts.json \
    -of json

    # HTTPS version with status code filtering
    ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -u https://TARGET_IP \
    -H "Host: FUZZ.target.com" \
    -mc 200,403 \
    -fc 404,400 \
    -t 150 \
    -o vhosts_https.json

    # 2. GOBUSTER VHOST SCANNING
    # Standard scan
    gobuster vhost -u http://target.com \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -t 100 \
    -o gobuster_vhost.txt

    # With domain appending
    gobuster vhost -u https://target.com \
    -w custom_wordlist.txt \
    --append-domain \
    -t 150 \
    -o gobuster_vhost_custom.txt

    # 3. ADVANCED TECHNIQUES
    # Find size differences (manual method)
    for sub in admin test staging; do
    echo -n "$sub: "
    curl -s -o /dev/null -w "%{size_download}" http://TARGET_IP -H "Host: $sub.target.com"
    done

    # TLS SNI fuzzing
    ffuf -w subdomains.txt \
    -u https://TARGET_IP \
    -H "Host: FUZZ.target.com" \
    -sni \
    -o sni_vhosts.json

    # 4. POST-DISCOVERY VERIFICATION
    # Validate found VHOSTs
    cat vhosts.json | jq -r '.results[] | input.FUZZ' | while read vhost; do
    echo -n "$vhost: "
    curl -s -I -H "Host: $vhost.target.com" http://TARGET_IP | head -n 1
    done > vhost_validation.txt

    # ======================
    # PRO TIPS:
    # 1. Always try both HTTP and HTTPS
    # 2. Check for size differences (--fs in ffuf)
    # 3. Look beyond 200 status codes (403 often indicates valid VHOST)
    # 4. Try different TLDs if target uses multiple
    # 5. Combine with DNS enumeration results
    # ======================

    # RECOMMENDED WORDLISTS:
    #  - /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
    #  - /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
    #  - Custom lists based on target naming conventions

    # EXAMPLE WORKFLOW:
    # 1. Determine baseline response for invalid VHOST
    # 2. Run ffuf with size filtering
    # 3. Verify findings with manual checks
    # 4. Test discovered VHOSTs for web applications
    # 5. Document all findings

    # SAMPLE VHOST TESTING SCRIPT:
    """
    #!/bin/bash
    # vhost_tester.sh
    target_ip=$1
    wordlist=$2

    echo "VHOST Discovery Report - $(date)"
    echo "================================"

    # Get baseline size
    baseline=$(curl -s -o /dev/null -w "%{size_download}" http://$target_ip -H "Host: nonexistent.target.com")

    while read sub; do
    size=$(curl -s -o /dev/null -w "%{size_download}" http://$target_ip -H "Host: $sub.target.com")
    if [ "$size" -ne "$baseline" ]; then
        echo "Found: $sub.target.com (Size: $size)"
    fi
    done < $wordlist
    """


    # Advanced Techniques:
    # - Use -H "X-Forwarded-Host: FUZZ" for reverse proxy scenarios
    # - Test with different HTTP versions (1.0, 1.1, 2)
    # - Monitor for new VHOSTs over time
    # - Combine with DNS brute-forcing
    # - Check for VHOST takeover opportunities

    # Security Considerations:
    # VHOSTs may expose:
    # - Internal applications
    # - Staging environments
    # - Admin interfaces
    # - Legacy systems
    # - Development versions