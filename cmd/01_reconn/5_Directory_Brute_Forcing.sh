#### 2.2.1 Directory/File Brute Forcing
    # FFUF (Most versatile)
    # Fast recursive scan with common extensions
    ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -u https://target.com/FUZZ \
    -t 200 \
    -recursion \
    -recursion-depth 2 \
    -e php,.html,.js,.json \
    -o ffuf_recursive.json \
    -of json \
    -v

    # API endpoint discovery
    ffuf -w /usr/share/seclists/Discovery/Web-Content/api/endpoints.txt \
    -u https://target.com/api/FUZZ \
    -t 150 \
    -mc 200,201,204 \
    -H "Authorization: Bearer token" \
    -o ffuf_api.json

    # FEROXBUSTER (Fast Rust-based)
    # Comprehensive scan with smart filtering
    feroxbuster -u https://target.com \
    -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
    -t 50 \
    -x php,html,js \
    -d 3 \
    --filter-status 404,403 \
    --extract-links \
    --auto-tune \
    -o ferox_full.txt

    # DIRSEARCH (Python-based)
    # Deep scan with backup file checking
    dirsearch -u https://target.com \
    -e php,asp,aspx,jsp,html,js,json \
    -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt \
    -t 100 \
    -r -R 2 \
    --exclude-status 404,500 \
    --random-agents \
    -o dirsearch_deep.json \
    --format=json

    # GOBUSTER (Simple Go-based)
    # Quick scan with common extensions
    gobuster dir -u https://target.com \
    -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
    -x php,html,js \
    -t 100 \
    -k \
    -o gobuster_quick.txt

    # WFuzz (Advanced filtering)
    # Parameter fuzzing with regex filtering
    wfuzz -c \
    -z file,/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -H "Content-Type: application/json" \
    --hh 0 \
    --hc 404 \
    --filter "s>0" \
    https://target.com/api/search?FUZZ=test

    # PRO TIPS & ADVANCED TECHNIQUES

    # 1. Custom 404 Handling
    # First find 404 page size:
    curl -s -o /dev/null -w "%{size_download}" https://target.com/nonexistentpage
    # Then use in ffuf: -fs 1234

    # 2. Smart Recursion
    # Only recurse into promising paths:
    ffuf -w wordlist.txt -u https://target.com/FUZZ \
    -recursion \
    -recursion-strategy greedy \
    -recursion-depth 3

    # 3. JWT Token Fuzzing
    ffuf -w /usr/share/seclists/Discovery/Web-Content/jwt-tokens.txt \
    -u https://target.com/api \
    -H "Authorization: Bearer FUZZ" \
    -mc 200,403

    # 4. Virtual Host Discovery
    ffuf -w subdomains.txt \
    -u https://target.com \
    -H "Host: FUZZ.target.com" \
    -fs 4242 \
    -o vhosts.json

    # 5. Backup File Hunting
    ffuf -w /usr/share/seclists/Discovery/Web-Content/backup-filenames.txt \
    -u https://target.com/FUZZ \
    -t 50 \
    -mc 200 \
    -o backups.json

    # RECOMMENDED WORDLISTS
    # Common: raft-medium-directories.txt
    # Large: raft-large-directories.txt
    # API: burp-parameter-names.txt
    # Backups: backup-filenames.txt
    # Sensitive: sensitive-api-paths.txt
    # Extensions: common-extensions.txt

    # RESPONSE CODE STRATEGIES
    # 200: Valid content
    # 301/302: Redirects worth following
    # 403: Forbidden (potential interest)
    # 401: Authentication required
    # 500: Server errors (potential info leaks)
