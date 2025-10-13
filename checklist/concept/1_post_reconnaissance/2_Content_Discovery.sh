
### 2.2 Content Discovery
    # FEROXBUSTER (Fast, Rust-based)
    feroxbuster -u https://target.com -w wordlist.txt -t 50 -o ferox_results.txt
    feroxbuster -u https://target.com -w wordlist.txt -x php,html -n -k -C 404,403

    # FFUF (Highly customizable)
    # Basic scan
    ffuf -w wordlist.txt -u https://target.com/FUZZ -o ffuf_basic.json

    # Advanced scan (filter custom 404s)
    ffuf -w wordlist.txt -u https://target.com/FUZZ -t 100 -fs 4242 -mc 200,301,302 -o ffuf_advanced.json

    # Virtual host discovery
    ffuf -w subdomains.txt -u https://target.com -H "Host: FUZZ.target.com" -o vhosts.json

    # DIRSEARCH (Python-based)
    dirsearch -u https://target.com -e php,asp,aspx,jsp,html -t 100 -x 403,404 --format=json -o dirsearch_out.json

    # GOBUSTER (Go-based)
    # Standard scan
    gobuster dir -u https://target.com -w wordlist.txt -x php,html -o gobuster.txt

    # DNS mode (subdomain brute-forcing)
    gobuster dns -d target.com -w subdomains.txt -o dns_brute.txt

    # WFUZZ (Python-based)
    wfuzz -c -z file,wordlist.txt --hc 404,400 https://target.com/FUZZ
    wfuzz -c -z file,wordlist.txt --sc 200 -H "X-Custom-Header: test" https://target.com/FUZZ

    # ======================
    # COMMON CRAWL QUERIES
    # ======================

    # Using cc-index-client (requires setup)
    cc-index-client --query "url=target.com/admin" --output cc_admin_paths.json

    # Alternative API approach
    curl "https://index.commoncrawl.org/CC-MAIN-2023-23-index?url=target.com/login&output=json" | jq

    # ======================
    # RESPONSE CODE STRATEGIES
    # ======================

    # 1. Filtering custom 404s (find the size first)
    curl -s -o /dev/null -w "%{size_download}" https://target.com/random404page
    # Then use with ffuf: -fs 1234

    # 2. Tracking redirect chains
    ffuf -w wordlist.txt -u https://target.com/FUZZ -fr "redirects-to:login" -o redirects.json

    # 3. Finding debug endpoints
    ffuf -w wordlist.txt -u https://target.com/FUZZ -mr "DEBUG" -o debug_pages.json

    # ======================
    # PRO TIPS:
    # 1. Always find and filter custom 404 pages first
    # 2. For WordPress: use '-w /usr/share/wordlists/wfuzz/general/common.txt'
    # 3. Rotate user agents with '-H "User-Agent: random"'
    # 4. For API discovery: add '-x json' extension
    # 5. Combine with nuclei: 'cat valid_paths.txt | nuclei -t exposures/'
    # ======================

    # RECOMMENDED WORDLISTS:
    # /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    # /usr/share/wordlists/dirb/common.txt
    # /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
    # Custom lists based on target tech (e.g., wp-content for WordPress)

