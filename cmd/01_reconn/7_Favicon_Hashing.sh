#### 2.2.4 Favicon Hashing for Tech/Asset Identification
    # 1. SINGLE SITE HASHING (Python)
    python3 -c 'import mmh3, requests; print(mmh3.hash(requests.get("https://target.com/favicon.ico", verify=False).content))' > favicon_hash.txt

    # 2. BATCH PROCESSING (favfreak alternative)
    while read url; do
    hash=$(python3 -c "import mmh3, requests; print(mmh3.hash(requests.get('$url/favicon.ico', verify=False).content))")
    echo "$url,$hash" >> favicon_hashes.csv
    done < live_hosts.txt

    # 3. SHODAN SEARCH
    hash=$(cat favicon_hash.txt)
    echo "Search Shodan for: http.favicon.hash:$hash"
    # Or use CLI if Shodan installed:
    shodan search --fields ip_str,port,org "http.favicon.hash:$hash"

    # 4. NUCLEI DETECTION
    nuclei -l live_hosts.txt -t technologies/favicon-detection.yaml -o nuclei_favicon_results.txt

    # 5. AUTOMATED TOOL (FavFreak alternative)
    # Install: pip install favicon-hash
    faviconhash -i live_hosts.txt -o results.json

    # ADVANCED TECHNIQUES

    # 1. ALTERNATIVE HASHING (for non-ico favicons)
    curl -s https://target.com/favicon.png | md5sum | cut -d' ' -f1

    # 2. FAVICON LOCATION DISCOVERY
    curl -s https://target.com/ | grep -E 'rel="(shortcut )?icon"' | grep -Eo 'href="[^"]+'

    # 3. HISTORICAL FAVICONS (Wayback Machine)
    waybackurls target.com | grep -i 'favicon\.ico' | sort -u

    # 4. CUSTOM FAVICON DB
    # Create your own fingerprint database:
    echo "hash,technology" > favicon_db.csv
    echo "-123456789,WordPress" >> favicon_db.csv
    echo "987654321,Drupal" >> favicon_db.csv

    # PRO TIPS:
    # 1. Always check multiple favicon locations:
    #  - /favicon.ico
    #  - /assets/favicon.ico
    #  - /static/favicon.ico
    # 2. Compare hashes from staging vs production
    # 3. Check for different favicons on different subdomains
    # 4. Use with other fingerprinting methods for better accuracy
    # 5. Monitor for favicon changes that might indicate system updates

    # EXAMPLE WORKFLOW:
    # 1. Collect favicon from target
    # 2. Calculate mmh3 hash
    # 3. Search Shodan for matching hashes
    # 4. Check against known technology hashes
    # 5. Correlate with other recon data

