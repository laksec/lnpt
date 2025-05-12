### 1.5 Technology Fingerprinting
    # WHATWEB (Comprehensive fingerprinting)
    # Verbose scan with aggressive detection
    whatweb https://target.com -v -a 3 --color=never -o whatweb_single.txt

    # Batch scan with XML output
    whatweb -i live_subdomains.txt -U "Mozilla/5.0" --log-xml=whatweb_report.xml

    # Targeted plugin scan
    whatweb https://target.com --plugins=Apache,PHP,WordPress,Joomla --no-errors

    # WEBANALYZE (Alternative fingerprinting)
    # Single host analysis
    webanalyze -host https://target.com -output webanalyze_single.json

    # Crawl and analyze multiple hosts
    webanalyze -hosts live_hosts.txt -crawl 2 -output webanalyze_crawled.json

    # HTTPX (Fast tech detection)
    # Basic tech detection with status
    httpx -l urls.txt -tech-detect -status-code -title -o httpx_basic.txt

    # Full tech detection with screenshots
    httpx -l urls.txt -tech-detect -screenshot -favicon -json -o httpx_full.json

    # RECOMMENDED WORKFLOW:
    # 1. Start with httpx for quick tech detection
    # 2. Use WhatWeb for detailed fingerprinting
    # 3. Run WebAnalyze for additional verification
    # 4. Combine results for comprehensive view

    # PRO TIPS:
    # For stealth: Rotate user agents with '-U random' in WhatWeb
    # For large scans: Add '-t 50' to increase threads in httpx
    # To compare results: 'jq' for JSON output analysis
    # For monitoring: Schedule regular scans with cron