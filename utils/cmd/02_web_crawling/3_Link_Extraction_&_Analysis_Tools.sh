
### 2.6 Link Extraction & Analysis Tools
    # 1. JAVASCRIPT LINK EXTRACTION (LinkFinder)
    # Single JS file analysis
    linkfinder -i https://target.com/main.js -o js_endpoints.txt

    # Discover and analyze all JS files on domain
    linkfinder -i https://target.com/ -d -o all_js_links.json --json

    # Filter for API endpoints only
    linkfinder -i https://target.com/*.js -r '^/api/' -o api_endpoints.txt

    # 2. PAGE LINK EXTRACTION (Custom Tools)
    # Extract all links from page (Python example)
    python3 -c 'import requests, lxml.html; print("\n".join(lxml.html.fromstring(requests.get("https://target.com").content).xpath("//@href")))' > page_links.txt

    # Alternative with httpx + pup
    httpx -u https://target.com -silent | pup 'a[href] attr{href}' > links.txt

    # 3. ADVANCED TECHNIQUES
    # Extract links from multiple pages
    cat urls.txt | while read url; do
    curl -s $url | grep -Eo 'href="[^"]+"' | sed 's/href="//;s/"$//'
    done > all_links.txt

    # Find hidden API endpoints in JS
    linkfinder -i https://target.com/app.js --complete | grep -E 'fetch|axios|XMLHttpRequest'

    # 4. COMBINED WORKFLOW
    # Step 1: Find all JS files
    subjs -u https://target.com -o js_files.txt

    # Step 2: Extract links from JS
    linkfinder -i js_files.txt -o js_links.json --json

    # Step 3: Extract page links
    getlinks -i https://target.com -o page_links.txt

    # ======================
    # PRO TIPS:
    # 1. Always check both minified and unminified JS
    # 2. Look for links in:
    #  - href/src attributes
    #  - JavaScript strings
    #  - API calls (fetch/XHR)
    #  - WebSocket connections
    # 3. Normalize relative URLs
    # 4. Filter out common CDN/external links
    # 5. Combine with other recon data
    # ======================

    # EXAMPLE WORKFLOW:
    # 1. Discover JS files with subjs
    # 2. Extract links with LinkFinder
    # 3. Crawl pages with getlinks
    # 4. Combine and deduplicate results
    # 5. Analyze for sensitive endpoints

    # RECOMMENDED TOOLS:
    #  - LinkFinder (JS analysis)
    #  - httpx + pup (HTML extraction)
    #  - unfurl (URL normalization)
    #  - gau (historical links)
    #  - waybackurls (archived links)

    # SAMPLE GETLINKS.PY IMPLEMENTATION:
    """
    import sys
    import requests
    from bs4 import BeautifulSoup

    url = sys.argv[1]
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    links = [a['href'] for a in soup.find_all('href')]
    print('\n'.join(links))
    """

    # Combine with unfurl to normalize URLs: cat links.txt | unfurl format %d%p
    # Find hidden WebSocket endpoints: grep -E 'wss?://' js_files/*.js
    # Extract links from CSS: grep -Eo 'url\([^)]+' *.css