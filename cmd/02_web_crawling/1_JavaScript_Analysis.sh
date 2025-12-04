
### 2.4 JavaScript Analysis
    # 1. ENDPOINT DISCOVERY (LinkFinder)
    # Single JS file analysis
    linkfinder -i https://target.com/main.js \
    -o endpoints.json \
    -d \ # Include DOM sinks
    -r '^/api/v[0-9]' # Filter API endpoints

    # Crawl domain for JS files and analyze
    linkfinder -i https://target.com \
    -o all_endpoints.json \
    --complete # Full analysis mode

    # 2. SECRET DISCOVERY (SecretFinder)
    # Single file secret scanning
    secretfinder -i script.js \
    -o secrets.json \
    -r high \ # Aggressive regex level
    -e entropy # Check for high entropy strings

    # Batch scan directory
    secretfinder -i js_files/ \
    -o all_secrets.json \
    -n \ # No color output
    -g "AWS|GOOGLE|TWILIO" # Custom patterns

    # 3. JS FILE COLLECTION (GetJS)
    # Download all JS from domain
    getjs --url https://target.com \
    -o js_files/ \
    -d 3 \ # Depth
    -t 20 \ # Threads
    --verbose

    # Download from subdomain list
    getjs --list live_subdomains.txt \
    -o all_js/ \
    -t 30 \
    --user-agent "Mozilla/5.0"

    # 4. JS FILE DISCOVERY (SubJS)
    # Find JS files on domain
    subjs -u https://target.com \
    -o js_urls.txt \
    -c 50 \ # Concurrency
    -t 5 \ # Timeout
    -v # Verbose

    # Find JS on multiple domains
    subjs -i domains.txt \
    -o all_js_urls.txt \
    -p https \ # Protocol
    --output-json # JSON format

    # 5. VULNERABILITY SCANNING (Retire.js)
    # Scan JS directory
    retire -j -p js_files/ \
    --outputformat json \
    --outputfile vulns.json \
    --verbose

    # Scan single file
    retire -j -p script.js \
    --exitwith 0 \
    --jspath /path/to/repo

    # ADVANCED TECHNIQUES

    # 1. DYNAMIC ANALYSIS (Browser Automation)
    # Use Puppeteer/Playwright to capture runtime JS
    node capture_js.js https://target.com -o dynamic_js/

    # 2. SOURCE MAP DECOMPILATION
    # Find and process source maps
    unwebpack sourcemap.json -o decompiled/

    # 3. AUTHENTICATED JS ANALYSIS
    # With cookies
    linkfinder -i https://target.com/app.js \
    -c "session=abc123" \
    -o auth_endpoints.json

    # With headers
    secretfinder -i https://target.com/auth.js \
    -H "Authorization: Bearer token" \
    -o auth_secrets.json

    # PRO TIPS:
    # 1. Always check for:
    #  - Source map files (*.js.map)
    #  - Minified files (*.min.js)
    #  - Runtime-loaded JS (XHR/fetch)
    # 2. Combine static and dynamic analysis
    # 3. Monitor for new JS files during recon
    # 4. Check for exposed API keys/tokens
    # 5. Correlate endpoints with other recon data

    # EXAMPLE WORKFLOW:
    # 1. Discover JS files with SubJS
    # 2. Download files with GetJS
    # 3. Extract endpoints with LinkFinder
    # 4. Find secrets with SecretFinder
    # 5. Check vulnerabilities with Retire.js

    # Combine with nuclei for vulnerability scanning: cat endpoints.json | nuclei -t exposures/
    # Use jq to process JSON results: jq '.results[] | url' linkfinder_output.json
    # Monitor for changes: watch -n 3600 getjs --url https://target.com -o js_monitor/
    # Create custom regex patterns for target-specific patterns

#### 2.4.1 Find JS files, then extract secrets