### 2.5 Screenshotting and Visual Recon
    # 1. GOWITNESS (Chrome-based screenshots)
    # Batch screenshot from URL list
    gowitness file -f live_urls.txt \
    -P screenshots/ \
    --delay 3 \
    --resolution "1920x1080" \
    --user-agent "Mozilla/5.0" \
    --full-page

    # Screenshot from Nmap scan
    gowitness nmap -f scan.xml \
    -P nmap_screenshots/ \
    --threads 20

    # Single URL with custom timeout
    gowitness single https://target.com/admin \
    -o admin.png \
    --timeout 30

    # 2. AQUATONE (Full reconnaissance)
    # Comprehensive subdomain screenshotting
    cat subdomains.txt | aquatone \
    -ports large \
    -scan-timeout 2000 \
    -threads 50 \
    -out aquatone_report \
    -screenshot-timeout 30000

    # HTTPX-based screenshotting
    httpx -l urls.txt \
    -ss \ # Take screenshots
    -srd screenshots/ \
    -timeout 10 \
    -threads 100 \
    -retries 2

    # 3. ADVANCED TECHNIQUES
    # Screenshot only 200 OK pages
    httpx -l urls.txt -status-code -ss -srd screenshots_ok/ -mc 200

    # Screenshot with authentication
    gowitness file -f auth_urls.txt \
    -P auth_screenshots/ \
    --chrome-arg "--user-data-dir=/path/to/chrome/profile"

    # Compare screenshots over time
    compare-screenshots old_screenshots/ new_screenshots/ -o diff_report.html

    # PRO TIPS:
    # 1. Always use full-page screenshots (-F in gowitness)
    # 2. For JavaScript-heavy sites, increase delay (--delay 5)
    # 3. Store screenshots with timestamped folders
    # 4. Combine with visual diff tools to detect changes
    # 5. Use custom Chrome profiles for authenticated areas

    # EXAMPLE WORKFLOW:
    # 1. Discover URLs with subdomain enumeration
    # 2. Filter live sites with httpx
    # 3. Take screenshots with gowitness/aquatone
    # 4. Analyze visually for interesting content
    # 5. Monitor changes with scheduled screenshots

    # RECOMMENDED SETTINGS:
    # Resolution: 1920x1080 or 1280x1024
    # Delay: 3-5 seconds for JS sites
    # Threads: 20-50 depending on hardware
    # Timeout: 30-60 seconds for slow sites

    # SCREENSHOT MONITORING:
    # Add to crontab for daily screenshots:
    0 3 * * * gowitness file -f urls.txt -P /path/to/screenshots/$(date +\%Y-\%m-\%d)