
### 2.2 Content Discovery
    :- FEROXBUSTER (Fast, Rust-based)
    feroxbuster -u https://target.com -w wordlist.txt -t 50 -o ferox_results.txt
    feroxbuster -u https://target.com -w wordlist.txt -x php,html -n -k -C 404,403

    :- FFUF (Highly customizable)
    :- Basic scan
    ffuf -w wordlist.txt -u https://target.com/FUZZ -o ffuf_basic.json

    :- Advanced scan (filter custom 404s)
    ffuf -w wordlist.txt -u https://target.com/FUZZ -t 100 -fs 4242 -mc 200,301,302 -o ffuf_advanced.json

    :- Virtual host discovery
    ffuf -w subdomains.txt -u https://target.com -H "Host: FUZZ.target.com" -o vhosts.json

    :- DIRSEARCH (Python-based)
    dirsearch -u https://target.com -e php,asp,aspx,jsp,html -t 100 -x 403,404 --format=json -o dirsearch_out.json

    :- GOBUSTER (Go-based)
    :- Standard scan
    gobuster dir -u https://target.com -w wordlist.txt -x php,html -o gobuster.txt

    :- DNS mode (subdomain brute-forcing)
    gobuster dns -d target.com -w subdomains.txt -o dns_brute.txt

    :- WFUZZ (Python-based)
    wfuzz -c -z file,wordlist.txt --hc 404,400 https://target.com/FUZZ
    wfuzz -c -z file,wordlist.txt --sc 200 -H "X-Custom-Header: test" https://target.com/FUZZ

    :- ======================
    :- COMMON CRAWL QUERIES
    :- ======================

    :- Using cc-index-client (requires setup)
    cc-index-client --query "url=target.com/admin" --output cc_admin_paths.json

    :- Alternative API approach
    curl "https://index.commoncrawl.org/CC-MAIN-2023-23-index?url=target.com/login&output=json" | jq

    :- ======================
    :- RESPONSE CODE STRATEGIES
    :- ======================

    :- 1. Filtering custom 404s (find the size first)
    curl -s -o /dev/null -w "%{size_download}" https://target.com/random404page
    :- Then use with ffuf: -fs 1234

    :- 2. Tracking redirect chains
    ffuf -w wordlist.txt -u https://target.com/FUZZ -fr "redirects-to:login" -o redirects.json

    :- 3. Finding debug endpoints
    ffuf -w wordlist.txt -u https://target.com/FUZZ -mr "DEBUG" -o debug_pages.json

    :- ======================
    :- PRO TIPS:
    :- 1. Always find and filter custom 404 pages first
    :- 2. For WordPress: use '-w /usr/share/wordlists/wfuzz/general/common.txt'
    :- 3. Rotate user agents with '-H "User-Agent: random"'
    :- 4. For API discovery: add '-x json' extension
    :- 5. Combine with nuclei: 'cat valid_paths.txt | nuclei -t exposures/'
    :- ======================

    :- RECOMMENDED WORDLISTS:
    :- /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    :- /usr/share/wordlists/dirb/common.txt
    :- /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
    :- Custom lists based on target tech (e.g., wp-content for WordPress)

#### 2.2.1 Directory/File Brute Forcing
    :- FFUF (Most versatile)
    :- Fast recursive scan with common extensions
    ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -u https://target.com/FUZZ \
    -t 200 \
    -recursion \
    -recursion-depth 2 \
    -e .php,.html,.js,.json \
    -o ffuf_recursive.json \
    -of json \
    -v

    :- API endpoint discovery
    ffuf -w /usr/share/seclists/Discovery/Web-Content/api/endpoints.txt \
    -u https://target.com/api/FUZZ \
    -t 150 \
    -mc 200,201,204 \
    -H "Authorization: Bearer token" \
    -o ffuf_api.json

    :- FEROXBUSTER (Fast Rust-based)
    :- Comprehensive scan with smart filtering
    feroxbuster -u https://target.com \
    -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
    -t 50 \
    -x php,html,js \
    -d 3 \
    --filter-status 404,403 \
    --extract-links \
    --auto-tune \
    -o ferox_full.txt

    :- DIRSEARCH (Python-based)
    :- Deep scan with backup file checking
    dirsearch -u https://target.com \
    -e php,asp,aspx,jsp,html,js,json \
    -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt \
    -t 100 \
    -r -R 2 \
    --exclude-status 404,500 \
    --random-agents \
    -o dirsearch_deep.json \
    --format=json

    :- GOBUSTER (Simple Go-based)
    :- Quick scan with common extensions
    gobuster dir -u https://target.com \
    -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
    -x php,html,js \
    -t 100 \
    -k \
    -o gobuster_quick.txt

    :- WFuzz (Advanced filtering)
    :- Parameter fuzzing with regex filtering
    wfuzz -c \
    -z file,/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -H "Content-Type: application/json" \
    --hh 0 \
    --hc 404 \
    --filter "s>0" \
    https://target.com/api/search?FUZZ=test

    :- PRO TIPS & ADVANCED TECHNIQUES

    :- 1. Custom 404 Handling
    :- First find 404 page size:
    curl -s -o /dev/null -w "%{size_download}" https://target.com/nonexistentpage
    :- Then use in ffuf: -fs 1234

    :- 2. Smart Recursion
    :- Only recurse into promising paths:
    ffuf -w wordlist.txt -u https://target.com/FUZZ \
    -recursion \
    -recursion-strategy greedy \
    -recursion-depth 3

    :- 3. JWT Token Fuzzing
    ffuf -w /usr/share/seclists/Discovery/Web-Content/jwt-tokens.txt \
    -u https://target.com/api \
    -H "Authorization: Bearer FUZZ" \
    -mc 200,403

    :- 4. Virtual Host Discovery
    ffuf -w subdomains.txt \
    -u https://target.com \
    -H "Host: FUZZ.target.com" \
    -fs 4242 \
    -o vhosts.json

    :- 5. Backup File Hunting
    ffuf -w /usr/share/seclists/Discovery/Web-Content/backup-filenames.txt \
    -u https://target.com/FUZZ \
    -t 50 \
    -mc 200 \
    -o backups.json

    :- RECOMMENDED WORDLISTS
    :- Common: raft-medium-directories.txt
    :- Large: raft-large-directories.txt
    :- API: burp-parameter-names.txt
    :- Backups: backup-filenames.txt
    :- Sensitive: sensitive-api-paths.txt
    :- Extensions: common-extensions.txt

    :- RESPONSE CODE STRATEGIES
    :- 200: Valid content
    :- 301/302: Redirects worth following
    :- 403: Forbidden (potential interest)
    :- 401: Authentication required
    :- 500: Server errors (potential info leaks)

#### 2.2.2 Backup & Temporary File Fuzzing
    :- 1. COMPREHENSIVE BACKUP SCAN (All common extensions)
    ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
    -u https://target.com/FUZZ \
    -e .bak,.old,.zip,.tar.gz,.sql,.conf,.config,.swp,~,.backup,.bkp,.save,.orig,.copy \
    -t 150 \
    -mc 200,403 \
    -o ffuf_backup_scan.json \
    -of json

    :- 2. TARGETED FILENAME SCAN (Common sensitive files)
    ffuf -w /usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt \
    -u https://target.com/FUZZ \
    -e .bak,.old,.sql \
    -t 100 \
    -mc 200 \
    -o ffuf_sensitive_backups.json

    :- 3. USER DIRECTORY CHECK (Tilde convention)
    ffuf -w /usr/share/seclists/Discovery/Web-Content/User-Directories.txt \
    -u https://target.com/~FUZZ \
    -t 50 \
    -mc 200,403 \
    -o ffuf_user_dirs.json

    :- 4. VERSION CONTROL FILES
    ffuf -w /usr/share/seclists/Discovery/Web-Content/VersionControlFiles.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -o ffuf_vcs_files.json

    :- 5. ENVIRONMENT FILES
    ffuf -w /usr/share/seclists/Discovery/Web-Content/Common-Environment-Files.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -o ffuf_env_files.json

    :- ADVANCED TECHNIQUES

    :- 1. TIMESTAMPED BACKUPS
    :- Find backups with date patterns
    for pattern in {2020..2023}{01..12}{01..31}; do
    curl -s -o /dev/null -w "%{http_code} " "https://target.com/db_backup_$pattern.sql"
    done | grep -v "404" > dated_backups.txt

    :- 2. INCREMENTAL BACKUPS
    :- Check for numbered backups
    seq 1 10 | xargs -I{} curl -s -o /dev/null -w "%{http_code} backup_{}.zip\n" "https://target.com/backup_{}.zip" \
    | grep -v "404"

    :- 3. CASE VARIATIONS
    :- Check case-sensitive backups
    cat common_files.txt | while read file; do
    for ext in .BAK .OLD .Backup; do
        curl -s -o /dev/null -w "%{http_code} $file$ext\n" "https://target.com/$file$ext" | grep -v "404"
    done
    done

    :- PRO TIPS:
    :- 1. Always check both with and without extensions
    :- 2. Try prepending/appending version numbers (v1, _old)
    :- 3. Check for compressed versions (.gz, .zip, .tar)
    :- 4. Look for developer naming patterns (final, test, temp)
    :- 5. Combine with waybackurls for historical backups

    :- RECOMMENDED WORDLISTS:
    :- /usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt
    :- /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
    :- /usr/share/seclists/Discovery/Web-Content/VersionControlFiles.txt
    :- Custom lists with target-specific naming conventions

    :- EXAMPLE WORKFLOW:
    :- 1. Run comprehensive backup scan
    :- 2. Check for version control files
    :- 3. Search for environment/config files
    :- 4. Verify found backups manually
    :- 5. Check historical data (Wayback Machine)

#### 2.2.3 Configuration File Discovery
    :- 1. COMPREHENSIVE CONFIG FILE SCAN
    ffuf -w /usr/share/seclists/Discovery/Web-Content/Common-Files.txt \
    -u https://target.com/FUZZ \
    -t 150 \
    -mc 200,403 \
    -o ffuf_config_scan.json \
    -of json

    :- 2. TARGETED CONFIG EXTENSIONS
    ffuf -w /usr/share/seclists/Discovery/Web-Content/ConfigurationFiles/extensions.txt \
    -u https://target.com/config.FUZZ \
    -t 100 \
    -mc 200,403 \
    -o ffuf_config_exts.json

    :- 3. ENVIRONMENT FILE CHECK
    ffuf -w /usr/share/seclists/Discovery/Web-Content/Common-Environment-Files.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -o ffuf_env_files.json

    :- 4. SERVER STATUS FILES
    ffuf -w /usr/share/seclists/Discovery/Web-Content/Apache-Httpd.txt \
    -u https://target.com/FUZZ \
    -H "Host: localhost" \
    -t 50 \
    -mc 200,403 \
    -o ffuf_apache_status.json

    :- 5. NUCLEI SENSITIVE FILE SCAN
    nuclei -u https://target.com \
    -t exposures/files/ \
    -severity low,medium,high,critical \
    -o nuclei_sensitive_files.txt \
    -silent

    :- ADVANCED TECHNIQUES

    :- 1. CASE-INSENSITIVE SEARCH
    ffuf -w /usr/share/seclists/Discovery/Web-Content/Common-Files.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -ic \
    -o ffuf_case_insensitive.json

    :- 2. BACKUP VERSIONS CHECK
    cat common_configs.txt | while read file; do
    for ext in .bak .old .orig; do
        curl -s -o /dev/null -w "%{http_code} $file$ext\n" "https://target.com/$file$ext" | grep -v "404"
    done
    done > config_backups.txt

    :- 3. DOTFILE DISCOVERY
    ffuf -w /usr/share/seclists/Discovery/Web-Content/DotFiles.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -o ffuf_dotfiles.json

    :- PRO TIPS:
    :- 1. Always check both with and without leading dots
    :- 2. Try prepending/appending version numbers (v1, _old)
    :- 3. Check for compressed versions (.gz, .zip, .tar)
    :- 4. Look for developer naming patterns (config-dev, .env.local)
    :- 5. Combine with waybackurls for historical config files

    :- RECOMMENDED WORDLISTS:
    :- /usr/share/seclists/Discovery/Web-Content/Common-Files.txt
    :- /usr/share/seclists/Discovery/Web-Content/ConfigurationFiles/
    :- /usr/share/seclists/Discovery/Web-Content/DotFiles.txt
    :- Custom lists with target-specific naming conventions

    :- EXAMPLE WORKFLOW:
    :- 1. Run comprehensive config file scan
    :- 2. Check for environment/config files
    :- 3. Search for server status files
    :- 4. Verify found configs manually (avoid downloading sensitive files)
    :- 5. Check historical data (Wayback Machine)
#### 2.2.4 Favicon Hashing for Tech/Asset Identification
    :- 1. SINGLE SITE HASHING (Python)
    python3 -c 'import mmh3, requests; print(mmh3.hash(requests.get("https://target.com/favicon.ico", verify=False).content))' > favicon_hash.txt

    :- 2. BATCH PROCESSING (favfreak alternative)
    while read url; do
    hash=$(python3 -c "import mmh3, requests; print(mmh3.hash(requests.get('$url/favicon.ico', verify=False).content))")
    echo "$url,$hash" >> favicon_hashes.csv
    done < live_hosts.txt

    :- 3. SHODAN SEARCH
    hash=$(cat favicon_hash.txt)
    echo "Search Shodan for: http.favicon.hash:$hash"
    :- Or use CLI if Shodan installed:
    shodan search --fields ip_str,port,org "http.favicon.hash:$hash"

    :- 4. NUCLEI DETECTION
    nuclei -l live_hosts.txt -t technologies/favicon-detection.yaml -o nuclei_favicon_results.txt

    :- 5. AUTOMATED TOOL (FavFreak alternative)
    :- Install: pip install favicon-hash
    faviconhash -i live_hosts.txt -o results.json

    :- ADVANCED TECHNIQUES

    :- 1. ALTERNATIVE HASHING (for non-ico favicons)
    curl -s https://target.com/favicon.png | md5sum | cut -d' ' -f1

    :- 2. FAVICON LOCATION DISCOVERY
    curl -s https://target.com/ | grep -E 'rel="(shortcut )?icon"' | grep -Eo 'href="[^"]+'

    :- 3. HISTORICAL FAVICONS (Wayback Machine)
    waybackurls target.com | grep -i 'favicon\.ico' | sort -u

    :- 4. CUSTOM FAVICON DB
    :- Create your own fingerprint database:
    echo "hash,technology" > favicon_db.csv
    echo "-123456789,WordPress" >> favicon_db.csv
    echo "987654321,Drupal" >> favicon_db.csv

    :- PRO TIPS:
    :- 1. Always check multiple favicon locations:
    :-    - /favicon.ico
    :-    - /assets/favicon.ico
    :-    - /static/favicon.ico
    :- 2. Compare hashes from staging vs production
    :- 3. Check for different favicons on different subdomains
    :- 4. Use with other fingerprinting methods for better accuracy
    :- 5. Monitor for favicon changes that might indicate system updates

    :- EXAMPLE WORKFLOW:
    :- 1. Collect favicon from target
    :- 2. Calculate mmh3 hash
    :- 3. Search Shodan for matching hashes
    :- 4. Check against known technology hashes
    :- 5. Correlate with other recon data

#### 2.2.5 Source Code/VCS Exposure Discovery
    :- 1. GIT REPOSITORY DISCOVERY & DUMPING
    :- Check for exposed .git
    ffuf -w /usr/share/seclists/Discovery/Web-Content/git.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -o git_scan.json

    :- Dump found repositories
    git-dumper https://target.com/.git/ git_dump --threads 10

    :- 2. SVN REPOSITORY DISCOVERY
    :- Check for exposed .svn
    ffuf -w /usr/share/seclists/Discovery/Web-Content/svn.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -o svn_scan.json

    :- Extract SVN info (alternative)
    svn export http://target.com/.svn/ svn_dump --force

    :- 3. DS_STORE FILES
    :- Find exposed .DS_Store
    ffuf -w /usr/share/seclists/Discovery/Web-Content/dsstore.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -o ds_store_scan.json

    :- Parse found .DS_Store
    ds_store_parser http://target.com/.DS_Store -o parsed_ds_store.txt

    :- 4. COMPREHENSIVE VCS SCAN
    nuclei -u https://target.com \
    -t exposures/version-control/ \
    -severity medium,high,critical \
    -o nuclei_vcs_scan.txt

    :- 5. AUTOMATED TOOLS
    :- GitHound (for GitHub-related leaks)
    python3 gitHound.py -k keywords.txt -t target.com -o githound_results.json

    :- TruffleHog (secret scanning)
    trufflehog git --extra-checks https://target.com/.git/

    :- ADVANCED TECHNIQUES

    :- 1. HISTORICAL VCS FILES (Wayback)
    waybackurls target.com | grep -E '\.(git|svn|hg|DS_Store)' | sort -u

    :- 2. GIT RECONSTRUCTION
    :- When full dump isn't possible
    git-extractor --partial --url https://target.com/.git/ --output partial_git

    :- 3. SVN ENUMERATION
    svn list http://target.com/.svn/ --depth infinity

    :- 4. METADATA ANALYSIS
    :- Extract interesting files from dumps
    find git_dump -type f -exec grep -l "password\|secret\|key" {} \;

    :- PRO TIPS:
    :- 1. Always check for:
    :-    - /.git/HEAD
    :-    - /.svn/entries
    :-    - /.DS_Store
    :-    - /CVS/Root
    :-    - /.hg/store
    :- 2. Look for backup files (*.git.tar.gz, *.svn.zip)
    :- 3. Check developer naming patterns (git_backup, old_svn)
    :- 4. Combine with other recon data
    :- 5. Be ethical - don't download proprietary code without permission

    :- RECOMMENDED WORDLISTS:
    :- /usr/share/seclists/Discovery/Web-Content/git.txt
    :- /usr/share/seclists/Discovery/Web-Content/svn.txt
    :- /usr/share/seclists/Discovery/Web-Content/dsstore.txt
    :- /usr/share/seclists/Discovery/Web-Content/CVS.txt

    :- EXAMPLE WORKFLOW:
    :- 1. Scan for VCS metadata files
    :- 2. Verify findings manually
    :- 3. Dump repositories if exposed
    :- 4. Search for secrets in dumped files
    :- 5. Check historical data (Wayback Machine)