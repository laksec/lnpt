
#### 2.2.2 Backup & Temporary File Fuzzing
    # 1. COMPREHENSIVE BACKUP SCAN (All common extensions)
    ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
    -u https://target.com/FUZZ \
    -e bak,.old,.zip,.tar.gz,.sql,.conf,.config,.swp,~,.backup,.bkp,.save,.orig,.copy \
    -t 150 \
    -mc 200,403 \
    -o ffuf_backup_scan.json \
    -of json

    # 2. TARGETED FILENAME SCAN (Common sensitive files)
    ffuf -w /usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt \
    -u https://target.com/FUZZ \
    -e bak,.old,.sql \
    -t 100 \
    -mc 200 \
    -o ffuf_sensitive_backups.json

    # 3. USER DIRECTORY CHECK (Tilde convention)
    ffuf -w /usr/share/seclists/Discovery/Web-Content/User-Directories.txt \
    -u https://target.com/~FUZZ \
    -t 50 \
    -mc 200,403 \
    -o ffuf_user_dirs.json

    # 4. VERSION CONTROL FILES
    ffuf -w /usr/share/seclists/Discovery/Web-Content/VersionControlFiles.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -o ffuf_vcs_files.json

    # 5. ENVIRONMENT FILES
    ffuf -w /usr/share/seclists/Discovery/Web-Content/Common-Environment-Files.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -o ffuf_env_files.json

    # ADVANCED TECHNIQUES

    # 1. TIMESTAMPED BACKUPS
    # Find backups with date patterns
    for pattern in {2020..2023}{01..12}{01..31}; do
    curl -s -o /dev/null -w "%{http_code} " "https://target.com/db_backup_$pattern.sql"
    done | grep -v "404" > dated_backups.txt

    # 2. INCREMENTAL BACKUPS
    # Check for numbered backups
    seq 1 10 | xargs -I{} curl -s -o /dev/null -w "%{http_code} backup_{}.zip\n" "https://target.com/backup_{}.zip" \
    | grep -v "404"

    # 3. CASE VARIATIONS
    # Check case-sensitive backups
    cat common_files.txt | while read file; do
    for ext in BAK OLD Backup; do
        curl -s -o /dev/null -w "%{http_code} $file$ext\n" "https://target.com/$file$ext" | grep -v "404"
    done
    done

    # PRO TIPS:
    # 1. Always check both with and without extensions
    # 2. Try prepending/appending version numbers (v1, _old)
    # 3. Check for compressed versions (.gz, zip, tar)
    # 4. Look for developer naming patterns (final, test, temp)
    # 5. Combine with waybackurls for historical backups

    # RECOMMENDED WORDLISTS:
    # /usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt
    # /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
    # /usr/share/seclists/Discovery/Web-Content/VersionControlFiles.txt
    # Custom lists with target-specific naming conventions

    # EXAMPLE WORKFLOW:
    # 1. Run comprehensive backup scan
    # 2. Check for version control files
    # 3. Search for environment/config files
    # 4. Verify found backups manually
    # 5. Check historical data (Wayback Machine)

