#### 2.2.3 Configuration File Discovery
    # 1. COMPREHENSIVE CONFIG FILE SCAN
    ffuf -w /usr/share/seclists/Discovery/Web-Content/Common-Files.txt \
    -u https://target.com/FUZZ \
    -t 150 \
    -mc 200,403 \
    -o ffuf_config_scan.json \
    -of json

    # 2. TARGETED CONFIG EXTENSIONS
    ffuf -w /usr/share/seclists/Discovery/Web-Content/ConfigurationFiles/extensions.txt \
    -u https://target.com/config.FUZZ \
    -t 100 \
    -mc 200,403 \
    -o ffuf_config_exts.json

    # 3. ENVIRONMENT FILE CHECK
    ffuf -w /usr/share/seclists/Discovery/Web-Content/Common-Environment-Files.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -o ffuf_env_files.json

    # 4. SERVER STATUS FILES
    ffuf -w /usr/share/seclists/Discovery/Web-Content/Apache-Httpd.txt \
    -u https://target.com/FUZZ \
    -H "Host: localhost" \
    -t 50 \
    -mc 200,403 \
    -o ffuf_apache_status.json

    # 5. NUCLEI SENSITIVE FILE SCAN
    nuclei -u https://target.com \
    -t exposures/files/ \
    -severity low,medium,high,critical \
    -o nuclei_sensitive_files.txt \
    -silent

    # ADVANCED TECHNIQUES

    # 1. CASE-INSENSITIVE SEARCH
    ffuf -w /usr/share/seclists/Discovery/Web-Content/Common-Files.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -ic \
    -o ffuf_case_insensitive.json

    # 2. BACKUP VERSIONS CHECK
    cat common_configs.txt | while read file; do
    for ext in bak old orig; do
        curl -s -o /dev/null -w "%{http_code} $file$ext\n" "https://target.com/$file$ext" | grep -v "404"
    done
    done > config_backups.txt

    # 3. DOTFILE DISCOVERY
    ffuf -w /usr/share/seclists/Discovery/Web-Content/DotFiles.txt \
    -u https://target.com/FUZZ \
    -t 100 \
    -mc 200,403 \
    -o ffuf_dotfiles.json

    # PRO TIPS:
    # 1. Always check both with and without leading dots
    # 2. Try prepending/appending version numbers (v1, _old)
    # 3. Check for compressed versions (.gz, zip, tar)
    # 4. Look for developer naming patterns (config-dev, env.local)
    # 5. Combine with waybackurls for historical config files

    # RECOMMENDED WORDLISTS:
    # /usr/share/seclists/Discovery/Web-Content/Common-Files.txt
    # /usr/share/seclists/Discovery/Web-Content/ConfigurationFiles/
    # /usr/share/seclists/Discovery/Web-Content/DotFiles.txt
    # Custom lists with target-specific naming conventions

    # EXAMPLE WORKFLOW:
    # 1. Run comprehensive config file scan
    # 2. Check for environment/config files
    # 3. Search for server status files
    # 4. Verify found configs manually (avoid downloading sensitive files)
    # 5. Check historical data (Wayback Machine)

