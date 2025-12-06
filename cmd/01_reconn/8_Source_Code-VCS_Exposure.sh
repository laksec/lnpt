# SOURCE CODE/VCS EXPOSURE DISCOVERY - COMMAND LINE TOOLS (FOR FILES)

## 1. GIT REPOSITORY DISCOVERY

# Check for exposed .git directories
while read url; do
    curl -s "$url/.git/HEAD" -I | head -1 | grep -q "200" && echo "$url/.git/"
done < urls.txt > git_exposed.txt

# Check multiple .git locations
while read url; do
    for loc in .git/ .git/HEAD .git/index .git/config; do
        curl -s "$url/$loc" -I | head -1 | grep -q "200" && echo "$url/$loc"
    done
done < urls.txt > git_all_checks.txt

# GitDumper scan
while read url; do
    python3 gitdumper.py "$url/.git/" "git_dump_$(echo $url | sed 's/[^a-zA-Z0-9]/_/g')/"
done < git_exposed.txt


## 2. GITHUB/GITLAB INFORMATION GATHERING

# Search GitHub for target domains
while read domain; do
    gitleaks --repo-path . --config-path gitleaks.toml --verbose --report "gitleaks_${domain//./_}.json"
    echo "$domain" >> github_search.txt
done < domains.txt

# GitRob scan for exposed secrets
while read domain; do
    gitrob -domain "$domain" -output "gitrob_${domain//./_}.json"
done < domains.txt


## 3. SVN (SUBVERSION) DISCOVERY

# Check for exposed .svn directories
while read url; do
    curl -s "$url/.svn/entries" -I | head -1 | grep -q "200" && echo "$url/.svn/"
done < urls.txt > svn_exposed.txt

# Check multiple SVN locations
while read url; do
    for loc in .svn/ .svn/entries .svn/wc.db .svn/format; do
        curl -s "$url/$loc" -I | head -1 | grep -q "200" && echo "$url/$loc"
    done
done < urls.txt > svn_all_checks.txt


## 4. MERCURIAL (HG) DISCOVERY

# Check for exposed .hg directories
while read url; do
    curl -s "$url/.hg/requires" -I | head -1 | grep -q "200" && echo "$url/.hg/"
done < urls.txt > hg_exposed.txt


## 5. BITKEEPER (BK) DISCOVERY

# Check for BitKeeper repositories
while read url; do
    curl -s "$url/BitKeeper/etc/ignore" -I | head -1 | grep -q "200" && echo "$url/BitKeeper/"
done < urls.txt > bk_exposed.txt


## 6. CVS DISCOVERY

# Check for CVS repositories
while read url; do
    curl -s "$url/CVS/Root" -I | head -1 | grep -q "200" && echo "$url/CVS/"
done < urls.txt > cvs_exposed.txt


## 7. BAZAAR (BZR) DISCOVERY

# Check for Bazaar repositories
while read url; do
    curl -s "$url/.bzr/README" -I | head -1 | grep -q "200" && echo "$url/.bzr/"
done < urls.txt > bzr_exposed.txt


## 8. DARC DISCOVERY

# Check for Darcs repositories
while read url; do
    curl -s "$url/_darcs/format" -I | head -1 | grep -q "200" && echo "$url/_darcs/"
done < urls.txt > darcs_exposed.txt


## 9. SOURCE CODE LEAK DISCOVERY

# Check for source code backups
while read url; do
    for ext in .tar.gz .tar.bz2 .zip .rar .7z .tgz .tar; do
        curl -s "$url/source$ext" -I | head -1 | grep -q "200" && echo "$url/source$ext"
        curl -s "$url/backup$ext" -I | head -1 | grep -q "200" && echo "$url/backup$ext"
        curl -s "$url/code$ext" -I | head -1 | grep -q "200" && echo "$url/code$ext"
    done
done < urls.txt > source_backups.txt


## 10. GITHUB SECRET SCANNING

# Scan GitHub repositories for secrets
while read repo_url; do
    trufflehog --regex --entropy=False "$repo_url" >> trufflehog_results.txt
done < github_repos.txt

# Gitleaks for repo scanning
while read repo_path; do
    gitleaks detect --source "$repo_path" --report "gitleaks_$(basename $repo_path).json"
done < local_repos.txt


## 11. NUCLEI TEMPLATES FOR VCS

# Scan for VCS exposures with nuclei
nuclei -l urls.txt -t ~/nuclei-templates/exposures/git/ -o nuclei_git_exposure.txt
nuclei -l urls.txt -t ~/nuclei-templates/exposures/configs/ -o nuclei_vcs_configs.txt


## 12. DVCS-RIPPER (GIT DUMPING)

# Dump exposed git repositories
while read git_url; do
    dvcs-ripper.pl --git "$git_url" -o "git_dump_$(echo $git_url | sed 's/[^a-zA-Z0-9]/_/g')"
done < git_exposed.txt


## 13. GIT EXTRACTION TOOLS

# GitTools for dumping and extracting
while read git_url; do
    # Dump git
    ./gitdumper.sh "$git_url" "dump_$(echo $git_url | sed 's/[^a-zA-Z0-9]/_/g')"
    
    # Extract git
    ./extractor.sh "dump_$(echo $git_url | sed 's/[^a-zA-Z0-9]/_/g')" "extracted_$(echo $git_url | sed 's/[^a-zA-Z0-9]/_/g')"
done < git_exposed.txt


## 14. LOG FILE DISCOVERY IN VCS

# Check for log files in repositories
while read vcs_url; do
    base_url=$(echo "$vcs_url" | sed 's/\/\.git\/$//;s/\/\.svn\/$//;s/\/\.hg\/$//')
    for log in git.log svn.log hg.log; do
        curl -s "$base_url/$log" -I | head -1 | grep -q "200" && echo "$base_url/$log"
    done
done < vcs_exposed.txt > vcs_logs.txt


## 15. SOURCE CODE DIRECTORY LISTINGS

# Check for directory listings with source code
while read url; do
    curl -s "$url/src/" | grep -q "Index of /src" && echo "$url/src/ - Directory listing"
    curl -s "$url/source/" | grep -q "Index of /source" && echo "$url/source/ - Directory listing"
    curl -s "$url/code/" | grep -q "Index of /code" && echo "$url/code/ - Directory listing"
done < urls.txt > source_dir_listings.txt


## 16. IDE CONFIGURATION FILES

# Check for IDE configuration files
while read url; do
    for file in .idea/ .vscode/ .editorconfig .project .classpath .settings/; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file"
    done
done < urls.txt > ide_configs.txt


## 17. PACKAGE MANAGER FILES

# Check for package manager files
while read url; do
    for file in package.json composer.json requirements.txt Gemfile pom.xml build.gradle; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file"
    done
done < urls.txt > package_files.txt


## 18. BUILD/CONFIGURATION FILES

# Check for build configuration
while read url; do
    for file in Makefile Dockerfile docker-compose.yml Jenkinsfile .travis.yml .gitlab-ci.yml; do
        curl -s "$url/$file" -I | head -1 | grep -q "200" && echo "$url/$file"
    done
done < urls.txt > build_files.txt


## 19. SOURCE CODE ANALYSIS

# Analyze found source code for secrets
while read source_file; do
    echo "=== $source_file ==="
    curl -s "$source_file" | grep -E "(password|secret|key|token|credential) ?= ?['\"]?[^'\"]+['\"]?" -i | head -5
    echo ""
done < source_files.txt > source_analysis.txt


## 20. COMBINATION PIPELINES

# Discover VCS → Dump → Analyze pipeline
while read url; do
    # Discover
    curl -s "$url/.git/HEAD" -I | head -1 | grep -q "200" && echo "$url/.git/" >> discovered_git.txt
    
    # Dump (if found)
    if grep -q "^$url/.git/$" discovered_git.txt; then
        python3 gitdumper.py "$url/.git/" "dump_$(echo $url | sed 's/[^a-zA-Z0-9]/_/g')/"
    fi
done < urls.txt


## 21. BATCH PROCESSING

# Batch VCS discovery
split -l 50 urls.txt url_batch_
for batch in url_batch_*; do
    while read url; do
        for vcs in .git .svn .hg; do
            curl -s "$url/$vcs/" -I | head -1 | grep -q "200" && echo "$url/$vcs/"
        done
    done < "$batch" > "vcs_batch_$batch.txt"
done
cat vcs_batch_*.txt > all_vcs_discovered.txt


## 22. VALIDATION

# Validate VCS discoveries
cat all_vcs_discovered.txt | httpx -silent -status-code -o validated_vcs.txt

# Filter accessible VCS
cat validated_vcs.txt | grep "200\|403" | cut -d' ' -f1 > accessible_vcs.txt


## 23. SECRET SCANNING IN DUMPED REPOS

# Scan dumped repositories for secrets
for dump_dir in git_dump_*/ extracted_*/; do
    if [ -d "$dump_dir" ]; then
        trufflehog filesystem "$dump_dir" --json >> "trufflehog_$(basename $dump_dir).json"
        gitleaks detect --source "$dump_dir" --report "gitleaks_$(basename $dump_dir).json"
    fi
done


## 24. OUTPUT PROCESSING

# Create VCS discovery report
echo "VCS/Source Code Exposure Report" > vcs_report.txt
echo "================================" >> vcs_report.txt
echo "" >> vcs_report.txt
echo "Total URLs scanned: $(wc -l < urls.txt)" >> vcs_report.txt
echo "VCS repositories found: $(wc -l < all_vcs_discovered.txt 2>/dev/null || echo 0)" >> vcs_report.txt
echo "" >> vcs_report.txt

# Breakdown by type
echo "By VCS Type:" >> vcs_report.txt
echo "- Git: $(grep -c "\.git" all_vcs_discovered.txt 2>/dev/null || echo 0)" >> vcs_report.txt
echo "- SVN: $(grep -c "\.svn" all_vcs_discovered.txt 2>/dev/null || echo 0)" >> vcs_report.txt
echo "- Mercurial: $(grep -c "\.hg" all_vcs_discovered.txt 2>/dev/null || echo 0)" >> vcs_report.txt
echo "- Other: $(grep -v "\.git\|\.svn\|\.hg" all_vcs_discovered.txt 2>/dev/null | wc -l)" >> vcs_report.txt


## 25. MONITORING FOR NEW EXPOSURES

# Diff-based monitoring for new VCS
old="old_vcs.txt"; new="new_vcs.txt"

# Scan for new VCS
while read url; do
    for vcs in .git .svn .hg; do
        curl -s "$url/$vcs/" -I | head -1 | grep -q "200" && echo "$url/$vcs/"
    done
done < urls.txt | sort -u > $new

# Find new discoveries
if [ -f "$old" ]; then
    comm -13 <(sort "$old") <(sort "$new") > newly_discovered_vcs.txt
fi

# Update tracking
mv "$new" "$old"


## 26. SPECIALIZED SCANS

# Check for GitHub Pages CNAME files (often exposed)
while read domain; do
    curl -s "https://$domain/CNAME" -I | head -1 | grep -q "200" && echo "$domain: CNAME file exposed"
done < domains.txt > cname_files.txt

# Check for exposed .DS_Store files (macOS)
while read url; do
    curl -s "$url/.DS_Store" -I | head -1 | grep -q "200" && echo "$url/.DS_Store"
done < urls.txt > ds_store_files.txt


## 27. QUICK CHECKS

# Quick VCS check
while read url; do
    echo -n "$url: "
    found=""
    for vcs in .git .svn .hg; do
        curl -s "$url/$vcs/" -I 2>/dev/null | head -1 | grep -q "200" && found="$vcs"
    done
    [ -n "$found" ] && echo "Found $found" || echo "No VCS"
done < urls.txt > quick_vcs_check.txt

# Count findings
echo "Total VCS found: $(cat all_vcs_discovered.txt 2>/dev/null | wc -l)"
echo "With exposed secrets: $(grep -l "secret\|key\|password" trufflehog_*.json 2>/dev/null | wc -l)"


## 28. INTEGRATION WITH OTHER TOOLS

# VCS discovery → Secret scanning pipeline
while read vcs_url; do
    # Try to dump
    dir_name="dump_$(echo $vcs_url | sed 's/[^a-zA-Z0-9]/_/g')"
    ./gitdumper.sh "$vcs_url" "$dir_name" 2>/dev/null
    
    # Scan for secrets
    if [ -d "$dir_name" ]; then
        trufflehog filesystem "$dir_name" --json >> "vcs_secrets_$(echo $vcs_url | sed 's/[^a-zA-Z0-9]/_/g').json"
    fi
done < accessible_vcs.txt


## 29. OUTPUT FORMATTING

# JSON output
cat all_vcs_discovered.txt | jq -R -s 'split("\n") | map(select(. != "")) | map({url: ., type: (. | capture(".*(\\.(?<type>git|svn|hg))") | .type)})' > vcs_discoveries.json

# CSV output
echo "URL,VCS Type,Accessible,Secrets Found" > vcs_report.csv
while read vcs_url; do
    # Check accessibility
    status=$(curl -s "$vcs_url" -I | head -1 | cut -d' ' -f2)
    accessible=$([ "$status" = "200" ] || [ "$status" = "403" ] && echo "Yes" || echo "No")
    
    # Determine type
    if [[ "$vcs_url" =~ \.git ]]; then type="Git"; fi
    if [[ "$vcs_url" =~ \.svn ]]; then type="SVN"; fi
    if [[ "$vcs_url" =~ \.hg ]]; then type="Mercurial"; fi
    
    # Check for secrets (simplified)
    secrets="Unknown"
    
    echo "$vcs_url,$type,$accessible,$secrets" >> vcs_report.csv
done < all_vcs_discovered.txt 2>/dev/null
