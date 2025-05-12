### 7.4 Code Repository Searching
    # (Manual on GitHub/GitLab with advanced search)
    
    # GitHub search for 'password' in JS related to target.com
    "target.com" language:javascript password
    
    # Search within a specific GitHub organization
    org:"TargetOrg" "SECRET_KEY"

    
    # Scan GitHub org for sensitive files
    gitrob --github-access-token YOUR_GITHUB_TOKEN target_organization
    
    # Scan local git repo for secrets
    gitleaks detect --source . -v -r gitleaks_report.json
    
    # Find secrets in GitHub org
    trufflehog github --org <target_org> --json > trufflehog_github.json 
    
    # Find secrets in local filesystem
    trufflehog filesystem /path/to/code --json > trufflehog_local.json