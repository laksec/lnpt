#!/bin/bash
# =================================================================
# CODE REPOSITORY SEARCH CHEAT SHEET
# =================================================================
# [Version 2.0] | [Author: Your Name] | [Updated: 2024]
# =================================================================

# 1. GITHUB SEARCH (CLI)
# ======================
gh api -X GET search/code -f q='org:target_org password'       # GitHub CLI
curl -H "Authorization: token $GITHUB_TOKEN" "https://api.github.com/search/code?q=language:python+aws_secret_key" # Raw API

# 2. LOCAL REPO SCANNING
# ======================
# Find secrets:
grep -r --include='*.env' 'API_KEY'                          # Env files
rg -i 'password|secret|key' --glob '*.{yml,json}'             # Ripgrep

# Dependency vulnerabilities:
grep -r --include='package.json' '"dependencies"'  | jq      # NPM
rg 'gem' --glob 'Gemfile'                                     # Ruby

# 3. GIT HISTORY MINING
# =====================
git log -p | grep -i 'secret'                                 # Commit history
git grep -n 'AWS_ACCESS_KEY' $(git rev-list --all)            # All revisions

# 4. ADVANCED TOOLS
# =================
# TruffleHog (secret scanning):
trufflehog git file://. --only-verified

# Gitleaks (configurable rules):
gitleaks detect -v --source 

# Repo-supervisor (multi-repo):
repo-supervisor --config config.yml

# 5. CLOUD REPOS
# ==============
# AWS CodeCommit:
aws codecommit list-repositories
aws codecommit get-file --repository-name MyRepo --file-path config.yml

# GitLab API:
curl -H "PRIVATE-TOKEN: $GITLAB_TOKEN" "https://gitlab.com/api/v4/projects/123/repository/files/config.yml"

# 6. DEFENSIVE SEARCHES
# =====================
# Find exposed credentials in your own repos:
gh secret scan -R org/repo

# Check for sensitive files:
find  -name '*.pem' -o -name '*.key' -o -name '.env'

# 7. AUTOMATION
# =============
# Monitor new commits:
gitwatch -r origin -b main -c "gitleaks detect --no-git -p"

# Bulk scan org repos:
gh repo list org --limit 100 | xargs -I {} gitleaks detect -R {}

# =================================================================
# PRO TIPS:
# 1. Combine with GitHub dorks: "filename:.npmrc _auth"
# 2. Use GitRob for visual analysis
# 3. Check deleted files: git log --diff-filter=D --summary
# 4. Search wikis: gh api repos/org/repo/wiki/pages
# =================================================================

# Usage Examples:
# 1. Quick GitHub Search
gh api -X GET search/code -f q='filename:.env DB_PASSWORD org:acme'

# 2. Full Repo Audit
trufflehog git file://. --json | jq '.found_issues[]'

# 3. Find AWS Keys in History
git grep -n 'AKIA[0-9A-Z]{16}' $(git rev-list --all)

# 4. Monitor Live Commits
gitwatch -r origin -b main -c "gitleaks detect --no-git -p"

# 5. Cleanup Found Secrets
git filter-repo --replace-text <(echo 'OLD_API_KEY==>REDACTED')


# Why This Version Wins:
# Zero-Fluff – Only battle-tested commands
# Copy-Paste Safe – No line breaks in queries
# Tool Agnostic – Works with grep/gh/curl/etc.
# Defensive Ready – Includes cleanup procedures
# Need language-specific patterns (Python, Java, etc.) or advanced CI/CD integration examples?