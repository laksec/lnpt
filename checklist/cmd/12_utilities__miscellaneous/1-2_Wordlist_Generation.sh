#!/bin/bash
# ==============================================
# ULTIMATE WORDLIST GENERATION CHEAT SHEET
# ==============================================

# 1. TARGETED WORD EXTRACTION
# ---------------------------
# Basic site crawling (depth 3, min length 6)
cewl https://target.com -d 3 -m 6 -w target_words.txt --lowercase

# Advanced crawling with metadata/numbers
cewl https://target.com -d 4 -m 8 \
    --meta \
    --with-numbers \
    --email-file target_emails.txt \
    -o target_advanced.txt

# 2. KEYWORD MUTATIONS
# --------------------
# Keyboard walk patterns
kwprocessor -b 3 -e 3 -l 5 \
    --stdout \
    --numbers \
    --symbols \
    > keyboard_patterns.txt

# Common word mutations
hashcat --stdout -a 6 base_words.txt ?d?d?d | tee -a mutations.txt

# 3. DOMAIN-SPECIFIC LISTS
# ------------------------
# Subdomain components
domain-analyzer -d target.com -o domain_words.txt \
    -t 5 \
    --include-tlds

# API endpoint discovery
gau target.com | awk -F/ '{print $NF}' | sort -u > api_words.txt

# 4. WORDLIST OPTIMIZATION
# ------------------------
# Merge and deduplicate
cat *.txt | tr '[:upper:]' '[:lower:]' | sort -u | grep -v '^$' > master.txt

# Split for parallel attacks
split -l 10000 master.txt segment_

# 5. SPECIALIZED GENERATION
# -------------------------
# Password policy patterns
crunch 8 12 -t ,@@^^%%% -o complex_pass.txt

# JavaScript scraping
python3 JSminer.py -u https://target.com -o js_keywords.txt

# ==============================================
# PRO TIPS:
# 1. Always sanitize: `tr -d '\r' < wordlist.txt`
# 2. Combine with SecLists: `cat /usr/share/seclists/*.txt`
# 3. Use `--rules` with hashcat for smart mutations
# ==============================================

# Usage Examples:
# 1. Quick Target Wordlist
cewl https://target.com -d 2 -m 5 -w quick_list.txt

# 2. Password Policy Compliance
crunch 10 10 -t ^%^company202 -o corp_pass.txt

# 3. Continuous Monitoring
watch -n 3600 "cewl https://target.com/news | grep -Ff keywords.txt"


# This version eliminates redundancy while adding critical flags like --lowercase and --meta that are often overlooked. 
# Each command is optimized for real-world testing scenarios.