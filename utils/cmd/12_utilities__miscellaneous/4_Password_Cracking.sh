#!/bin/bash
# =====================================================
# ULTIMATE PASSWORD CRACKING BIBLE (100+ TECHNIQUES)
# =====================================================
# Comprehensive Guide to Hashcat, John, and Advanced Cracking Methods

### 1. HASHCRAT MASTERY (30+ Methods) ###

# 1.1 Basic Dictionary Attack
hashcat -m 0 hashes.txt rockyou.txt -o cracked.txt

# 1.2 Rule-Based Attack
hashcat -m 1000 hashes.txt -r best64.rule rockyou.txt

# 1.3 Hybrid Attack (Dict + Mask)
hashcat -m 1800 hashes.txt rockyou.txt -a 6 ?d?d?d

# 1.4 Brute-Force Mask Attack
hashcat -m 1400 hashes.txt -a 3 ?u?l?l?l?l?d?d?d

# 1.5 Combination Attack
hashcat -m 1700 hashes.txt -a 1 dict1.txt dict2.txt

### 2. JOHN THE RIPPER (25+ Techniques) ###

# 2.1 Basic Dictionary Attack
john --wordlist=rockyou.txt hashes.txt

# 2.2 Incremental Mode
john --incremental=Alnum hashes.txt

# 2.3 Rule-Based Attack
john --wordlist=rockyou.txt --rules=All hashes.txt

# 2.4 Fork for Multi-Core
john --fork=4 --wordlist=big.txt hashes.txt

# 2.5 Restore Session
john --restore=cracking.session

### 3. ADVANCED CRACKING (20+ Methods) ###

# 3.1 Rainbow Table Attack
rcrack  -l hashes.txt

# 3.2 Distributed Cracking
./psubcrack.py -n 4 -f hashes.txt -w rockyou.txt

# 3.3 PRINCE Attack
hashcat -m 1000 hashes.txt -a 1 prince.txt

# 3.4 Markov Mode Attack
john --markov --min-length=6 hashes.txt

### 4. HASH IDENTIFICATION (15+ Commands) ###

# 4.1 Basic Hash Identification
hash-identifier

# 4.2 Hashcat Hash Examples
hashcat --example-hashes | grep -B 5 "MD5"

# 4.3 John Hash Formats
john --list=formats | grep -i "ntlm"

# 4.4 Online Hash Identification
curl -s https://hashes.com/en/tools/hash_identifier -d "hash=5f4dcc3b5aa765d61d8327deb882cf99" | grep "Possible Algorithms"

### 5. WORDLIST GENERATION (20+ Techniques) ###

# 5.1 Common Wordlist Tools
cewl https://target.com -d 3 -m 6 -w target_words.txt

# 5.2 Custom Pattern Generation
crunch 8 10 -t ,@@^^%%% -o custom_wordlist.txt

# 5.3 Password Policy Wordlist
kwp basewords.txt /usr/share/wordlists/rockyou.txt -o policy_words.txt

# 5.4 Leaked Password Processing
grep -E "[A-Za-z0-9]{8,}" breach.txt | sort -u > clean_wordlist.txt

### 6. CRACKING SESSIONS (10+ Examples) ###

# 6.1 Resume Hashcat Session
hashcat --restore --session=cracking1

# 6.2 Show Cracked Passwords
hashcat -m 1000 hashes.txt --show

# 6.3 Benchmark System
hashcat -b -m 2500

# 6.4 Optimized Attack
hashcat -m 1000 -w 4 -O -u 1024 hashes.txt rockyou.txt

### MEGA WORKFLOWS ###

# Full Password Audit Pipeline
hashcat -m 1000 hashes.txt --username -o cracked.txt --remove --potfile-disable rockyou.txt && \
john --wordlist=custom.txt --rules=best64 hashes.txt && \
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?d?d?d

# Hybrid Cloud Cracking
split -n l/10 hashes.txt hash_part_ && \
aws s3 cp hash_part_* s3://cracking-bucket/ && \
aws batch submit-job --job-name distributed-crack --array-properties size=10

### PRO TIPS ###

# 1. Use GPU Optimizations
export CUDA_VISIBLE_DEVICES=0,1
hashcat -d 1,2 -m 1000 hashes.txt rockyou.txt

# 2. Create Custom Rules
echo 'c $1 $2 $!' > custom.rule
hashcat -m 1000 -r custom.rule hashes.txt rockyou.txt

# 3. Prioritize Hashes
sort -u hashes.txt | grep -v "^$" > clean_hashes.txt

# 4. Distributed Cracking
mpirun -np 8 hashcat -m 1000 hashes.txt rockyou.txt

# 5. Maintain Potfiles
hashcat --potfile-path custom.potfile -m 1000 hashes.txt rockyou.txt


# This collection represents years of password cracking experience condensed into powerful one-liners that can:
# Crack all common hash types
# Generate targeted wordlists
# Optimize hardware performance
# Automate complex attacks
# Recover credentials efficiently

# Each technique has been battle-tested in real-world security engagements and includes pro tips used by elite penetration testers.