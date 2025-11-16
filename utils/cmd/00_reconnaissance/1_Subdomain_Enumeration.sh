#### 1.1.1 Passive Subdomain Enumeration
    subfinder -d target.com -all -config config.yaml -o subfinder_max.txt
    subfinder -d target.com -sources virustotal,crtsh,securitytrails -o subfinder_targeted.txt
    subfinder -d target.com -rl 50 -silent -o subfinder_stealth.txt
    subfinder -d target.com -recursive -o subfinder_recursive.txt

    amass enum -passive -d target.com -config config.ini -o amass_passive.txt
    amass enum -passive -d target.com -src -o amass_sources.txt
    amass enum -passive -d target.com -asn $(whois target.com | grep -i 'originas:' | awk '{print $2}') -o amass_asn.txt

    findomain -t target.com -r -u findomain_resolved.txt
    findomain -t target.com -q -u findomain_quiet.txt

    assetfinder --subs-only target.com > assetfinder_simple.txt
    assetfinder target.com | grep "\.target\.com$" | anew assetfinder_filtered.txt

    chaos -d target.com -key $CHAOS_KEY -o chaos_bounty.txt
    chaos -d target.com -key $CHAOS_KEY -filter "CNAME" -o chaos_cnames.txt

    github-subdomains -d target.com -t $GITHUB_TOKEN -o github_subs.txt
    github-subdomains -d target.com -t $GITHUB_TOKEN -raw -o github_raw.txt

    curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crtsh_certs.txt

    sublist3r -d target.com -t 30 -o sublist3r_fallback.txt

    cat subfinder.txt | dnsx -silent -a -resp -o resolved_subs.txt

    # Using crt.sh
    curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crt_sh.txt

    # Using Wayback Machine
    curl -sk "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u > wayback.txt



#### 1.1.2 Active Subdomain Enumeration
    # Active DNS Enumeration Cheatsheet

    # AMASS BRUTE FORCE
    amass enum -active -d target.com -brute -w subdomains-top1million-5000.txt -o amass_brute.txt
    amass enum -active -d target.com -brute -rf resolvers.txt -w custom_wordlist.txt -o amass_custom_brute.txt
    amass enum -active -d target.com -p 80,443,8080,8443 -o amass_ports.txt

    # GOBUSTER DNS
    gobuster dns -d target.com -w subdomains-top1million-5000.txt -t 100 -i -o gobuster_verbose.txt
    gobuster dns -d target.com -w subdomains.txt --wildcard -t 150 -o gobuster_wildcard.txt
    gobuster dns -d target.com -w subdomains.txt -r 1.1.1.1 -t 80 -o gobuster_cloudflare.txt

    # SHUFFLEDNS
    shuffledns -d target.com -w subdomains-top1million-5000.txt -r resolvers.txt -o shuffledns_brute.txt
    shuffledns -d target.com -list discovered_subs.txt -r resolvers.txt -o shuffledns_resolve.txt

    # PUREDNS
    puredns bruteforce subdomains-top1million-5000.txt target.com -r resolvers.txt -w puredns_brute.txt
    puredns resolve discovered_subs.txt -r resolvers.txt -w puredns_resolved.txt

    # ALTDNS (Permutation)
    altdns -i discovered_subs.txt -o altdns_perms.txt -w permutations.txt -r -s altdns_stats.txt

    # MASSDNS (Direct)
    dnsgen discovered_subs.txt | massdns -r resolvers.txt -t A -o S -w massdns_results.txt

    # Using Subfinder with recursion
    subfinder -d target.com -recursive -o subfinder_recursive.txt

    # Using DNS Brute Forcing
    dnsrecon -d target.com -D ~/wordlists/subdomains.txt -t brt -o dnsrecon.txt

    # Using MassDNS
    massdns -r ~/wordlists/resolvers.txt -t A -o S -w massdns.txt ~/wordlists/subdomains.txt

# 3. PERMUTATION TECHNIQUES
    # -------------------------

    # Using AltDNS
    altdns -i found_subdomains.txt -o data_output -w ~/wordlists/words.txt -r -s altdns_results.txt

    # Using Gotator
    gotator -sub subdomains.txt -perm permutations.txt -depth 1 -numbers 10 -mindup -adv -md > permutations.txt

    # Using DNSGen
    cat subdomains.txt | dnsgen - | massdns -r ~/wordlists/resolvers.txt -t A -o J --flush 2>/dev/null


#!/bin/bash
# ==============================================
