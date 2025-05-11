### 12.1 Wordlist Management
    cewl https://target.com -d 3 -m 5 -w custom_words.txt
    kwprocessor -b 1 -e 2 -l 3 --stdout > keyboard_walk.txt
    domain-analyzer -d target.com -o keywords.txt
    seclists -h
    custom-list -d target.com -o custom_wordlist.txt
    ------
    cewl https://target.com -d 5 -m 10 -w custom_words_deep.txt --email --meta --no-words
    kwprocessor -b 2 -e 3 -l 4 --stdout --numbers --symbols > keyboard_walk_complex.txt
    domain-analyzer -d target.com -o keywords_full.txt -t 5
    puredns resolve -l subdomains.txt -r /etc/resolv.conf -w resolved.txt
    puredns bruteforce subdomains.txt target.com -w /subdomains-top1million-5000.txt -o brute_resolved.txt
    ------
    cewl https://target.com -d 6 -m 15 -w custom_words_extreme.txt --email --meta --no-words --lowercase --strip-words "the,and,for"
    kwprocessor -b 3 -e 4 -l 5 --stdout --numbers --symbols --leet > keyboard_walk_ultimate.txt
    domain-analyzer -d target.com -o keywords_ultimate.txt -t 7 -s 100
    puredns resolve -l subdomains.txt -r /etc/resolv.conf -w resolved_full.txt -threads 50
    puredns bruteforce subdomains.txt target.com -w /subdomains-top1million-5000.txt -o brute_resolved_full.txt -threads 50 -rate 1000
    gobuster vhost -u FUZZ.target.com -w subdomains.txt -t 100 -o vhost_brute.txt
    gobuster s3 -u target-bucket.s3.amazonaws.com -w aws_s3_bucket_names.txt -t 50 -o s3_brute.txt

#### 12.1.1 Wordlist Generation
    :- Custom wordlist from site, depth 3, min length 6
    cewl https://target.com -d 3 -m 6 -w custom_words_from_site.txt
    
    :- Include numbers found on site
    cewl https://target.com -d 2 --with-numbers -o cewl_with_numbers.txt
    
    :- Keyword processor (example, may need specific tool)
    kwp -s /usr/share/wordlists/dirb/common.txt -b 3 -e 3 > mutations.txt