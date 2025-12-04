## 11. REPORTING & AUTOMATION
    # AUTOMATION SNIPPETS & WORKFLOW EXAMPLES

    # Bash loop to run nuclei on subdomains found by subfinder    
    subfinder -d target.com -silent | nuclei -t ~/nuclei-templates/exposures/ -c 50 -o nuclei_exposure_results.txt

    # Bash loop for directory brute-forcing multiple hosts    
    while read host; do ffuf -w wordlist.txt -u "$host/FUZZ" -mc 200 -o "ffuf_$(basename $host).txt"; done < live_hosts.txt

    # Find JS files, then extract secrets    
    subfinder -d target.com -silent | httpx -silent | subjs -c 10 | while read url; do secretfinder -i "$url" -o "secrets_$(basename $url).json"; done

    # Combine passive and active enum, resolve, check live hosts, and screenshot    
    { subfinder -d target.com -silent; amass enum -passive -d target.com -silent; } | sort -u > subs.txt
    puredns resolve subs.txt -r resolvers.txt | httpx -silent -status-code -o live.txt
    gowitness file -f live.txt -P screenshots/ --threads 10

    # Filter URLs for potential XSS using gf and test with dalfox    
    cat all_urls.txt | gf xss | dalfox pipe -b your.collab.server -o dalfox_xss_results.txt
