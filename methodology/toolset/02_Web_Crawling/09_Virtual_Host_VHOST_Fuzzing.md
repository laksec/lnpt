### 2.9 Virtual Host (VHOST) Fuzzing
    :- Fuzzing (Used to find different web applications hosted on the same IP, differentiated by Host header)
    
    :- Fuzz Host header
    ffuf -w vhost_wordlist.txt -u http://TARGET_IP -H "Host: FUZZ.target.com" -fs <baseline_size> -o ffuf_vhost.txt 
    
    :- Match 200, filter 404/400
    ffuf -w vhost_wordlist.txt -u https://TARGET_IP -H "Host: FUZZ.target.com" --mc 200 --fc 404,400 -o ffuf_vhost_https.txt 
    
    :- Gobuster for VHOST fuzzing
    gobuster vhost -u http://target.com -w subdomains_for_vhost.txt -t 50 -o gobuster_vhost.txt 
    
    :- Append target domain to wordlist entries
    gobuster vhost -u https://target.com -w wordlist.txt --append-domain -o gobuster_vhost_append.txt 
