### 12.10 Miscellaneous helpful commands    
    :- Run nmap for each IP in a list
    xargs -a list_of_ips.txt -I {} nmap -sV -p80,443 {}
    
    :- Find API keys in local JS files
    find . -name "*.js" -exec grep -Hn "api_key" {} \;
    
    :- Resolve all domains in a file
    for domain in $(cat domains.txt); do host $domain; done | grep "has address" 
