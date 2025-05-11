### 12.6 One-liners for Recon Chains
    :- Find live subdomains
    assetfinder --subs-only target.com | httpx -silent -threads 100 | anew live_subdomains.txt 
    
    :- Fuzz live subdomains
    cat live_subdomains.txt | nuclei -t /path/to/fuzzing-templates/ -c 50 -o fuzzing_results.txt 
    
    :- Get tech, title, status for subs
    subfinder -d target.com -silent | httpx -silent -tech-detect -title -status-code -o tech_and_status.txt 
