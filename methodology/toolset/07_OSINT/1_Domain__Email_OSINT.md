### 7.1 Domain & Email OSINT
    :- Gather emails, subdomains, hosts
    theHarvester -d target.com -l 500 -b google,bing,linkedin -o harvester_report.html 
    
    :- Use all available sources
    theHarvester -d target.com -b all -f harvester_results_all.xml
    
    :- Hunt for social media accounts by username
    sherlock username123 --timeout 10 -o sherlock_results.txt
    
    :- Check multiple usernames, output CSV
    sherlock user1 user2 user3 --csv -o sherlock_multiuser.csv