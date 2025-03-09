## ☣️ Few Cmds

- `subfinder -d fb.com | httpx -title -ports 80,443,8443`
    - Sub-domains of `fb.com`
    - Httpx to get page title & check ports `80,443,8443` for these sub-domains.
- `subfinder -d fb.com | httpx -title -status-code content-length -silent`
    - Sub-domains of `fb.com`
    - Httpx to return the status codes, titles, content-length for each sub-domain, silently displaying the results. 
- `seq 1 10 | ffuf -u "http://fb.com/cmt?token=FUZZ" -w - `
    - Generates a sequence of numbers from 01 to 10 and uses FFUF to inject them into the URL's token parameter, testing different values.
- `turbosearch -t https://fb.com -w wordlist.txt`
    - Using Turbosearch to search for directories and files on the website using specific wordlists.
- `echo htpp://fb.com | waybackurls | kxxs `
    - `KXSS` & `WAYBACKURLS` - It passes urls to `WaybackUrls` to retrive archived URLs, and then uses `KXSS` to find potential `XSS vulns` in those URLs.
