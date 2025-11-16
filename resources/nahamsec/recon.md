<!--  -->

### Topics

- `Asset Discovery` - Gather as many assets as we can.
- `Content Discovery` - Perform pentest on collected assets.

#### Asset Discovery

- Find domains, subdomians, IP Addresses, something that we can attack
- Get as many domain & subdomains as you can and always try to change config files for your tools according the needs (Ex: subfinder, shuffledns). Sometimes we have to brute-force these so that we don't miss.
- Check permutations (can use "alterX"). Allow different keywords added together to create different permutation
  cat dms.txt | alterx | tee -a subdns-dnsx.txt
  cat subdns-dnsx.txt | dnsx

-

- cat dms.txt | `alterx` | `dnsx`
- `subfinder`/`shuffledns` [subdomain finder] | `alterx` [Permutations] | `dnsx` [check valid record] | `httpx`
- `subfinder`/`shuffledns` -d target.com | `alterx` | `dnsx` | `naabu` -tp -ep 22 -o open-ports.txt
- > > `List Of Domains` >> `Permutations` >> `dnsx` which one resolve >> `naabu` for Ports are avaialable
- `httpx` -title -ct -sc -cl -location -fr -o httpx.txt

#### Content Discovery

- Infomation, Sub-Directory, Brute-forcing, Scraping JS files, Crawling websites like Katana.
- `katana` -u sub-dm.com
- `katana` -u sub-dm.com -H 'Cookie: SUPPOTESSESSID=jnbhbmh' -xhr -jsl -aff
- `httpx` -title -ct -sc -cl -location -fr -o httpx.txt

#### Purpose

- The point of recon is just find `leads` not to just `automate` everything and run `nuclei` across.
- Just run tools, Get thing that are interest to you which gives more things to hack on and also automatical in between generate leads that could potentially lead to vulnarability.

- `chaos-client` -d dm.com -silent | `grep` api | `alterx` -silent | `dnsx` -silent | `naabu` -p 443,8443 -silent
- `urlfinder` -d dm.com [feeds all subdomains to urlfinder to have it passively look for thing to do]
- `tlsx` `cloudlist` `asnmap`
