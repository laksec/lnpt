# Bug Bounty Checklist

## 1. Reconnaissance Techniques

### 1.1 Information Gathering<br />

1. **Google Dorking**: Use advanced search operators to find sensitive information.
    - ***Tools:***&emsp; [Google Search](#), [Shodan](#), , [Censys](#) , [Bing Search](#) , [DuckDuckGo](#)<br /><br />

2. **WHOIS Lookup**: Gather domain registration details.
    - ***Tools:***&emsp; [WHOIS](#), [Domaintools](#), , [WhoisXML API](#) , [ARIN WHOIS](#) , [RIPE NCC](#)<br /><br />

3. **Reverse WHOIS Lookup**: Find domains associated with a specific registrant.
    - ***Tools:***&emsp; [WhoisXML API](#), [DomainTools](#), , [ReverseWHOIS](#) , [Robtex](#) , [SecurityTrails](#)<br /><br />

4. **DNS Enumeration**: Identify DNS records like A, MX, NS, TXT, SOA.
    - ***Tools:***&emsp; [dnsenum](#), [dnsrecon](#), , [dnspython](#) , [dnsutils](#) , [fierce](#) , [dnsmap](#) , [dnsx](#) , [sublist3r](#) , [theHarvester](#) , [crt.sh](#)<br /><br />

5. **IP Geolocation**: Find the geographical location of IP addresses.
    - ***Tools:***&emsp; [ipinfo](#), [ipapi](#), , [geoip](#) , [maxmind](#) , [ipstack](#) , [IPLocation.net](#) , [ipgeolocation.io](#) , [GeoIP2](#) , [IPinfo](#) , [DB-IP](#)<br /><br />

6. **Public Records Search**: Access public records related to the target.
    - ***Tools:***&emsp; [Pipl](#), [Spokeo](#), , [PeopleFinder](#) , [Intelius](#) , [LinkedIn](#) , [Facebook](#) , [Whitepages](#) , [PublicRecords.com](#) , [ZabaSearch](#) , [BeenVerified](#)<br /><br />

7. **Search Engine Queries**: Use search engines to gather information.
    - ***Tools:***&emsp; [Google](#), [Bing](#), , [DuckDuckGo](#) , [Yandex](#) , [Startpage](#) , [Searx](#) , [Blekko](#) , [Qwant](#) , [MetaCrawler](#) , [WebCrawler](#)<br /><br />

8. **Breach Data Search**: Check for data breaches with services like Have I Been Pwned.
    - ***Tools:***&emsp; [Have I Been Pwned](#), [BreachDirectory](#), , [DeHashed](#) , [Leaks.ovh](#) , [SpyCloud](#) , [Pwned Passwords](#) , [BreachAlarm](#) , [Hacked Emails](#) , [HackNotice](#) , [BreachAuth](#)<br /><br />

9. **Social Engineering Techniques**: Use social tactics to gather information.
    - ***Tools:***&emsp; [Social Engineering Toolkit](#), [Recon-ng](#), , [Maltego](#) , [OSINT Framework](#) , [Hunter.io](#) , [Email Hunter](#) , [EmailPermutator](#) , [LinkedIn](#) , [Facebook](#) , [Twitter](#)<br /><br />

10. **Publicly Available APIs**: Analyze APIs for exposed information.
    - ***Tools:***&emsp; [Postman](#), [Insomnia](#), [Swagger](#), [APIsec](#), [RapidAPI](#), [Shodan API](#), [Censys API](#), [Google Maps API](#), [IPinfo API](#), [VirusTotal API](#)<br /><br />

11. **Certificate Transparency Logs**: Monitor public logs for SSL certificates.
    - ***Tools:***&emsp; [crt.sh](#), [CertSpotter](#), [Google Certificate Transparency](#), [SSL Labs](#), [PassiveTotal](#), [CertStream](#), [Certificate Transparency Logs](#), [Symantec CT](#), [Cloudflare CT Logs](#), [HackerOne CT Logs](#)<br /><br />

12. **Domain History Analysis**: Use tools to analyze historical domain data.
    - ***Tools:***&emsp; [DomainTools](#),, [WhoisXML API](#), [Wayback Machine](#), [Archive.org](#), [DNS History](#), [Historical WHOIS](#), [Netcraft](#), [Robtex](#), [SecurityTrails](#), [BuiltWith](#)

### 1.2 Subdomain and Domain Discovery<br /><br />

1. **Subdomain Enumeration**: Discover subdomains using tools like Sublist3r or Amass.
    - ***Tools:***&emsp; [Sublist3r](#), [Amass](#),, [Subfinder](#) , [Findomain](#) , [Subjack](#) , [Assetfinder](#) , [Knockpy](#) , [Subzy](#) , [Subdomainizer](#) , [CRT.sh](#)<br /><br />

2. **Reverse IP Lookup**: Identify other domains hosted on the same IP.
    - ***Tools:***&emsp; [Reverse IP Lookup](#), [Robtex](#), , [SecurityTrails](#) , [Shodan](#) , [Censys](#) , [Netcraft](#) , [DNSdumpster](#) , [Spyse](#) , [ThreatMiner](#) , [Webscan](#)<br /><br />

3. **DNS Dumpster Diving**: Extract information about DNS records.
    - ***Tools:***&emsp; [dnsdumpster](#), [dnsrecon](#), , [dnstracer](#) , [dnsutils](#) , [DNSMap](#) , [Fierce](#) , [Netcraft](#) , [Google DNS](#) , [SecurityTrails](#) , [Shodan](#)<br /><br />

4. **Zone Transfers**: Attempt DNS zone transfers to gather records.
    - ***Tools:***&emsp; [dig](#), [nslookup](#), , [dnsrecon](#) , [Fierce](#) , [DNSMap](#) , [dnstracer](#) , [dnsscan](#) , [Zone Transfer Scanner](#) , [Recon-ng](#) , [Netcat](#)

### 1.3 Technology and Service Identification<br /><br />

1. **Website Footprinting**: Identify technologies, server details, and software versions.
    - ***Tools:***&emsp; [Wappalyzer](#), [WhatWeb](#), , [BuiltWith](#) , [Netcraft](#) , [Shodan](#) , [Censys](#) , [HTTP Headers](#) , [Wappalyzer](#) , [WhatCMS](#) , [Gau](#)<br /><br />

2. **Shodan Search**: Find internet-connected devices and their details.
    - ***Tools:***&emsp; [Shodan](#), [Censys](#), , [ZoomEye](#) , [BinaryEdge](#) , [Fofa](#) , [Rapid7](#) , [GreyNoise](#) , [Pulsedive](#) , [ThreatQuotient](#) , [RATelnet](#)<br /><br />

3. **Censys Search**: Identify and analyze devices and systems.
    - ***Tools:***&emsp; [Censys](#), [Shodan](#), , [ZoomEye](#) , [BinaryEdge](#) , [Fofa](#) , [Rapid7](#) , [GreyNoise](#) , [Pulsedive](#) , [ThreatQuotient](#) , [RATelnet](#)<br /><br />

4. **SSL/TLS Certificate Analysis**: Review certificates for associated domains.
    - ***Tools:***&emsp; [SSLLabs](#), [CertSpotter](#), , [crt.sh](#) , [SSL Certificate Checker](#) , [Shodan](#) , [Censys](#) , [SecurityTrails](#) , [SSL Labs](#) , [CertStream](#) , [SSL Checker](#)<br /><br />

5. **Web Application Framework Identification**: Determine the frameworks used on a website.
    - ***Tools:***&emsp; [Wappalyzer](#), [WhatWeb](#), , [BuiltWith](#) , [Netcraft](#) , [CMS Detector](#) , [Framework Scanner](#) , [HTTP Headers](#) , [Wappalyzer](#) , [WebTech](#) , [AppDetective](#)<br /><br />

6. **Netcraft Site Reports**: Analyze site reports for server details and technologies.
    - ***Tools:***&emsp; [Netcraft](#), [BuiltWith](#), , [Wappalyzer](#) , [WhatWeb](#) , [Shodan](#) , [Censys](#) , [SecurityTrails](#) , [SSL Labs](#) , [Wayback Machine](#) , [Webscreenshot](#)

### 1.4 Metadata and Historical Data<br /><br />

1. **FOCA**: Extract metadata from documents and images.
    - ***Tools:***&emsp; [FOCA](#), [ExifTool](#), , [Metadata Extractor](#) , [ExifPilot](#) , [Metagoofil](#) , [DocScraper](#) , [PDF-Analyzer](#) , [X1](#) , [Metagoofil](#) , [ExifTool](#)<br /><br />

2. **ExifTool**: Extract metadata from files and images.
    - ***Tools:***&emsp; [ExifTool](#), [FOCA](#), , [Metadata Extractor](#) , [ExifPilot](#) , [DocScraper](#) , [PDF-Analyzer](#) , [X1](#) , [Metagoofil](#) , [ExifTool](#) , [Metadata++](#)<br /><br />

3. **Wayback Machine**: Retrieve historical versions of web pages.
    - ***Tools:***&emsp; [Wayback Machine](#), [Archive.org](#), , [Oldweb.today](#) , [WebCite](#) , [PageFreezer](#) , [Google Cache](#) , [Bing Cache](#) , [Yandex Cache](#) , [Wayback Machine API](#) , [Netarchive](#)<br /><br />

4. **Github Repository Search**: Look for sensitive information in code repositories.
    - ***Tools:***&emsp; [Github Search](#), [GitHub Code Search](#), , [GitHound](#) , [TruffleHog](#) , [Repo-Extractor](#) , [GitSecrets](#) , [Gitleaks](#) , [GitRob](#) , [GitGuardian](#) , [GitGraber](#)<br /><br />

5. **Metadata Analysis**: Analyze file and document metadata.
    - ***Tools:***&emsp; [ExifTool](#), [FOCA](#), , [Metadata Extractor](#) , [DocScraper](#) , [PDF-Analyzer](#) , [Metagoofil](#) , [X1](#) , [Metagoofil](#) , [ExifTool](#) , [Metadata++](#)

### 1.5 Network and Traffic Analysis<br /><br />

1. **Network Mapping**: Map out network topology with tools like Nmap.
    - ***Tools:***&emsp; [Nmap](#), [Masscan](#), , [Zenmap](#) , [Netcat](#) , [Angry IP Scanner](#) , [Unicornscan](#) , [Nessus](#) , [Advanced IP Scanner](#) , [OpenVAS](#) , [Netdiscover](#)<br /><br />

2. **Network Traffic Analysis**: Analyze network traffic for service and system information.
    - ***Tools:***&emsp; [Wireshark](#), [tcpdump](#), , [Tshark](#) , [Kismet](#) , [NetworkMiner](#) , [Zeek](#) , [EtherApe](#) , [Snort](#) , [NetFlow](#) , [Colasoft Capsa](#)<br /><br />

3. **IP Range Scanning**: Identify IP ranges associated with the target.
    - ***Tools:***&emsp; [Nmap](#), [Masscan](#), , [Zmap](#) , [Unicornscan](#) , [Netdiscover](#) , [Angry IP Scanner](#) , [Advanced IP Scanner](#) , [Fping](#) , [Nessus](#) , [Shodan](#)<br /><br />

4. **Network Enumeration**: Use traceroute to identify network paths.
    - ***Tools:***&emsp; [Traceroute](#), [MTR](#), , [PingPlotter](#) , [PathPing](#) , [Tracert](#) , [NetworkMiner](#) , [TraceRoute](#) , [Nmap](#) , [Hping](#) , [OpenVAS](#)

## 2. Enumeration Techniques

### 2.1 Service and Port Enumeration<br /><br />

1. **Service Enumeration**: Identify active services and their versions.
    - ***Tools:***&emsp; [Nmap](#), [Netcat](#), , [Masscan](#) , [Service Scanner](#) , [Zmap](#) , [Nessus](#) , [OpenVAS](#) , [Shodan](#) , [Censys](#) , [TCP Port Scanner](#)<br /><br />

2. **Port Scanning**: Identify open ports and services running on the target.
    - ***Tools:***&emsp; [Nmap](#), [Masscan](#), , [Zmap](#) , [Unicornscan](#) , [Netcat](#) , [Angry IP Scanner](#) , [Nessus](#) , [OpenVAS](#) , [PortQry](#) , [Fping](#)<br /><br />

3. **Banner Grabbing**: Obtain service banners to determine versions.
    - ***Tools:***&emsp; [Nmap](#), [Netcat](#), , [Telnet](#) , [BannerGrab](#) , [Netcat](#) , [Telnet](#) , [WhatWeb](#) , [Shodan](#) , [Censys](#) , [BannerGrabber](#)<br /><br />

4. **FTP Enumeration**: List files and directories on FTP servers.
    - ***Tools:***&emsp; [Nmap](#), [Metasploit](#), , [ftp](#) , [NcFTP](#) , [WinSCP](#) , [FileZilla](#) , [FTPScan](#) , [Hydra](#) , [FTPEnum](#) , [Burp Suite](#)<br /><br />

5. **HTTP Methods Testing**: Check for supported HTTP methods.
    - ***Tools:***&emsp; [Nmap](#), [Burp Suite](#), , [OWASP ZAP](#) , [Nikto](#) , [HTTP Methods](#) , [Wapiti](#) , [WhatWeb](#) , [Dirb](#) , [Gau](#) , [HTTPX](#)<br /><br />

6. **WebDAV Enumeration**: Explore WebDAV services for vulnerabilities.
    - ***Tools:***&emsp; [Nmap](#), [Burp Suite](#), , [OWASP ZAP](#) , [Nikto](#) , [WebDAV Scanner](#) , [dirb](#) , [Wapiti](#) , [Gau](#) , [HTTPX](#) , [WebDAV](#)<br /><br />

7. **NFS Enumeration**: Identify Network File System shares and permissions.
    - ***Tools:***&emsp; [showmount](#), [Nmap](#), , [rpcinfo](#) , [nfsstat](#) , [nmap -p 2049](#) , [nfs-common](#) , [Nessus](#) , [OpenVAS](#) , [Metasploit](#) , [Hydra](#)

### 2.2 User and Resource Enumeration<br /><br />

1. **User Enumeration**: Find valid usernames using tools like Hydra or Medusa.
    - ***Tools:***&emsp; [Hydra](#), [Medusa](#), , [CrackMapExec](#) , [Nmap](#) , [Enum4linux](#) , [Snmpwalk](#) , [SMBclient](#) , [LDAP Enumeration](#) , [Kerberos Enumeration](#) , [Fuzzdb](#)<br /><br />

2. **SMB Enumeration**: Extract information from SMB shares using tools like enum4linux.
    - ***Tools:***&emsp; [enum4linux](#), [SMBclient](#), , [Nmap](#) , [CrackMapExec](#) , [SMBMap](#) , [Metasploit](#) , [SMBScanner](#) , [Nessus](#) , [OpenVAS](#) , [Impacket](#)<br /><br />

3. **NetBIOS Enumeration**: Gather NetBIOS information with nbtstat.
    - ***Tools:***&emsp; [nbtstat](#), [NetBIOS Scanner](#), , [Nmap](#) , [Enum4linux](#) , [SMBclient](#) , [NetView](#) , [Metasploit](#) , [Hydra](#) , [CrackMapExec](#) , [Smbclient](#)<br /><br />

4. **SNMP Enumeration**: Extract SNMP data with snmpwalk.
    - ***Tools:***&emsp; [snmpwalk](#), [nmap](#), , [onesixtyone](#) , [snmpenum](#) , [snmpcheck](#) , [Metasploit](#) , [Nessus](#) , [OpenVAS](#) , [SolarWinds](#) , [SolarWinds SNMP Walk](#)<br /><br />

5. **LDAP Enumeration**: Query LDAP servers for user and group details.
    - ***Tools:***&emsp; [ldapsearch](#), [Nmap](#), , [CrackMapExec](#) , [Enum4linux](#) , [Metasploit](#) , [LDAP Enumeration](#) , [LDAPScan](#) , [Nessus](#) , [OpenVAS](#) , [Ldapdomaindump](#)<br /><br />

6. **SMTP Enumeration**: Discover email configurations using tools like SMTPSend.
    - ***Tools:***&emsp; [smtp-user-enum](#), [Nmap](#), , [Metasploit](#) , [SMTPSend](#) , [SMTPScan](#) , [SMTP Enumeration](#) , [Harvester](#) , [Snmpwalk](#) , [Burp Suite](#) , [EmailHunter](#)<br /><br />

7. **Kerberos Enumeration**: Enumerate Kerberos tickets and services.
    - ***Tools:***&emsp; [Kerberoast](#), [Rubeus](#), , [Impacket](#) , [Nmap](#) , [Metasploit](#) , [CrackMapExec](#) , [Evil-WinRM](#) , [GetNPUsers](#) , [PowerView](#) , [BloodHound](#)<br /><br />

8. **RPC Enumeration**: Identify RPC services and versions.
    - ***Tools:***&emsp; [rpcinfo](#), [Nmap](#), , [Metasploit](#) , [Enum4linux](#) , [CrackMapExec](#) , [SMBclient](#) , [Hydra](#) , [Nessus](#) , [OpenVAS](#) , [RPCScan](#)<br /><br />

9. **LDAP Injection Testing**: Test for LDAP injection vulnerabilities.
    - ***Tools:***&emsp; [LDAPInjection](#), [Burp Suite](#), , [OWASP ZAP](#) , [Nmap](#) , [Metasploit](#) , [Sqlmap](#) , [LDAPi](#) , [Fuzzdb](#) , [DirBuster](#) , [Gf](#)<br /><br />

10. **Kerberoasting**: Extract and crack service tickets from Kerberos.
    - ***Tools:***&emsp; [Rubeus](#), [Impacket](#) , [Kerberoast](#) , [Metasploit](#) , [CrackMapExec](#) , [PowerView](#) , [BloodHound](#) , [GetNPUsers](#) , [Kerbrute](#) , [Kerbrute](#)

## 3. Scanning Techniques

### 3.1 Network and Service Scanning<br /><br />

1. **Network Scanning**: Discover live hosts and network services.
    - ***Tools:***&emsp; [Nmap](#), [Masscan](#), , [Zmap](#) , [Unicornscan](#) , [Netdiscover](#) , [Angry IP Scanner](#) , [Nessus](#) , [OpenVAS](#) , [Netcat](#) , [Advanced IP Scanner](#)<br /><br />

2. **Port Scanning**: Identify open ports with detailed options.
    - ***Tools:***&emsp; [Nmap](#), [Masscan](#), , [Zmap](#) , [Unicornscan](#) , [Netcat](#) , [Angry IP Scanner](#) , [Nessus](#) , [OpenVAS](#) , [PortQry](#) , [Fping](#)<br /><br />

3. **Service Scanning**: Determine services running on open ports.
    - ***Tools:***&emsp; [Nmap](#), [Netcat](#), , [Masscan](#) , [Zmap](#) , [Unicornscan](#) , [Nessus](#) , [OpenVAS](#) , [Shodan](#) , [Censys](#) , [TCP Port Scanner](#)<br /><br />

4. **Operating System Fingerprinting**: Identify the operating system using tools like Nmap or p0f.
    - ***Tools:***&emsp; [Nmap](#), [p0f](#), , [Xprobe2](#) , [Nessus](#) , [OpenVAS](#) , [Shodan](#) , [Censys](#) , [OS Fingerprinter](#) , [P0f](#) , [Netcat](#)<br /><br />

5. **Web Application Scanning**: Detect vulnerabilities in web applications using tools like OWASP ZAP or Burp Suite.
    - ***Tools:***&emsp; [OWASP ZAP](#), [Burp Suite](#), , [Nikto](#) , [Wapiti](#) , [Arachni](#) , [Acunetix](#) , [Nessus](#) , [OpenVAS](#) , [W3af](#) , [SQLMap](#)<br /><br />

6. **DNS Scanning**: Scan DNS records and identify potential misconfigurations.
    - ***Tools:***&emsp; [Nmap](#), [dnsenum](#), , [dnsrecon](#) , [dnsutils](#) , [dnsmap](#) , [fierce](#) , [DNSEnum](#) , [DNSRecon](#) , [DNSMap](#) , [Fierce](#)<br /><br />

7. **SSL/TLS Scanning**: Check SSL/TLS configurations and vulnerabilities using tools like Qualys SSL Labs.
    - ***Tools:***&emsp; [Qualys SSL Labs](#), [SSLLabs](#), , [Nmap](#) , [OpenSSL](#) , [SSLScan](#) , [TestSSL](#) , [SSLYze](#) , [Cipherscan](#) , [SSLStrip](#) , [Hardenize](#)

### 3.2 Vulnerability and Protocol Scanning<br /><br />

1. **Vulnerability Scanning**: Identify known vulnerabilities using tools like Nessus or OpenVAS.
    - ***Tools:***&emsp; [Nessus](#), [OpenVAS](#), , [Qualys](#) , [Rapid7 InsightVM](#) , [Burp Suite](#) , [Acunetix](#) , [Wapiti](#) , [Nmap](#) , [Arachni](#) , [AppScan](#)<br /><br />

2. **Port Sweeping**: Scan a range of ports to identify open services.
    - ***Tools:***&emsp; [Nmap](#), [Masscan](#), , [Zmap](#) , [Unicornscan](#) , [Fping](#) , [Netcat](#) , [Angry IP Scanner](#) , [PortQry](#) , [Zmap](#) , [Netdiscover](#)<br /><br />

3. **Application Scanning**: Identify vulnerabilities in applications and services.
    - ***Tools:***&emsp; [OWASP ZAP](#), [Burp Suite](#), , [Nessus](#) , [OpenVAS](#) , [Acunetix](#) , [AppScan](#) , [Wapiti](#) , [Arachni](#) , [AppSpider](#) , [Nikto](#)<br /><br />

4. **Network Protocol Analysis**: Analyze network protocols for weaknesses.
    - ***Tools:***&emsp; [Wireshark](#), [tcpdump](#), , [Tshark](#) , [Kismet](#) , [NetFlow](#) , [Snort](#) , [Zeek](#) , [Colasoft Capsa](#) , [NetworkMiner](#) , [Suricata](#)<br /><br />

5. **Wireless Scanning**: Identify and analyze wireless networks and their security settings.
    - ***Tools:***&emsp; [Kismet](#), [Aircrack-ng](#), , [Wireshark](#) , [Reaver](#) , [Fern Wifi Cracker](#) , [Wifite](#) , [NetStumbler](#) , [InSSIDer](#) , [Airodump-ng](#) , [WPS Cracker](#)

## 4. OSINT Techniques
<br /><br />

1. **Social Media Analysis**: Collect information from social media platforms.
    - ***Tools:***&emsp; [Maltego](#), [Social-Engineer Toolkit](#), , [Recon-ng](#) , [Spokeo](#) , [Pipl](#) , [LinkedIn](#) , [Facebook](#) , [Twitter](#) , [Instagram](#) , [Social Mapper](#)<br /><br />

2. **Public Records Search**: Access public records and databases.
    - ***Tools:***&emsp; [Pipl](#), [Spokeo](#), , [PeopleFinder](#) , [Intelius](#) , [LinkedIn](#) , [Facebook](#) , [Whitepages](#) , [PublicRecords.com](#) , [ZabaSearch](#) , [BeenVerified](#)<br /><br />

3. **Domain and IP Lookup**: Investigate domain and IP address information.
    - ***Tools:***&emsp; [WHOIS](#), [DomainTools](#), , [ipinfo](#) , [Censys](#) , [Shodan](#) , [Google Search](#) , [Bing Search](#) , [dnsenum](#) , [dnsrecon](#) 
[ipapi]&emsp;&emsp; <br /><br />

4. **Historical Data Search**: Access historical data on websites and domains.
    - ***Tools:***&emsp; [Wayback Machine](#), [Archive.org](#), , [Oldweb.today](#) , [WebCite](#) , [PageFreezer](#) , [Google Cache](#) , [Bing Cache](#) , [Yandex Cache](#) , [Netarchive](#) , [Wayback Machine API](#)<br /><br />

5. **Code Repository Search**: Look for sensitive information in public code repositories.
    - ***Tools:***&emsp; [Github Search](#), [GitHub Code Search](#), , [GitHound](#) , [TruffleHog](#) , [Repo-Extractor](#) , [GitSecrets](#) , [Gitleaks](#) , [GitRob](#) , [GitGuardian](#) , [GitGraber](#)<br /><br />

6. **Online People Search**: Find personal details and professional backgrounds.
    - ***Tools:***&emsp; [Pipl](#), [Intelius](#), , [Spokeo](#) , [PeopleFinders](#) , [LinkedIn](#) , [Facebook](#) , [Whitepages](#) , [BeenVerified](#) , [ZabaSearch](#) , [PublicRecords.com](#)<br /><br />

7. **Technical Analysis**: Analyze publicly available technical data.
    - ***Tools:***&emsp; [Shodan](#), [Censys](#), , [Google Search](#) , [Bing Search](#) , [CVE Details](#) , [Exploit-DB](#) , [Mitre ATT&CK](#) , [Common Vuln. Scoring System (CVSS)](#) , [NVD](#) , [OSINT Framework](#)

## 5. Active Directory Enumeration
<br /><br />

1. **Domain Enumeration**: Gather information about the domain structure.
    - ***Tools:***&emsp; [BloodHound](#), [PowerView](#), , [ADRecon](#) , [Nmap](#) , [LDAP Enumeration](#) , [Kerberos Enumeration](#) , [Enum4linux](#) , [Metasploit](#) , [CrackMapExec](#) , [Impacket](#)<br /><br />

2. **User Enumeration**: Identify domain users.
    - ***Tools:***&emsp; [BloodHound](#), [PowerView](#), , [ADRecon](#) , [Nmap](#) , [Kerberos Enumeration](#) , [Enum4linux](#) , [CrackMapExec](#) , [Impacket](#) , [NetUser](#) , [ADfind](#)<br /><br />

3. **Group Enumeration**: Discover groups and their memberships.
    - ***Tools:***&emsp; [BloodHound](#), [PowerView](#), , [ADRecon](#) , [Nmap](#) , [Kerberos Enumeration](#) , [Enum4linux](#) , [CrackMapExec](#) , [Impacket](#) , [NetGroup](#) , [ADfind](#)<br /><br />

4. **Domain Trust Enumeration**: Identify domain trusts and relationships.
    - ***Tools:***&emsp; [BloodHound](#), [PowerView](#), , [ADRecon](#) , [Nmap](#) , [Kerberos Enumeration](#) , [Enum4linux](#) , [CrackMapExec](#) , [Impacket](#) , [Netdom](#) , [TrustInspector](#)<br /><br />

5. **ACL Enumeration**: Review Access Control Lists for misconfigurations.
    - ***Tools:***&emsp; [BloodHound](#), [PowerView](#), , [ADRecon](#) , [Nmap](#) , [Kerberos Enumeration](#) , [Enum4linux](#) , [CrackMapExec](#) , [Impacket](#) , [NetDom](#) , [Dcom](#)<br /><br />

6. **Kerberoasting**: Extract service tickets to crack passwords.
    - ***Tools:***&emsp; [Kerberoast](#), [Rubeus](#), , [Impacket](#) , [CrackMapExec](#) , [PowerView](#) , [BloodHound](#) , [GetNPUsers](#) , [Kerbrute](#) , [Kerberoast](#) , [GetUserSPNs](#)<br /><br />

7. **SPN Enumeration**: Discover Service Principal Names.
    - ***Tools:***&emsp; [Kerberoast](#), [Rubeus](#), , [Impacket](#) , [CrackMapExec](#) , [PowerView](#) , [BloodHound](#) , [GetNPUsers](#) , [Kerbrute](#) , [GetUserSPNs](#) , [Kerberoast](#)<br /><br />

8. **Kerberos Ticket Extraction**: Obtain Kerberos tickets for analysis.
    - ***Tools:***&emsp; [Rubeus](#), [Impacket](#), , [Kerberoast](#) , [GetNPUsers](#) , [CrackMapExec](#) , [PowerView](#) , [BloodHound](#) , [Kerbrute](#) , [Kerberoast](#) , [Mimikatz](#)

## 6. Privilege Escalation Techniques

### 6.1 Linux Privilege Escalation<br /><br />

1. **SUID/SGID Files**: Identify files with SUID or SGID permissions.
    - ***Tools:***&emsp; [find](#), [LinPeas](#), , [Linux Exploit Suggester](#) , [GTFOBins](#) , [LinEnum](#) , [Pspy](#) , [Enum4linux](#) , [RogueMaster](#)<br /><br />

2. **Kernel Exploits**: Check for vulnerabilities in the Linux kernel.
    - ***Tools:***&emsp; [uname](#), [Kernel Exploits](#), , [Linux Exploit Suggester](#) , [Metasploit](#)<br /><br />

3. **Cron Jobs**: Identify misconfigured cron jobs.
    - ***Tools:***&emsp; [crontab](#), [LinPeas](#), , [Linux Exploit Suggester](#) , [GTFOBins](#) , [LinEnum](#) , [Pspy](#) , [Enum4linux](#) , [RogueMaster](#)<br /><br />

4. **Writable Directories**: Check for directories where files can be written.
    - ***Tools:***&emsp; [find](#), [LinPeas](#), , [Linux Exploit Suggester](#) , [GTFOBins](#) , [LinEnum](#) , [Pspy](#) , [Enum4linux](#) , [RogueMaster](#)<br /><br />

5. **Environment Variables**: Inspect environment variables for sensitive data.
    - ***Tools:***&emsp; [env](#), [printenv](#), , [LinPeas](#) , [Linux Exploit Suggester](#) , [GTFOBins](#) , [LinEnum](#) , [Pspy](#) , [Enum4linux](#) , [RogueMaster](#)<br /><br />

6. **SetUID Binaries**: Check for binaries with SetUID permissions.
    - ***Tools:***&emsp; [find](#), [LinPeas](#), , [Linux Exploit Suggester](#) , [GTFOBins](#) , [LinEnum](#) , [Pspy](#) , [Enum4linux](#) , [RogueMaster](#)<br /><br />

7. **Sudo Permissions**: Inspect sudo permissions and configurations.
    - ***Tools:***&emsp; [sudo -l](#), [LinPeas](#), , [Linux Exploit Suggester](#) , [GTFOBins](#) , [LinEnum](#) , [Pspy](#) , [Enum4linux](#) , [RogueMaster](#)

### 6.2 Windows Privilege Escalation<br /><br />

1. **Unquoted Service Paths**: Identify unquoted service paths that can be exploited.
    - ***Tools:***&emsp; [wmic](#), [PowerShell](#), , [Sysinternals](#) , [Accesschk](#) , [Procmon](#) , [Autoruns](#) , [WinPEAS](#) , [Windows Exploit Suggester](#) , [Metasploit](#)<br /><br />

2. **Insecure File Permissions**: Check for files with insecure permissions.
    - ***Tools:***&emsp; [icacls](#), [Accesschk](#), , [WinPEAS](#) , [Sysinternals](#) , [PowerShell](#) , [Windows Exploit Suggester](#) , [Metasploit](#) , [Netcat](#) , [Nmap](#) , [Dirbuster](#)<br /><br />

3. **Local Privilege Escalation Vulnerabilities**: Look for known local privilege escalation vulnerabilities.
    - ***Tools:***&emsp; [WinPEAS](#), [Windows Exploit Suggester](#), , [PowerShell](#) , [Metasploit](#) , [Nmap](#) , [Netcat](#) , [Exploit-DB](#) , [CVE Details](#) , [MSFvenom](#) , [MSFconsole](#)<br /><br />

4. **Scheduled Tasks**: Check for tasks that can be exploited for privilege escalation.
    - ***Tools:***&emsp; [schtasks](#), [PowerShell](#), , [Sysinternals](#) , [WinPEAS](#) , [Accesschk](#) , [Task Scheduler](#) , [Scheduled Tasks Explorer](#) , [Metasploit](#) , [Nmap](#) , [Netcat](#)<br /><br />

5. **Kerberos Ticket Extraction**: Obtain Kerberos tickets to elevate privileges.
    - ***Tools:***&emsp; [Rubeus](#), [Mimikatz](#), , [PowerView](#) , [Impacket](#) , [GetNPUsers](#) , [Kerberoast](#) , [Kerbrute](#) , [BloodHound](#) , [PowerSploit](#) , [Metasploit](#)<br /><br />

6. **Service Account Misconfigurations**: Identify misconfigured service accounts.
    - ***Tools:***&emsp; [PowerView](#), [BloodHound](#), , [WinPEAS](#) , [Nmap](#) , [Netcat](#) , [PowerShell](#) , [Service Account Finder](#) , [Metasploit](#) , [Windows Exploit Suggester](#) , [Sysinternals](#)<br /><br />

7. **DLL Hijacking**: Exploit DLL hijacking vulnerabilities for privilege escalation.
    - ***Tools:***&emsp; [DLL Hijacking](#), [PowerShell](#), , [Sysinternals](#) , [Metasploit](#) , [WinPEAS](#) , [Accesschk](#)
