<!-- Ethical Hacking Tools - Minimal Documentation -->

# Information Gathering

## Subdomain Enumeration
##### subfinder: `subfinder -d [target domain] -o [output file name] -all -v -timeout [seconds]`
    -d: Target domain (e.g., example.com)
    -o: Output file path (e.g., results.txt)
    -all: Use all sources
    -v: Verbose output
    -timeout: Timeout for requests in seconds

##### amass: `amass enum -d [target domain] -o [output file name] -brute -active -w [wordlist]`
    -d: Target domain
    -o: Output file path
    -brute: Enable brute forcing
    -active: Enable active subdomain enumeration
    -w: Wordlist for brute forcing

##### findomain: `findomain -t [target domain] -o [output file name] --sources [source1,source2,...]`
    -t: Target domain
    -o: Output file path
    --sources: Comma-separated list of sources (e.g., AlienVault,Censys)

##### assetfinder: `assetfinder [target domain] > [output file name]`
    [target domain]: Target domain
    >: Output redirection to a file

##### chaos: `chaos -d [target domain] -o [output file name] -subdomains -silent`
    -d: Target domain
    -o: Output file path
    -subdomains:  Find subdomains
    -silent:  Silent output

##### sublist3r: `sublist3r -d [target domain] -o [output file name] -b -v -t [threads]`
    -d: Target domain
    -o: Output file path
    -b: Show banner
    -v: Verbose output
    -t: Number of threads

## DNS Analysis
##### dig: `dig [target domain] [type] +trace`
    [target domain]: Target domain or IP address
    [type]: DNS record type (e.g., A, MX, NS, CNAME)
    +trace: Enable tracing

##### gobuster: `gobuster dns -d [target domain] -w [wordlist] -o [output file name] -t [threads] -wildcard`
    -d: Target domain
    -w: Wordlist for subdomain discovery
    -o: Output file path
    -t: Number of threads
    -wildcard: Filter wildcard DNS

##### shuffledns: `shuffledns -d [target domain] -w [wordlist] -o [output file name] -r -threads [num]`
    -d: Target domain
    -w: Wordlist
    -o: Output file
    -r: Resolve subdomains
    -threads: Number of threads

##### altdns: `altdns -i [input file] -o [output file name] -w [wordlist] -s [seed] -t [threads]`
    -i: Input file containing subdomains
    -o: Output file path
    -w: Wordlist for alterations
    -s: Seed for alterations
     -t: Number of threads

##### dnsgen: `dnsgen -o [output file name] -w [wordlist] [target domain] -a -num [count]`
    -o: Output file path
    -w: Wordlist
    [target domain]: Target domain
    -a:  Append the root domain
    -num: Number of variations

##### dnsx: `dnsx -l [targets.txt] -o [output file name] -a -mx -ns -c [concurrency] -retry [num]`
    -l: Input file containing targets
    -o: Output file path
    -a: Resolve A records
    -mx: Resolve MX records
    -ns: Resolve NS records
    -c: Concurrency level
    -retry: Number of retries

##### dnscan: `dnscan -d [target domain] -w [wordlist] -o [output file name] -t [threads] -r`
    -d: Target domain
    -w: Wordlist
    -o: Output file
    -t: Threads
    -r: Resolve

##### fierce: `fierce -dns [target domain] -out [output file name] -threads [num] -dnsserver [DNS server]`
    -dns: Target domain
    -out: Output file
    -threads: Number of threads
    -dnsserver: Specify a DNS server

##### dnsrecon: `dnsrecon -d [target domain] -n [nameserver] -t [type] -o [output file name] --threads [num] -D [dictionary]`
    -d: Target domain
    -n: Nameserver
    -t: Record type (e.g., A, MX, NS)
    -o: Output file
    --threads: Number of threads
    -D: Dictionary file

## Network Information
##### whois: `whois [target domain]`
    [target domain]: Target domain

##### bgp.he: `bgp.he [AS number or IP address]`
    [AS number or IP address]: Autonomous System number or IP

##### traceroute: `traceroute [target IP or domain]`
    [target IP or domain]: Target IP or domain

##### host: `host -t [type] [target domain or IP]`
     -t: Type of lookup (e.g., A, MX)
    [target domain or IP]: Target domain or IP

## Cloud Infrastructure Reconnaissance
##### cloud_enum: `cloud_enum -k [AWS_ACCESS_KEY_ID] -s [AWS_SECRET_ACCESS_KEY] --services [service1,service2,...] --regions [region1,region2,...]`
    -k: AWS Access Key ID
    -s: AWS Secret Access Key
    --services: Services to enumerate (e.g., s3, ec2, rds)
    --regions: AWS regions

##### scout: `scout aws --region [region] --list-all --output [format]`
    --region: AWS region
    --list-all: List all resources
    --output: Output format (e.g., json)

##### cfr: `cfr [domain] -a -json`
    [domain]: Cloudflare domain.
    -a:  Analyze all.
    -json: Output in JSON.

##### s3scanner: `s3scanner --url [S3 bucket URL] --list-objects --check-acl --threads [num]`
    --url: S3 bucket URL
    --list-objects: List objects in the bucket
    --check-acl: Check ACLs
    --threads: Number of threads

##### gcpbucketbrute: `gcpbucketbrute -p [project_id] -w [wordlist] -threads [num]`
    -p: GCP Project ID
    -w: Wordlist for bucket names
    -threads: Number of threads

##### prowler: `prowler -c [check_id] -r [region] -f [output_file] -s [profile]`
    -c: Check ID
    -r: AWS region
    -f: Output file path
    -s: AWS profile

## Database Information
##### ripe-dbase: `ripe-dbase -T [object] -a -b`
    -T: Type of object (e.g., person, organisation)
    -a:  Show all attributes
    -b:  Bulk output


# Vulnerability Analysis
## Port Scanning
##### nmap: `nmap -sV -p- [target IP or domain] -oN [output file name] --script [script]`
    -sV: Service version detection
    -p-: Scan all ports
    [target IP or domain]: Target IP or domain
    -oN: Normal output file
    --script: Nmap script (e.g., vulners)

##### naabu: `naabu -p [ports] [target IP or range] -o [output file name] -c [concurrency] -sS -vv`
    -p: Ports to scan (e.g., 80,443,22)
    [target IP or range]: Target IP or range
    -o: Output file path
    -c: Concurrency level
    -sS: SYN scan
    -vv: Very verbose

##### rustscan: `rustscan -a [target IP or range] --ulimit [limit] -o [output file name] --scripts [script(s)] --ports [ports]`
    -a: Target IP or range
    --ulimit: Increase open file limit
    -o: Output file path
    --scripts:  Scripts to run
    --ports: Ports to scan

##### masscan: `masscan -p [ports] --rate [rate] [target IP range] -oL [output file name] --wait [seconds]`
    -p: Ports to scan
    --rate: Packets per second
    [target IP range]: Target IP range
    -oL: List output file
    --wait: time to wait

## Web Application Analysis
##### testssl.sh: `testssl.sh --url [target URL] -E -p`
    --url: Target URL
    -E:  Show all errors
    -p:  Check protocols

##### tlsx: `tlsx -l [targets.txt] -o [output file name] -sni [SNI] -ciphers -protos`
    -l: Input file containing targets
    -o: Output file path
    -sni: Server Name Indication
    -ciphers: Check ciphers
    -protos: Check protocols

##### gau: `gau [target domain] > [output file name]`
    [target domain]: Target domain
    >: Output redirection

##### waybackurls: `waybackurls [target domain] > [output file name]`
    [target domain]: Target domain
    >: Output redirection

##### katana: `katana -u [target URL] -o [output file name] -c [concurrency] -depth [depth] -jc`
    -u: Target URL
    -o: Output file path
    -c: Concurrency
    -depth: Crawl depth
    -jc: JSON output

##### hakrawler: `hakrawler -u [target URL] -o [output file name] -depth [depth] -scope [regex]`
    -u: Target URL
    -o: Output file path
    -depth: Crawl depth
    -scope: Regex for allowed URLs

##### gospider: `gospider -s [target URL] -o [output file name] -t [threads] -d [depth]`
    -s: Starting URL
    -o: Output file path
    -t: Threads
    -d: Depth

##### ffuf: `ffuf -w [wordlist] -u [target URL]/FUZZ -o [output file name] -mc [status codes] -fs [size]`
    -w: Wordlist
    -u: Target URL with FUZZ keyword
    -o: Output file path
    -mc: Match status codes (e.g., 200,204,302)
    -fs: Filter by size

##### feroxbuster: `feroxbuster -w [wordlist] -u [target URL] -o [output file name] -d [depth] -x [extensions] -fc [status code]`
    -w: Wordlist
    -u: Target URL
    -o: Output file path
    -d: Depth
    -x: File extensions (e.g., php,html)
    -fc:  Filter Status Code

##### dirsearch: `dirsearch -w [wordlist] -u [target URL] -o [output file name] -e [extensions] -t [threads]`
    -w: Wordlist
    -u: Target URL
    -o: Output file path
    -e: File extensions
    -t: Threads

##### wfuzz: `wfuzz -c -w [wordlist] --hc [status code] [target URL]/FUZZ -o [output file name] --hh [bytes] --hw [words] --hl [lines]`
    -c: Colorize output
    -w: Wordlist
    --hc: Hide status code
    [target URL]/FUZZ: Target URL with FUZZ keyword
    -o: Output file
    --hh: Hide Header Bytes
    --hw: Hide Header Words
    --hl: Hide Header Lines

##### arjun: `arjun -u [target URL] -p [parameter] -o [output file name] -m [mode] -c [concurrency]`
    -u: Target URL
    -p: Parameter to fuzz
    -o: Output file path
    -m: Mode (e.g., get, post, all)
    -c: Concurrency

##### paramspider: `paramspider -d [target domain] -o [output file name] -s [level] -b`
    -d: Target domain
    -o: Output file path
    -s: Stringency level (e.g., high, medium, low)
    -b:  Use big dictionary

##### waybackparam: `waybackparam [target domain] > [output file name]`
    [target domain]: Target domain
    >: Output redirection

##### parameth: `parameth -u [target URL] -p [parameter list] -o [output file name] -a [analysis_level] -t [threads]`
    -u: Target URL
    -p: Parameter list (comma-separated)
    -o: Output file
    -a: Analysis level
    -t: Threads

##### qsreplace: `qsreplace "[original_query]" "[replacement_query]" -o [output file name] -l [input_file]`
    "[original_query]": Original query string
    "[replacement_query]": Replacement query string
    -o: Output file
    -l: Input file

##### linkfinder: `linkfinder [target URL] -o [output file name] -r -d`
    [target URL]: Target URL
    -o: Output file path
    -r: Recursive
    -d:  Domain

##### jsanalyze.py: `jsanalyze.py -u [target URL] -o [output file name] -c [cookies] -l [localstorage]`
    -u: Target URL
    -o: Output file
    -c:  Check cookies
    -l: Check local storage

##### secretfinder: `secretfinder -i [input file/URL] -o [output file name] -e [extensions] -r`
    -i: Input file or URL
    -o: Output file path
    -e: File extensions to search
    -r: Recursive

##### getjs: `getjs [target URL]`
    [target URL]: Target URL

##### subjs: `subjs -u [target URL] -o [output file name] -s -a`
    -u: Target URL
    -o: Output file
    -s: Save
    -a:  Analyze

## Vulnerability Scanning
##### nuclei: `nuclei -t [nuclei_templates] -u [target URL] -o [output file name] -c [concurrency] -severity [severity]`
    -t: Nuclei templates (e.g., sqli, xss)
    -u: Target URL
    -o: Output file path
    -c: Concurrency
    -severity: Severity level (e.g., high, critical)

##### nikto: `nikto -h [target URL] -o [output file name] -p [ports] -C [CGI options]`
    -h: Target URL or host
    -o: Output file path
     -p: Ports
     -C: CGI Options

##### zap: `zap -cmd -quickurl [target URL] -report [report_file] -reporttype [type]`
    -cmd: Run in command-line mode
    -quickurl: Target URL for quick scan
    -report: Report file path
    -reporttype: Report type (e.g., html, xml)

##### wpscan: `wpscan --url [target URL] --enumerate [options] --output [output.txt]`
    --url: Target WordPress URL
    --enumerate: Enumeration options (e.g., p, u, t)
    --output: Output file

##### cent: `cent -t [target URL] -o [output file name]`
    -t: Target URL
    -o: Output file

##### dalfox: `dalfox url [target URL] -b [burp collaborator] -o [output file name]`
    url:  Keyword
    [target URL]: Target URL
    -b: Burp Collaborator payload
    -o: Output file

##### xsstrike: `xsstrike -u [target URL] -p [parameter] -o [output file name] --crawl`
    -u: Target URL
    -p: Parameter
    -o: Output file
    --crawl: Crawl the site

##### xsser: `xsser -u [target URL] --all --output [output file name]`
    -u: Target URL
    --all: Test all vectors
    --output: Output file

##### kxsstester: `kxsstester -u [target URL] -p [parameter] -o [output file name]`
    -u: Target URL
    -p: Parameter
    -o: Output file

##### brutexss: `brutexss -u [target URL] -w [wordlist] -o [output file name]`
    -u: Target URL
    -w: Wordlist
    -o: Output file

##### sqlmap: `sqlmap -u "[target URL]?id=1" --dbs -o [output file name]`
    -u: Target URL (with injectable parameter)
    --dbs: Enumerate databases
    -o: Output file

##### nosqli: `nosqli -u [target URL] -p [parameter] -o [output file name]`
    -u: Target URL
    -p: Parameter
    -o: Output file

##### nosqlmap: `nosqlmap -u [target URL] --all -o [output file name]`
    -u: Target URL
    --all: Test all
    -o: Output file

##### ghauri: `ghauri -u [target URL] -p [parameter] --level [level] --risk [risk] -o [output file name]`
    -u: Target URL
    -p: Parameter
    --level: Level of tests (1-5)
    --risk: Risk of tests (1-3)
    -o: Output file

##### jsql: `jsql "[target URL]?id=1"`
    [target URL]?id=1: Target URL

##### sqli-detector: `sqli-detector -u [target URL] -p [parameter]`
    -u: Target URL
    -p: Parameter

##### ssrfmap: `ssrfmap -u [target URL] -o [output file name] --crawl`
    -u: Target URL
    -o: Output file
    --crawl: Crawl the site

##### gopherus: `gopherus --protocol [protocol] --host [host] --port [port] --path [path]`
    --protocol: Protocol (e.g., http, gopher)
    --host: Host
    --port: Port
    --path: Path

##### ground-control: `ground-control -u [target URL] -d [delay] -o [output file name]`
    -u: Target URL
    -d: Delay
    -o: Output file

##### xxeinjector: `xxeinjector -u [target URL] -p [parameter] -o [output file name]`
    -u: Target URL
    -p: Parameter
    -o: Output file

##### docem: `docem -u [target URL] -o [output file name]`
    -u: Target URL
    -o: Output file

##### lfisuite: `lfisuite -u [target URL] -lfi [payload] -o [output file name]`
    -u: Target URL
    -lfi: LFI payload
    -o: Output file

##### fimap: `fimap -u [target URL] -p [parameter] -o [output file name]`
    -u: Target URL
    -p: Parameter
    -o: Output file

##### dotdotpwn: `dotdotpwn -m [protocol] -h [target host] -d [depth] -o [output file name]`
    -m: Protocol (e.g., http, ftp)
    -h: Target host
    -d: Depth
    -o: Output file

##### tplmap: `tplmap -u [target URL] -o [output file name]`
    -u: Target URL
    -o: Output file

##### crlfuzz: `crlfuzz -u [target URL] -w [wordlist] -o [output file name]`
    -u: Target URL
    -w: Wordlist
    -o: Output file

##### corsy: `corsy [target URL]`
     [target URL]: Target URL

##### kiterunner: `kiterunner --list [targets.txt] -o [output file name]`
    --list: File containing target URLs
    -o: Output file

##### postman-smuggler: `postman-smuggler -u [target URL] -d "[data]" -c "[CLRF headers]"`
    -u: Target URL
    -d:  Data
    -c:  CLRF headers

##### crAPI: `crAPI -u [target URL] -m [module] -a [action] -o [output file name]`
    -u: Target URL
    -m: Module
    -a: Action
    -o: Output file

##### restler: `restler --url [target URL] --grammar_files [grammar_directory]`
    --url: Target URL
    --grammar_files: Directory containing grammar files

##### swagger-cli: `swagger-cli validate [swagger.json/yaml]`
    validate:  Command
    [swagger.json/yaml]: Swagger file

##### graphqlmap: `graphqlmap -u [graphql endpoint] -o [output file name] --introspection`
    -u: GraphQL endpoint URL
    -o: Output file
    --introspection: Use introspection

##### clairvoyance: `clairvoyance -u [target URL] -o [output file name]`
    -u: Target URL
    -o: Output file

##### inql: `inql -u [graphql endpoint]`
    -u: GraphQL endpoint

##### graphw00f: `graphw00f -u [graphql endpoint]`
    -u: GraphQL endpoint

##### wsdlfuzz: `wsdlfuzz -u [wsdl url] -o [output file name]`
    -u: WSDL URL
    -o: Output file

##### soapui: `soapui [project.xml]`
    [project.xml]: SoapUI project file

##### jwt_tool: `jwt_tool -t [jwt] -I`
    -t: JWT token
    -I: Interactive mode

##### crackjwt: `crackjwt [jwt] -w [wordlist]`
    [jwt]: JWT token
    -w: Wordlist

##### jwt-hack: `jwt-hack [jwt]`
    [jwt]: JWT Token

##### oauth2test: `oauth2test -u [authorization url] --client-id [client id] --client-secret [client secret]`
    -u: Authorization URL
    --client-id: Client ID
    --client-secret: Client Secret

##### burp-oauth: `burp-oauth --url [authorization url] --client_id [client id] --client_secret [client secret]`
    --url: Authorization URL
    --client_id: Client ID
    --client_secret: Client Secret

##### session-fuzz: `session-fuzz -u [target URL] -c [cookie name] -w [wordlist] -o [output file name]`
    -u: Target URL
    -c: Cookie name
    -w: Wordlist
    -o: Output file

##### session-bruteforcer: `session-bruteforcer -u [login url] -p [password parameter] -U [username parameter] -l [usernames.txt] -W [passwords.txt] -c [cookie name]`
    -u: Login URL
    -p: Password parameter name
    -U: Username parameter name
    -l: List of usernames
    -W: List of passwords
    -c: Cookie name

# Post-Exploitation
#### winpeas.exe: `winpeas.exe`

##### windows-exploit suggester.py: `windows-exploit suggester.py --database [database.csv]`
    --database: Path to the database CSV file

##### Watson.exe: `Watson.exe`

##### accesschk.exe: `accesschk.exe -quvwc users [target]`
    -quvwc: Options
    users:  Users
    [target]: Target

##### Get-Process: `Get-Process`

##### Get-Service: `Get-Service`

##### Get-WmiObject: `Get-WmiObject -Class [className]`
    -Class: WMI class name

##### Get-ScheduledTask: `Get-ScheduledTask`

##### crackmapexec: `crackmapexec [protocol] [target(s)] -u [user] -p [password] -H [hash] -d [domain]`
    [protocol]: Protocol (e.g., smb, winrm)
    [target(s)]: Target IP(s) or range
    -u: Username
    -p: Password
    -H: NTLM hash
    -d: Domain

##### evil-winrm: `evil-winrm -i [target IP] -u [username] -p [password]`
    -i: Target IP
    -u: Username
    -p: Password

##### ssh: `ssh [user]@[target IP] -p [port]`
    [user]: Username
    [target IP]: Target IP
    -p: Port

##### mimikatz.exe: `mimikatz.exe`

##### LaZagne.exe: `LaZagne.exe all -o [output.txt]`
    all:  Get all
    -o: Output file

##### reg query: `reg query [key]`
    [key]: Registry key

## Lateral Movement


##### python: `python -m http.server [port]`
    -m: Module
    http.server: Serve
    [port]: Port

##### net use: `net use \\[target IP]\IPC$ "[password]" /user:"[domain]\[username]"`
    \\[target IP]\IPC$: IPC share
    "[password]": Password
    /user:"[domain]\[username]": Domain and username

##### copy: `copy [local file] \\[target IP]\C$\[remote path]`
     [local file]: Local file
     \\[target IP]\C$\[remote path]: Remote path

## Web Shells & Frameworks


##### arachni: `arachni [target URL] --report-save-path [report.html]`
    [target URL]: Target URL
    --report-save-path: Path to save the report

##### bugbounty-auto: `bugbounty-auto --scope [scope.txt] --config [config.yaml]`
    --scope: Scope file
    --config: Configuration file

##### reconftw: `reconftw -d [target domain] -all`
    -d: Target domain
    -all: Run all modules

##### autorecon: `autorecon [target IP or domain]`
    [target IP or domain]: Target

##### interlace: `interlace -f [targets.txt] -m [modules] -o [output_dir]`
     -f: targets file
     -m: Modules
     -o: Output dir

# Wordlist Generation


##### cewl: `cewl [target URL] -w [wordlist.txt] -d [depth]`
    [target URL]: Target URL
    -w: Output wordlist file
    -d: Depth

##### kwprocessor: `kwprocessor -i [input_file] -o [output_file] -s [separator]`
    -i: Input file
    -o: Output file
    -s: Separator

##### domain-analyzer: `domain-analyzer -i [domains.txt] -o [output.txt]`
    -i: Input file
    -o: Output file

##### seclists: (Tool/Collection of wordlists, no direct command-line usage documented here)

# Utilities


##### puredns: `puredns resolve -l [domains.txt] -r [resolvers.txt] -o [resolved.txt]`
    -l: Input file containing domains
    -r: Resolver list
    -o: Output file

##### gf: `gf [pattern] [input]`
    [pattern]: Grep pattern
    [input]: Input

##### anew: `anew [input_file] [output_file]`
    [input_file]: Input file
    [output_file]: Output file

##### urldedupe: `urldedupe [input_file] -o [output_file]`
    [input_file]: Input file
    -o: Output file

##### sed: `sed 's/old/new/g' [input_file] > [output_file]`
    's/old/new/g': Sed command
    [input_file]: Input file
    >: Output redirection

##### awk: `awk '{print $1}' [input_file] > [output_file]`
    '{print $1}': Awk command
    [input_file]: Input file
    >: Output redirection

##### cut: `cut -d',' -f1 [input_file] > [output_file]`
    -d',': Delimiter
    -f1: Field
    [input_file]: Input file
    >: Output redirection

##### proxychains: `proxychains [command]`
    [command]: Command to run through proxychains

##### mitmproxy: `mitmproxy -p [port]`
    -p: Port

##### curl: `curl [target URL] -v -H "Header: Value"`
    [target URL]: Target URL
    -v: Verbose
    -H: Header

##### proxychains4: `proxychains4 [command]`
     [command]: Command

##### socat: `socat tcp-listen:[local_port],fork tcp-connect:[remote_host]:[remote_port]`

##### tcpdump: `tcpdump -i [interface] -n -s 0 -w [capture.pcap]`
    -i: Interface
    -n: Don't resolve names
    -s 0: Capture the entire packet
    -w: Output capture file

##### tshark: `tshark -r [capture.pcap] -T fields -e [field1] -e [field2]`
    -r: Input capture file
    -T fields: Output format
    -e: Field to extract (e.g., ip.src, ip.dst)

##### hashcat: `hashcat -m [hash_type] [hash_file] [wordlist]`
    -m: Hash type
    [hash_file]: File containing hashes
    [wordlist]: Wordlist

##### john: `john --format=[format] --wordlist=[wordlist] [hash_file]`
    --format: Hash format
    --wordlist: Wordlist
    [hash_file]: File containing hashes

##### upload-fuzz: `upload-fuzz -u [upload URL] -p [file parameter] -w [wordlist]`
    -u: Upload URL
    -p: File parameter name
    -w: Wordlist

# Cloud Exploitation


##### scoutsuite: `scoutsuite aws --region [region] --audit`
     aws: Cloud Provider
    --region: AWS region
    --audit: Audit

##### aws-nuke: `aws-nuke --profile [profile] --regions [region(s)] --force`
    --profile: AWS profile
    --regions: AWS regions
    --force: Force deletion

##### gcloud: `gcloud [command] [arguments]`
    gcloud: GCP CLI
    [command]: gcloud command (e.g., compute, storage)
    [arguments]: Command arguments

##### az: `az [command] [arguments]`
    az: Azure CLI
    [command]: Azure command
    [arguments]: Command arguments

# Fuzzing


##### radamsa: `radamsa -n [iterations] -o [output_file] [input_file]`
    -n: Number of iterations
    -o: Output file
    [input_file]: Input file

##### afl-fuzz: `afl-fuzz -i [input_dir] -o [output_dir] -- [program] [@@]`
    -i: Input directory
    -o: Output directory
    --: Separator
    [program]: Target program
    @@: Input file placeholder
