## 📌 CORE SEARCH OPERATORS

### BASIC OPERATORS
    site:        - Restrict to specific domain         (site:example.com)
    inurl:       - URL contains text                   (inurl:admin)
    intitle:     - Page title contains text            (intitle:"login")
    intext:      - Page body contains text             (intext:"password")
    filetype:    - Filter by file type                 (filetype:pdf)
    ext:         - Filter by file extension            (ext:sql)
    cache:       - Show cached version                 (cache:example.com)
    related:     - Find related sites                  (related:example.com)
    info:        - Get site information                (info:example.com)
    define:      - Get word definition                (define:dorking)

### LOGICAL OPERATORS
    AND          - Both terms required                 (cat AND dog)
    OR           - Either term                         (cat OR dog)
    |            - Alternative OR                      (cat | dog)
    -            - Exclude term                        (cat -dog)
    " "          - Exact phrase match                  ("error logs")
    ( )          - Group terms                         ((vulnerability OR exploit) AND web)
    *            - Wildcard placeholder                (how to * a database)

### CONTENT TYPE OPERATORS
    allintext:   - All terms in page text              (allintext:"username password")
    allinurl:    - All terms in URL                    (allinurl:admin login)
    allintitle:  - All terms in title                  (allintitle:"index of")
    allinanchor: - All terms in anchor text            (allinanchor:"click here")

## 🔍 ADVANCED SEARCH TECHNIQUES

### PROXIMITY SEARCHING
    AROUND(n)    - Terms within n words                ("password" AROUND(5) "key")
    NEAR(n)      - Alternative proximity               ("admin" NEAR(3) "portal")

### TEMPORAL FILTERS
    before:      - Results before date                 (before:2023-12-31)
    after:       - Results after date                  (after:2020-01-01)
    daterange:   - Date range search                   (daterange:20200101-20201231)

### NUMERIC RANGES
                - Number range                        (price $100..$500)
    in           - Unit conversion                     (100m in feet)

### SPECIALIZED SEARCHES
    phonebook:   - Phone directory                     (phonebook:John+NY)
    map:         - Map results                         (map:NYC)
    weather:     - Weather forecast                    (weather:London)
    stocks:      - Stock information                   (stocks:GOOG)
    movie:       - Movie information                   (movie:"Inception")
    book:        - Book information                    (book:"1984")
    link:       - Pages linking to URL               (link:example.com)
    location:   - Filter by location                 (location:US)
    AROUND(n)   - Terms within n words               ("password" AROUND(5) "key")

## 🎯 TARGETED SEARCH SYNTAX

### FILE SEARCHING
    inurl:       - Search for file paths               (inurl:/etc/passwd)
    filehash:    - Search by file hash                 (filehash:md5)
    mimetype:    - Search by MIME type                 (mimetype:application/json)

### CODE SEARCHING
    repo:        - GitHub repository search            (repo:torvalds/linux)
    path:        - File path in repositories           (path:src/main/java)
    language:    - Code language filter                (language:python)

### MEDIA SEARCHING
    imagesize:   - Image dimensions                    (imagesize:1920x1080)
    inpostauthor# Blog post author                    (inpostauthor:"john doe")

## ⚙️ SPECIAL CHARACTER SYNTAX
    @            - Social media tags                   (@twitter)
    #          - Hashtag search                      (#cybersecurity)
    $            - Currency/prices                     ($500 laptop)
    +            - Force term inclusion                (+required)
    _            - Underscore matching                 (file_name)

## 🛡️ SECURITY-SPECIFIC DORKS
    intitle:"index of" - Directory listings            (intitle:"index of" /backup)
    intext:"SQL syntax" - Database errors              (intext:"SQL syntax error")
    filetype:env - Environment files                   (filetype:env DB_PASSWORD)
    inurl:phpinfo() - PHP configuration                (inurl:phpinfo())



## CORE SEARCH OPERATORS  (EXPANDED)

### Basic Search Syntax
    site: inurl: intitle: intext: filetype: ext: 
    allintext: allintitle: allinurl: allinanchor:
    cache: info: related: define: location: loc: 
    weather: stocks: before: after: cr: inanchor:

### Boolean Logic
    AND OR NOT  |  & + - "exact phrase"  (grouping) 
       (range) *  (wildcard) ~  (synonym) 

### Advanced Operators
    inanchor: inpostauthor: inposttitle: blogurl:
    source: app: more: has: prefers: 

## FILE TYPE OPERATORS  (300+)

### Document Formats
    pdf | doc | docx | xls | xlsx | ppt | pptx | odt | ods | odp | rtf | csv | tsv | txt | tex | md | markdown | pages | numbers | key | epub | mobi | chm | djvu | oxps | xps

### Media Files
    jpg | jpeg | png | gif | bmp | tiff | tif | webp | svg | ico | psd | ai | eps | raw | cr2 | cr3 | nef | orf | sr2 | arw | rw2 | pef | srf | dng | raf | 3fr | kdc | mef | mrw | nrw

### Archive Formats
    zip | rar | 7z | tar | gz | bz2 | xz | zst | lzma | lz4 | iso | dmg | exe | msi | deb | rpm | pkg | apk | ipa | jar | war | ear | whl | egg | gem | nupkg | snap | flatpak | appimage

### Developer Files
    php | py | js | jsx | ts | tsx | java | class | jar | rb | go | rs | swift | kt | kts | scala | pl | pm | lua | r | dart | elm | hs | erl | ex | exs | clj | cljs | cljc | sc | scm | ss | rkt

### Config Files
    conf | config | cfg | ini | inf | reg | yml | yaml | properties | prop | env | dotenv | htaccess | htpasswd | xml | json | toml | hcl | tfvars | editorconfig | gitconfig | npmrc

### Database Files
    sql | db | dbf | mdb | accdb | sqlite | sqlite3 | dump | export | backup | bkp | dbk | myd | myi | frm | ibd | wal | ldb | mdf | ndf | bak | trn | dmp | archive | restore | snapshot

## URL PATH OPERATORS  (250+)

### Authentication Paths
    login | signin | auth | authentication | oauth | sso | openid | saml | ldap | kerberos | register | signup | password | passwd | pwd | reset | recovery | 2fa | mfa | otp | totp

### Admin Interfaces
    admin | administrator | dashboard | panel | console | portal | manager | control | root | system | cms | wp-admin | joomla-admin | drupal | adminer | phpmyadmin | directadmin

### API Endpoints
    api | rest | graphql | soap | rpc | jsonrpc | xmlrpc | endpoint | v1 | v2 | v3 | beta | alpha | developer | swagger | openapi | postman | webhook | callback | webapi | ajax | rpc

### Development Environments
    test | testing | dev | development | stage | staging | prod | production | uat | preprod | sandbox | demo | local | debug | qa | quality | verification | validation | experimental

### Sensitive Directories
    config | configuration | backup | restore | dump | upload | download | export | import | migrate | install | setup | update | upgrade | patch | hotfix | temp | tmp | cache | session

### Version Control
    git | svn | hg | gitlab | github | bitbucket | repo | repository | git | svn | hg | bzr | cvs | DS_Store | idea | vscode | project | classpath | settings | nbproject

## TITLE OPERATORS  (200+)

### Directory Listings
    "index of" | "directory listing" | "parent directory" | "file listing" | "contents of" | "file tree" | "directory contents" | "folder contents" | "server at" | "server directory"

### Authentication Pages
    "login" | "sign in" | "log in" | "authentication" | "authorization" | "password reset" | "otp verification" | "mfa setup" | "two factor" | "account recovery" | "forgot password"

### Error Messages
    "error" | "warning" | "exception" | "stack trace" | "debug" | "failed" | "syntax error" | "crash" | "fatal" | "unhandled" | "critical" | "alert" | "notice" | "deprecated"

### Restricted Content
    "restricted" | "confidential" | "secret" | "private" | "internal" | "classified" | "proprietary" | "sensitive" | "protected" | "need to know" | "eyes only" | "top secret"

## CONTENT KEYWORDS  (300+)

### Authentication Patterns
#### API Keys
    api[_]?key | api[_]?token | api[_]?secret | client[_]?id | client[_]?secret | client[_]?key | oauth[_]?token | oauth[_]?key | oauth[_]?secret | bearer[_]?token

#### Cloud Credentials
    aws[_]? (access[_]?key | secret[_]?key | session[_]?token) | gcp[_]? (api[_]?key | service[_]?account) | azure[_]? (client[_]?secret | account[_]?key)

#### Database Connections
    db[_]? (url | string | conn | connection | host | port | name | user | pass | pwd) |  (mysql | postgres | mongo | redis)[_]? (host | port | user | pass | pwd | name | uri | url)

### Error Patterns
    stack[_]?trace |  (error | exception | warning)[_]? (log | message | code | details) | failed[_]? (to | request | response | connection | query) |  (sql | database)[_]?error

## EXCLUSION FILTERS  (ENHANCED)

### Domain Exclusions
    -site:github.com -site:gitlab.com -site:bitbucket.org -site:stackoverflow.com -site:pastebin.com -site:repl.it -site:codepen.io -site:jsfiddle.net

### Path Exclusions
    -inurl:/node_modules/ -inurl:/vendor/ -inurl:/tests/ -inurl:/examples/ -inurl:/demos/ -inurl:/samples/ -inurl:/tutorials/ -inurl:/documentation/

### Content Exclusions
    -intext:"example" -intext:"test" -intext:"sample" -intext:"placeholder" -intext:"dummy" -intext:"mock" -intext:"template" -intext:"tutorial"

## SPECIALIZED OPERATORS  (DEEP TECH)

### Technical Discovery
    intext:"powered by" | "built with" | "running on" | "server:" | "x-powered-by:" | "x-generator:" | "framework:" | "cms:" | "version:" | "build:"

### Device Interfaces
    intitle:"router" | "switch" | "firewall" | "camera" | "dvr" | "nvr" | "iot" | "embedded" | "scada" | "hmi" | "plc" | "rtu" | "ics" | "scada" | "industrial"

### Industrial Protocols
    inurl:"/modbus/" | "/opc/" | "/profibus/" | "/dnp3/" | "/iec/" | "/bacnet/" | "/ethernet/ip" | "/ff/" | "/hart/" | "/cc-link/" | "/devicenet/" | "/controlnet/"

### Medical Systems
    inurl:"/pacs/" | "/dicom/" | "/his/" | "/ris/" | "/emis/" | "/ehr/" | "/patient/" | "/medical/" | "/hospital/" | "/clinic/" | "/pharmacy/" | "/laboratory/"