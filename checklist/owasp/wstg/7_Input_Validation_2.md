
### 7.11 TESTING FOR CODE INJECTION

#### 7.11.1 FILE INCLUSION
    - Local file inclusion
    - Remote file inclusion
    - Log poisoning
    - Wrapper abuse
    - PHAR injection
    - ZipArchive risks
    - Deserialization
    - allow_url_include
    - File protocol
    - Filter chains

### 7.12 TESTING FOR COMMAND INJECTION
    - OS command injection
    - Shellshock testing
    - Argument injection
    - Pipeline abuse
    - Subshell execution
    - Environment vars
    - Wildcard attacks
    - Deserialization
    - CLI parameter
    - Binary planting

### 7.13 TESTING FOR FORMAT STRING
    - %n exploitation
    - Memory corruption
    - Information leaks
    - Stack overwrite
    - GOT overwrite
    - ASLR bypass
    - Buffer overflow
    - C++ iostream
    - WFormat security
    - Log formatting

### 7.14 TESTING FOR INCUBATED VULNS
    - Delayed execution
    - Time bombs
    - Batch processing
    - Queue poisoning
    - Background jobs
    - Cron job abuse
    - Temp file races
    - Session storage
    - Cache poisoning
    - Database triggers

### 7.15 TESTING FOR HTTP SPLITTING
    - CRLF injection
    - Header splitting
    - Response queue
    - Cache poisoning
    - Chunked encoding
    - HTTP/2 abuse
    - Request smuggling
    - Proxy confusion
    - Browser quirks
    - WAF evasion

### 7.16 TESTING INCOMING REQUESTS
    - IP spoofing
    - Header forgery
    - User-agent abuse
    - Referer manipulation
    - Accept-Language
    - Cookie tampering
    - Origin spoofing
    - Forwarded header
    - X-Forwarded-For
    - True-Client-IP

### 7.17 TESTING HOST HEADER
    - Password reset
    - Cache poisoning
    - SSRF via Host
    - Virtual host
    - Domain fronting
    - Cloud metadata
    - Internal service
    - XSS via Host
    - Routing bypass
    - Admin console

### 7.18 TESTING SSTI
    - Template context
    - Sandbox escape
    - Python Jinja2
    - Twig PHP
    - Freemarker
    - Velocity
    - Handlebars
    - ERB Ruby
    - ASP.NET Razor
    - Smarty

### 7.19 TESTING SSRF
    - Internal service
    - Cloud metadata
    - DNS rebinding
    - Gopher protocol
    - File protocol
    - Port scanning
    - HTTP redirection
    - FTP abuse
    - URL parser
    - Open redirect

### 7.20 TESTING MASS ASSIGNMENT
    - JSON properties
    - Form fields
    - API parameters
    - Model attributes
    - Admin flags
    - Role assignment
    - Privilege fields
    - Metadata
    - Protected vars
    - Nested objects

### 7.21 TESTING FOR DESERIALIZATION VULNERABILITIES
    - Java serialized objects
    - .NET ViewState
    - PHP object injection
    - Python pickle
    - Ruby Marshal
    - Node.js node-serialize
    - Binary format abuse
    - JSON deserialization
    - XML decoder risks
    - Custom parsers

### 7.22 TESTING FOR PROTOTYPE POLLUTION
    - JavaScript __proto__
    - Constructor abuse
    - JSON.parse reviver
    - Object recursive merge
    - Lodash vulnerabilities
    - AngularJS exploitation
    - Node.js module abuse
    - Template engines
    - Schema validation bypass
    - Deep clone attacks

### 7.23 TESTING FOR REGEX INJECTION
    - ReDoS attacks
    - Evil regex patterns
    - Catastrophic backtracking
    - Nested quantifiers
    - Exponential blowup
    - Polynomial attacks
    - WAF bypass patterns
    - Regex engine flaws
    - Time-based detection
    - Unicode abuse

### 7.24 TESTING FOR SERVER-SIDE JAVASCRIPT
    - Node.js eval()
    - Function constructor
    - VM module abuse
    - Sandbox escape
    - NPM package risks
    - Process injection
    - Child_process
    - File system access
    - Environment vars
    - Buffer overflow

### 7.25 TESTING FOR CLIENT-SIDE STORAGE
    - localStorage XSS
    - IndexedDB injection
    - WebSQL attacks
    - Cache poisoning
    - Service Worker abuse
    - Cookie tampering
    - SessionStorage risks
    - FileSystem API
    - WebCrypto abuse
    - Blob storage
