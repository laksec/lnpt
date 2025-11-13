# 🔍 HTTP VERB TAMPERING TESTING CHECKLIST

 ## Comprehensive HTTP Verb Tampering Testing

### 1 Standard HTTP Method Testing
    - Core HTTP Method Manipulation:
      * GET method with sensitive operations
      * POST method with parameter tampering
      * PUT method for unauthorized file creation
      * DELETE method for resource removal
      * HEAD method for information disclosure
      * OPTIONS method for endpoint enumeration
      * TRACE method for request reflection
      * CONNECT method for proxy tunneling

    - Extended HTTP Method Testing:
      * PATCH method for partial resource modification
      * COPY method for resource duplication
      * MOVE method for resource relocation
      * LOCK method for resource locking
      * UNLOCK method for resource unlocking
      * PROPFIND method for property retrieval
      * PROPPATCH method for property modification
      * MKCOL method for collection creation

### 2 HTTP Method Override Techniques
    - Header-Based Method Override:
      * X-HTTP-Method-Override header manipulation
      * X-HTTP-Method header injection
      * X-Method-Override header exploitation
      * X-REST-METHOD header testing
      * Custom method override header discovery

    - Parameter-Based Method Override:
      * _method parameter in query strings
      * _method parameter in POST data
      * method parameter in REST APIs
      * _verb parameter manipulation
      * _type parameter testing

    - Alternative Override Mechanisms:
      * Content-Type header method specification
      * Custom request header injection
      * URL fragment method specification
      * Cookie-based method override
      * XML body method declaration

### 3 Authentication Bypass Testing
    - Method-Specific Authentication Testing:
      * GET requests to POST-protected endpoints
      * HEAD requests to authenticated resources
      * OPTIONS bypassing authentication checks
      * TRACE method for credential reflection
      * Unauthenticated PUT/DELETE operations

    - Authorization Circumvention:
      * Role-based access control via different methods
      * Privilege escalation through method alteration
      * Administrative function access via alternative verbs
      * User permission testing across all HTTP methods
      * API key and token validation across methods

### 4 Web Server Specific Testing
    - Apache HTTP Server Testing:
      * htaccess method restriction bypass
      * mod_rewrite rule manipulation
      * WebDAV extension exploitation
      * LimitExcept directive testing
      * mod_security method filtering evasion

    - Nginx Server Testing:
      * limit_except directive bypass
      * Rewrite rule method condition evasion
      * Proxy method forwarding manipulation
      * WebDAV module configuration testing
      * OpenResty method handling

    - IIS Server Testing:
      * WebDAV extension method testing
      * Handler mapping method restrictions
      * Request filtering method rules
      * ASP.NET verb handling
      * ISAPI filter method processing

### 5 Application Framework Testing
    - Java Framework Testing:
      * Spring Security method restrictions
      * JEE security constraint bypass
      * Struts method validation
      * JAX-RS method filtering
      * Servlet filter method checking

    - NET Framework Testing:
      * Web.config verb filtering
      * MVC action method attributes
      * Web API method selection
      * Handler verb restrictions
      * Module method validation

    - Python Framework Testing:
      * Django decorator method restrictions
      * Flask route method conditions
      * Pyramid view method predicates
      * FastAPI operation method validation
      * WSGI middleware method handling

    - Node.js Framework Testing:
      * Express route method validation
      * Koa router method restrictions
      * Hapi route configuration
      * Restify method handling
      * Middleware method filtering

### 6 Advanced Evasion Techniques
    - Case Manipulation:
      * Lowercase method names (get, post, put)
      * Uppercase method names (GET, POST, PUT)
      * Mixed case method names (GeT, PoSt, PuT)
      * Unicode case variations

    - Whitespace and Special Character Injection:
      * Leading/trailing whitespace in method names
      * Tab character injection in methods
      * Newline injection in method declarations
      * Null byte injection in method strings
      * Unicode space character variations

    - Protocol-Level Manipulation:
      * HTTP/1.0 vs HTTP/1.1 method handling
      * HTTP/2 method frame manipulation
      * Chunked transfer encoding with method tampering
      * Keep-alive connection method mixing
      * Pipeline request method manipulation

### 7 API and Web Service Testing
    - REST API Method Testing:
      * Resource collection method manipulation
      * Individual resource method testing
      * Nested resource method access
      * Bulk operation method tampering
      * Custom action method exploitation

    - SOAP Web Service Testing:
      * SOAPAction header manipulation
      * HTTP method for SOAP endpoints
      * WS-Addressing method implications
      * SOAP body with alternative methods
      * WSDL-defined operation access

    - GraphQL Testing:
      * HTTP method for GraphQL endpoints
      * GET requests with query parameters
      * POST method with operation tampering
      * Mutation operation via alternative methods
      * Subscription method manipulation

### 8 Security Control Bypass Testing
    - Web Application Firewall (WAF) Evasion:
      * Method name obfuscation techniques
      * Encoding variations in method names
      * Multiple method declaration conflicts
      * Request splitting with method tampering
      * Protocol violation with method manipulation

    - Input Validation Bypass:
      * Method parameter type confusion
      * Buffer overflow in method processing
      * Integer overflow in method handling
      * Regex filter evasion for method names
      * Parser differential exploitation

    - Logging and Monitoring Evasion:
      * Method names avoiding detection
      * Legitimate method for malicious actions
      * Audit log method manipulation
      * SIEM correlation rule evasion
      * Forensic investigation obstacles

#### Testing Tools and Methodologies:
    Manual Testing Tools:
    - Burp Suite Repeater with method manipulation
    - OWASP ZAP manual request editing
    - Postman with custom method testing
    - curl with extended HTTP methods
    - nc (netcat) for raw HTTP requests

    Automated Testing Tools:
    - Custom scripts for method fuzzing
    - Nuclei templates for verb tampering
    - ffuf for method enumeration
    - Metasploit auxiliary modules
    - Custom wordlists for HTTP methods

    Test Case Examples:
    - TRACE /admin HTTP/1.1
    - GET /delete_user?id=1 HTTP/1.1
    - PUT /upload/shell.jsp HTTP/1.1
    - OPTIONS /restricted/ HTTP/1.1
    - CUSTOM /bypass HTTP/1.1