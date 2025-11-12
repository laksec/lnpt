# 🔍 IMAP/SMTP INJECTION TESTING CHECKLIST

 ## Comprehensive IMAP/SMTP Injection Testing

### 1 IMAP Command Injection Testing
    - IMAP Protocol Manipulation:
      * Command termination with CRLF: \r\n
      * Command prefix injection in parameters
      * Command chaining with literal sequences
      * Unauthenticated command execution
      * Authenticated state command injection

    - Authentication Bypass Testing:
      * LOGIN command injection: A001 LOGIN "user" "pass"\r\nINJECTED_COMMAND
      * AUTHENTICATE mechanism manipulation
      * Pre-authentication command injection
      * Credential separation attacks
      * Null byte injection in credentials

    - IMAP Command Injection Vectors:
      * SELECT command injection: SELECT "inbox")\r\nINJECTED_COMMAND
      * SEARCH command manipulation: SEARCH FROM "attacker@example.com"\r\nINJECTED
      * FETCH command injection: FETCH 1 BODY[HEADER]\r\nINJECTED_COMMAND
      * STORE command manipulation: STORE 1 +FLAGS (\Deleted)\r\nINJECTED
      * APPEND command injection: APPEND "inbox" {size}\r\nINJECTED_CONTENT

### 2 SMTP Command Injection Testing
    - SMTP Protocol Manipulation:
      * Command injection in MAIL FROM: MAIL FROM:<attacker@example.com>\r\nINJECTED
      * RCPT TO command injection: RCPT TO:<victim@example.com>\r\nINJECTED
      * DATA section command injection
      * EHLO/HELO command manipulation
      * VRFY/EXPN command exploitation

    - SMTP Headers Injection:
      * Subject line command injection
      * From/To header manipulation
      * Message body command injection
      * MIME header exploitation
      * Content-Type boundary manipulation

    - SMTP Session Hijacking:
      * Command pipelining exploitation
      * Session reset attacks
      * Buffer overflow in command parameters
      * TLS negotiation manipulation
      * Authentication context switching

### 3 Email Header Injection Testing
    - From Header Injection:
      * Additional header injection: From: legit@example.com\r\nInjected-Header: value
      * Command injection in display names
      * Email address parameter manipulation
      * Multiple From header exploitation
      * Unicode and encoding attacks

    - Subject Header Injection:
      * CRLF injection in subject lines
      * Additional header injection via subject
      * Command sequence injection
      * Header splitting attacks
      * Multi-line subject exploitation

    - Recipient Header Injection:
      * To/Cc/Bcc header manipulation
      * Multiple recipient injection
      * Recipient enumeration through errors
      * Bcc header exploitation
      * Group address manipulation

### 4 Message Body Injection Testing
    - Email Content Manipulation:
      * MIME boundary injection
      * Content-Type manipulation
      * Character set encoding attacks
      * HTML email script injection
      * Attachment header manipulation

    - Multipart Message Exploitation:
      * Boundary conflict creation
      * Nested multipart injection
      * Mixed/alternative part manipulation
      * Related part reference injection
      * Embedded content exploitation

    - Attachment Injection:
      * Filename parameter injection
      * Content-Disposition manipulation
      * Attachment header command injection
      * Base64 encoding bypass techniques
      * Compressed attachment exploitation

### 5 Web Application Integration Testing
    - Contact Form Injection:
      * Name field command injection
      * Email field protocol manipulation
      * Subject line CRLF injection
      * Message body command injection
      * File attachment field exploitation

    - Email Functionality Testing:
      * Password reset functionality
      * Email verification systems
      * Newsletter subscription
      * Email forwarding features
      * Bulk email systems

    - User Profile Email Testing:
      * Email change functionality
      * Notification preferences
      * Signature injection attacks
      * Auto-responder manipulation
      * Forwarding rule injection

### 6 Advanced Injection Techniques
    - Command Chaining Attacks:
      * Multiple command injection in single field
      * Sequential command execution
      * Conditional command injection
      * Loop and iteration exploitation
      * Batch command execution

    - Protocol Switching Attacks:
      * IMAP to SMTP protocol switching
      * POP3 command injection through IMAP
      * HTTP to mail protocol escalation
      * DNS integration exploitation
      * LDAP through mail command injection

    - Encoding Bypass Techniques:
      * URL encoding variations
      * Base64 encoding manipulation
      * Quoted-printable exploitation
      * UTF-8 encoding attacks
      * Character set translation issues

### 7 Authentication Mechanism Testing
    - IMAP Authentication Injection:
      * PLAIN authentication manipulation
      * LOGIN method injection
      * CRAM-MD5 challenge response attacks
      * OAuth token injection
      * Two-factor authentication bypass

    - SMTP Authentication Testing:
      * AUTH PLAIN command injection
      * LOGIN authentication manipulation
      * CRAM-MD5 in SMTP context
      * STARTTLS command injection
      * Authentication state machine attacks

    - Credential Harvesting:
      * Error message information disclosure
      * Timing attacks for user enumeration
      * Response differential analysis
      * Log file injection for credential capture
      * Side-channel credential leakage

### 8 Server-Specific Testing
    - Microsoft Exchange Testing:
      * EWS (Exchange Web Services) injection
      * Outlook Web Access manipulation
      * ActiveSync command injection
      * MAPI over HTTP exploitation
      * Exchange management shell injection

    - Postfix Server Testing:
      * Postfix configuration injection
      * Master process command manipulation
      * Policy service exploitation
      * Content filter injection
      * Transport mapping attacks

    - Sendmail Testing:
      * Sendmail.cf configuration injection
      * M4 macro preprocessing attacks
      * Mailer definition manipulation
      * Rule set injection
      * Header processing exploitation

    - Exim Server Testing:
      * Exim configuration injection
      * ACL (Access Control List) manipulation
      * Router and transport injection
      * Authenticator exploitation
      * Expansion variable attacks

### 9 Client-Side Email Testing
    - Email Client Testing:
      * Outlook command injection
      * Thunderbird protocol manipulation
      * Apple Mail client exploitation
      * Webmail interface injection
      * Mobile email app testing

    - Browser Email Integration:
      * mailto: protocol manipulation
      * Webmail AJAX request injection
      * Browser email client integration
      * OAuth email integration attacks
      * Cross-protocol request forgery

### 10 Defense Bypass Testing
    - Input Filter Evasion:
      * Case variation in commands
      * Whitespace obfuscation (tabs, spaces)
      * Comment injection in commands
      * Multiple encoding layers
      * Null byte and control character injection

    - WAF Bypass Techniques:
      * Token fragmentation attacks
      * Protocol compliance exploitation
      * Request splitting techniques
      * Chunked encoding manipulation
      * Pipeline request confusion

    - Parser Differential Exploitation:
      * Client vs server parsing differences
      * Multiple parser invocation
      * Character set interpretation differences
      * Line ending normalization issues
      * Quoted string parsing variations

### 11 Business Impact Testing
    - Email Spoofing Testing:
      * From address spoofing
      * Return-Path manipulation
      * Sender Policy Framework (SPF) bypass
      * DomainKeys Identified Mail (DKIM) exploitation
      * Domain-based Message Authentication (DMARC) bypass

    - Information Disclosure:
      * Directory harvesting attacks
      * User enumeration through error messages
      * Server version information leakage
      * Configuration file access
      * Log file extraction

    - Denial of Service Testing:
      * Resource exhaustion through large commands
      * Connection pool exhaustion
      * Memory consumption attacks
      * CPU utilization through complex operations
      * Storage exhaustion through message flooding

#### Testing Tools and Methodologies:
    Manual Testing Tools:
    - Burp Suite with email protocol extensions
    - OWASP ZAP with custom injection scripts
    - Telnet/netcat for raw protocol testing
    - Email client configuration testing
    - Custom Python IMAP/SMTP libraries

    Automated Testing Tools:
    - IMAP/SMTP injection fuzzing frameworks
    - Custom protocol fuzzers
    - Security scanner email plugins
    - Nuclei templates for email injection
    - Metasploit email protocol modules

    Specialized Testing Tools:
    - Swaks (SMTP transaction testing)
    - IMAPtest for IMAP protocol testing
    - Email security assessment frameworks
    - Protocol analyzer tools (Wireshark)
    - Mail server security scanners

    Test Case Examples:
    - IMAP: A001 LOGIN "user" "pass"\r\nINJECTED_COMMAND
    - SMTP: MAIL FROM:<attacker@example.com>\r\nINJECTED_COMMAND
    - Header: From: legit@example.com\r\nInjected: value
    - Body: Content-Type: text/plain\r\nInjected-Header: value

    Testing Methodology:
    1. Identify email protocol interaction points
    2. Test basic command injection vectors
    3. Attempt authentication bypass techniques
    4. Test header and body injection
    5. Verify server-specific vulnerabilities
    6. Test defense bypass methods
    7. Assess business impact and data exposure
    8. Document exploitation paths and remediation