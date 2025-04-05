# ULTIMATE COMMAND INJECTION TESTING CHECKLIST (v1.0)

### Comprehensive Methodology for Command Injection Vulnerability Assessment

### 🌐 RECONNAISSANCE PHASE

    - Identify all system command execution points
    - Map user inputs that get processed by system commands
    - Locate file operations (read/write/delete)
    - Find process execution functions (system(), exec(), etc.)
    - Document wrapper scripts and scheduled tasks
    - Identify administrative interfaces with command execution
    - Locate API endpoints that trigger system commands
    - Find places where user input is concatenated into commands
    - Identify file upload handlers with post-processing
    - Discover places where filenames are used in commands

### 🔍 BASIC INJECTION VECTORS

#### Command Separators

    - Test semicolon (;) command chaining
    - Verify pipe (|) character
    - Check double pipe (||) OR operator
    - Test ampersand (&) background operator
    - Verify double ampersand (&&) AND operator
    - Check newline (\n) character
    - Test backtick (`) command substitution
    - Verify dollar($()) command substitution
    - Check caret (^) in Windows
    - Test redirection operators (>, >>, <)

#### Common Dangerous Commands

    - Test arbitrary command execution (whoami, id)
    - Verify file system access (cat, dir, ls)
    - Check network commands (ping, curl, wget)
    - Test process listing (ps, tasklist)
    - Verify system info commands (uname, ver)
    - Check environment variables (env, set)
    - Test write operations (echo, touch)
    - Verify privilege escalation attempts (sudo, su)
    - Check reverse shell attempts
    - Test file download capabilities

### 🛠️ INJECTION TECHNIQUES

#### Obfuscation Methods

    - Test case variation (WhOaMi)
    - Verify whitespace padding
    - Check tab characters instead of spaces
    - Test wildcard characters
    - Verify variable expansion
    - Check encoded commands (base64, hex)
    - Test quoted commands ("w"h"o"a"m"i)
    - Verify escaped characters
    - Check environment variable injection
    - Test nested command substitution

#### Platform-Specific Tests

    - Test Windows-only commands (dir, copy)
    - Verify Unix-only commands (ls, cat)
    - Check PowerShell injection
    - Test bash/sh specific syntax
    - Verify Windows alternative separators
    - Check command line switches
    - Test batch file special characters
    - Verify shell special variables
    - Check interpreter injection (perl, python)
    - Test database command execution features

### ⚙️ CONTEXT-AWARE TESTING

#### Web Application Vectors

    - Test form inputs that affect filesystem
    - Verify filename parameters
    - Check file upload fields
    - Test user registration fields
    - Verify search functionality
    - Check admin interface inputs
    - Test configuration parameters
    - Verify import/export features
    - Check template rendering inputs
    - Test webhook URLs

#### API/Script Vectors

    - Test API endpoints executing system commands
    - Verify web service parameters
    - Check scheduled task parameters
    - Test cron job inputs
    - Verify wrapper script arguments
    - Check build system parameters
    - Test deployment script inputs
    - Verify CI/CD pipeline parameters
    - Check container execution parameters
    - Test serverless function triggers

### 🛡️ DEFENSE BYPASS TECHNIQUES

#### Filter Evasion

    - Test mixed case bypass
    - Verify string concatenation
    - Check partial command matching
    - Test alternative command paths
    - Verify Unicode normalization
    - Check hex/octal encoding
    - Test regex bypass techniques
    - Verify time-based delays
    - Check out-of-band data exfiltration
    - Test alternative protocol usage

#### Sandbox Escape

    - Test command chaining to break out
    - Verify environment variable abuse
    - Check file descriptor manipulation
    - Test library path injection
    - Verify symlink attacks
    - Check process injection
    - Test container escape techniques
    - Verify privilege escalation vectors
    - Check kernel exploit delivery
    - Test persistence mechanisms

### 📊 IMPACT ANALYSIS

#### System Access

    - Verify user context access
    - Check filesystem read access
    - Test filesystem write access
    - Verify network access
    - Check process access
    - Test privilege escalation
    - Verify persistence mechanisms
    - Check sensitive data access
    - Test remote connectivity
    -  Verify system modification

#### Business Impact

    - Test data exfiltration
    - Verify system disruption
    - Check ransomware potential
    - Test compliance violation
    - Verify reputation damage
    - Check financial impact
    - Test operational disruption
    - Verify legal consequences
    - Check supply chain contamination
    - Test lateral movement potential

### 🧠 MITIGATION STRATEGIES

#### Prevention

    - Implement input validation
    - Use allowlists instead of blocklists
    - Apply proper escaping
    - Implement parameterized commands
    - Use built-in language functions instead of commands
    - Apply least privilege principles
    - Implement command signing
    - Use restricted shells where possible
    - Apply process hardening
    - Implement system call filtering

#### Detection

    - Monitor command execution
    - Implement argument logging
    - Detect anomalous command patterns
    - Monitor process creation
    - Implement file integrity monitoring
    - Detect unusual network connections
    - Monitor privilege escalation
    - Implement user behavior analytics
    - Detect obfuscated commands
    - Monitor for suspicious child processes

### 📝 REPORTING

    - Document vulnerable endpoints
    - Record successful payloads
    - Note execution context
    - Document system access level
    - Report data accessed
    - Note detection bypasses
    - Document potential pivots
    - Record business impact
    - Note remediation difficulty
    - Provide mitigation recommendations
