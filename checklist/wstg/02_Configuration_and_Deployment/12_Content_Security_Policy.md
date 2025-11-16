
# 🔐 CONFIGURATION AND DEPLOYMENT MANAGEMENT | TEST CONTENT SECURITY POLICY

## Comprehensive Content Security Policy (CSP) Security Assessment

### 1 CSP Header Discovery & Analysis
- **CSP Header Enumeration:**
  - Content-Security-Policy header presence testing
  - Content-Security-Policy-Report-Only header analysis
  - Multiple CSP header collision testing
  - Meta tag CSP implementation analysis
  - CSP header syntax and format validation
  - HTTP/HTTPS CSP header consistency testing
  - Subdomain CSP policy analysis
  - API endpoint CSP implementation testing

- **CSP Delivery Mechanism Analysis:**
  - HTTP header vs meta tag implementation testing
  - CSP header order and precedence analysis
  - Multiple policy enforcement testing
  - Browser CSP support level testing
  - Mobile browser CSP compatibility testing
  - CSP with HTTP/2 and HTTP/3 testing
  - CDN CSP header propagation testing
  - Load balancer CSP implementation testing

### 2 CSP Directive Security Testing
- **Source Directive Analysis:**
  - `default-src` directive security assessment
  - `script-src` directive source validation testing
  - `style-src` directive source validation testing
  - `img-src` directive source validation testing
  - `connect-src` directive source validation testing
  - `font-src` directive source validation testing
  - `object-src` directive source validation testing
  - `media-src` directive source validation testing

- **Frame & Navigation Directive Testing:**
  - `frame-src` directive security testing
  - `child-src` directive validation testing
  - `frame-ancestors` directive X-Frame-Options compatibility testing
  - `form-action` directive form submission testing
  - `base-uri` directive base URL restriction testing
  - `navigate-to` directive navigation control testing
  - `sandbox` directive isolation testing
  - `plugin-types` directive MIME type testing

### 3 CSP Source Validation Testing
- **Source List Security Assessment:**
  - Wildcard source (`*`) security impact testing
  - `'self'` source scope validation testing
  - `'none'` source restriction effectiveness testing
  - Scheme source (`https:`, `data:`, `blob:`) testing
  - Host source with and without port testing
  - Path-restricted source testing
  - Nonce and hash source implementation testing
  - Unsafe directive evaluation testing

- **Unsafe Directive Testing:**
  - `'unsafe-inline'` directive security impact testing
  - `'unsafe-eval'` directive JavaScript evaluation testing
  - `'unsafe-hashes'` directive hash bypass testing
  - `'unsafe-allow-redirects'` directive testing
  - `data:` URL scheme security testing
  - `blob:` URL scheme security testing
  - `filesystem:` URL scheme testing
  - `mediastream:` URL scheme testing

### 4 Nonce & Hash Implementation Testing
- **Nonce Security Testing:**
  - Nonce generation randomness and entropy testing
  - Nonce reuse and predictability testing
  - Nonce length and complexity validation
  - Nonce lifetime and rotation testing
  - Nonce delivery mechanism security testing
  - Nonce with server-side rendering testing
  - Nonce in cached responses testing
  - Nonce brute force resistance testing

- **Hash Source Testing:**
  - Hash algorithm support testing (sha256, sha384, sha512)
  - Hash calculation accuracy testing
  - Hash collision resistance testing
  - Dynamic content hash generation testing
  - Hash with external scripts testing
  - Hash with inline event handlers testing
  - Hash with style attributes testing
  - Hash maintenance and update testing

### 5 CSP Bypass & Evasion Testing
- **Script Injection Bypass Testing:**
  - JSONP endpoint CSP bypass testing
  - AngularJS template injection CSP bypass testing
  - Flash-based CSP bypass testing
  - SVG file script execution testing
  - CSS expression injection testing
  - Data URI scheme bypass testing
  - Blob URL scheme bypass testing
  - Dynamic code evaluation bypass testing

- **Policy Injection Testing:**
  - Header injection in CSP directives testing
  - Multiple header policy confusion testing
  - Policy injection via URL parameters testing
  - Meta tag injection in CSP testing
  - Report-URI header injection testing
  - Directive order manipulation testing
  - Browser parser differential testing
  - Legacy browser CSP support testing

### 6 CSP Reporting & Monitoring Testing
- **Report Delivery Testing:**
  - `report-uri` directive functionality testing
  - `report-to` directive endpoint testing
  - Report format and content validation
  - Report delivery reliability testing
  - Report authentication and authorization testing
  - Report rate limiting testing
  - Report integrity verification testing
  - Report endpoint availability testing

- **Monitoring Effectiveness Testing:**
  - Violation report analysis testing
  - Report aggregation and correlation testing
  - Real-time alerting capability testing
  - Report storage and retention testing
  - False positive identification testing
  - Policy adjustment based on reports testing
  - Compliance reporting testing
  - Security incident correlation testing

### 7 Advanced CSP Feature Testing
- **Trusted Types Implementation Testing:**
  - Trusted Types policy creation testing
  - Trusted Types enforcement testing
  - Trusted Types with DOM XSS prevention testing
  - Trusted Types policy configuration testing
  - Trusted Types with third-party libraries testing
  - Trusted Types browser support testing
  - Trusted Types policy violation testing
  - Trusted Types with framework testing

- **Strict Dynamic & Nonce Testing:**
  - `'strict-dynamic'` directive effectiveness testing
  - Strict dynamic with nonce propagation testing
  - Strict dynamic with hash testing
  - Strict dynamic browser compatibility testing
  - Strict dynamic with legacy browser testing
  - Strict dynamic policy maintenance testing
  - Strict dynamic with CDN resources testing
  - Strict dynamic with framework testing

### 8 Framework-Specific CSP Testing
- **JavaScript Framework Testing:**
  - React application CSP implementation testing
  - Angular CSP configuration testing
  - Vue.js CSP security testing
  - jQuery CSP compatibility testing
  - Web Components CSP testing
  - Single Page Application (SPA) CSP testing
  - Progressive Web App (PWA) CSP testing
  - Server-Side Rendering (SSR) CSP testing

- **CMS & Platform Testing:**
  - WordPress CSP implementation testing
  - Drupal CSP configuration testing
  - Joomla CSP security testing
  - Shopify CSP implementation testing
  - Magento CSP configuration testing
  - Custom CMS CSP testing
  - E-commerce platform CSP testing
  - Blog platform CSP testing

### 9 Automated CSP Testing Framework
```yaml
CSP Security Assessment Pipeline:
  Discovery Phase:
    - CSP header detection and enumeration
    - CSP directive analysis and validation
    - Source list security assessment
    - Nonce and hash implementation testing
    - Reporting mechanism analysis
    - Browser compatibility testing
    - Framework-specific CSP testing
    - Legacy system CSP analysis

  Analysis Phase:
    - CSP policy effectiveness evaluation
    - Security control gap analysis
    - Bypass vulnerability identification
    - Risk exposure assessment
    - Compliance requirement validation
    - Business impact analysis
    - Implementation maturity assessment
    - Security control effectiveness scoring

  Testing Phase:
    - CSP bypass technique testing
    - Script injection evasion testing
    - Policy injection testing
    - Reporting mechanism testing
    - Browser compatibility testing
    - Framework-specific testing
    - Advanced feature testing
    - Security control evasion testing

  Validation Phase:
    - CSP policy effectiveness verification
    - Security control implementation validation
    - Remediation effectiveness testing
    - Monitoring system validation
    - Documentation accuracy verification
    - Management approval and sign-off
    - Continuous monitoring setup
    - Automated alerting configuration
```

### 10 CSP Testing Tools & Commands
```bash
# CSP Header Analysis
curl -I https://target.com | grep -i content-security-policy
nmap --script http-security-headers target.com
testssl.sh --headers target.com
python3 csp_analyzer.py -u https://target.com -v

# Comprehensive CSP Testing
csp-evaluator --url https://target.com --output csp_report.json
securityheaders.com --scan target.com
observatory.mozilla.org --analyze target.com
python3 csp_scanner.py -d target.com -o detailed_report.html

# CSP Bypass Testing
csp-bypass --url https://target.com --techniques all
xsstrike --csp --url https://target.com
csp-tester --policy "default-src 'self'" --test-bypasses

# Reporting Testing
csp-report-tester --report-uri https://target.com/csp-report --test-payload
report-analyzer --file csp_reports.log --output analysis.json

# Automated Scanning
nuclei -t csp/ -u https://target.com -o nuclei_csp_results.txt
burp-suite --csp-audit --target https://target.com
zap-cli --csp-scan --url https://target.com

# Continuous Monitoring
monitor-csp --domain target.com --interval 3600 --webhook https://hooks.slack.com/XXX
watch-csp --config policies.yaml --alert-on-change
automated-csp-scanner --schedule daily --output-dir  /reports/

# Framework Testing
react-csp-audit --app-dir  /src --output react_csp_report.json
angular-csp-check --project  /angular-app --verbose
wordpress-csp-scanner --url https://target.com --plugins --themes
```

### 11 Advanced CSP Testing Implementation
```python
# Comprehensive Content Security Policy Security Testing Tool
import requests
import re
import json
import hashlib
import base64
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import threading
from datetime import datetime

class CSPTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; CSPTester/1.0)'
        })
        self.test_results = {
            'csp_headers': {},
            'directive_analysis': {},
            'security_assessment': {},
            'vulnerabilities': {},
            'recommendations': {}
        }

    def comprehensive_csp_testing(self):
        """Perform comprehensive CSP security testing"""
        print(f"[+] Starting CSP security testing for {self.target_url}")
        
        # Execute all CSP testing methods
        self.analyze_csp_headers()
        self.test_directive_security()
        self.analyze_source_lists()
        self.test_nonce_implementation()
        self.test_csp_bypasses()
        self.test_reporting_mechanisms()
        
        return {
            'test_results': self.test_results,
            'security_assessment': self.perform_security_assessment(),
            'risk_analysis': self.perform_risk_analysis(),
            'remediation_recommendations': self.generate_recommendations()
        }

    def analyze_csp_headers(self):
        """Analyze CSP headers and configurations"""
        print("[+] Analyzing CSP headers...")
        
        csp_analysis = {}
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            # Extract CSP headers
            csp_headers = {
                'Content-Security-Policy': headers.get('Content-Security-Policy', ''),
                'Content-Security-Policy-Report-Only': headers.get('Content-Security-Policy-Report-Only', ''),
                'X-Content-Security-Policy': headers.get('X-Content-Security-Policy', ''),  # Legacy Firefox
                'X-WebKit-CSP': headers.get('X-WebKit-CSP', '')  # Legacy WebKit
            }
            
            # Analyze each CSP header
            for header_name, header_value in csp_headers.items():
                if header_value:
                    analysis = self.analyze_single_csp_header(header_name, header_value)
                    csp_analysis[header_name] = analysis
            
            # Check for meta tag CSP
            meta_csp = self.extract_meta_csp(response.text)
            if meta_csp:
                csp_analysis['Meta-Tag-CSP'] = self.analyze_single_csp_header('Meta-Tag-CSP', meta_csp)
            
            self.test_results['csp_headers'] = csp_analysis
            
        except requests.RequestException as e:
            print(f"[-] Error analyzing CSP headers: {e}")

    def analyze_single_csp_header(self, header_name, header_value):
        """Analyze a single CSP header"""
        analysis = {
            'raw_header': header_value,
            'directives': {},
            'syntax_validation': {},
            'security_indicators': {},
            'risk_level': 'low'
        }
        
        # Parse directives
        directives = self.parse_csp_directives(header_value)
        analysis['directives'] = directives
        
        # Validate syntax
        analysis['syntax_validation'] = self.validate_csp_syntax(header_value)
        
        # Security analysis
        analysis['security_indicators'] = self.analyze_csp_security(directives)
        
        # Risk assessment
        analysis['risk_level'] = self.assess_csp_risk(directives)
        
        return analysis

    def parse_csp_directives(self, csp_header):
        """Parse CSP directives into structured format"""
        directives = {}
        
        # Split by semicolon and process each directive
        directive_parts = csp_header.split(';')
        
        for part in directive_parts:
            part = part.strip()
            if not part:
                continue
            
            # Split directive name and value
            if ' ' in part:
                directive_name, directive_value = part.split(' ', 1)
                directives[directive_name.strip()] = directive_value.strip()
            else:
                directives[part] = ''
        
        return directives

    def validate_csp_syntax(self, csp_header):
        """Validate CSP header syntax"""
        validation = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        # Check for common syntax errors
        if ';;' in csp_header:
            validation['valid'] = False
            validation['errors'].append('Multiple consecutive semicolons detected')
        
        if csp_header.startswith(';') or csp_header.endswith(';'):
            validation['warnings'].append('CSP header starts or ends with semicolon')
        
        # Check directive format
        directives = self.parse_csp_directives(csp_header)
        for directive, value in directives.items():
            if not directive:
                validation['errors'].append('Empty directive name')
            
            # Check for valid directive names
            valid_directives = [
                'default-src', 'script-src', 'style-src', 'img-src', 'connect-src',
                'font-src', 'object-src', 'media-src', 'frame-src', 'child-src',
                'form-action', 'base-uri', 'report-uri', 'report-to', 'sandbox',
                'frame-ancestors', 'navigate-to', 'worker-src', 'manifest-src',
                'prefetch-src', 'plugin-types', 'require-trusted-types-for',
                'trusted-types', 'upgrade-insecure-requests', 'block-all-mixed-content'
            ]
            
            if directive not in valid_directives and not directive.startswith('sandbox'):
                validation['warnings'].append(f'Unknown directive: {directive}')
        
        return validation

    def analyze_csp_security(self, directives):
        """Analyze CSP security indicators"""
        security = {
            'unsafe_directives': [],
            'wildcard_sources': [],
            'open_sources': [],
            'missing_directives': [],
            'weak_directives': []
        }
        
        # Check for unsafe directives
        unsafe_patterns = ["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "data:", "blob:"]
        
        for directive, value in directives.items():
            for pattern in unsafe_patterns:
                if pattern in value:
                    security['unsafe_directives'].append({
                        'directive': directive,
                        'value': value,
                        'pattern': pattern
                    })
            
            # Check for wildcard sources
            if '*' in value and "'none'" not in value:
                security['wildcard_sources'].append({
                    'directive': directive,
                    'value': value
                })
        
        # Check for missing critical directives
        critical_directives = ['script-src', 'object-src', 'base-uri']
        for critical in critical_directives:
            if critical not in directives:
                security['missing_directives'].append(critical)
        
        # Check for weak directives
        if directives.get('script-src') and "'unsafe-inline'" in directives['script-src']:
            security['weak_directives'].append('script-src allows unsafe-inline')
        
        if directives.get('object-src') and "'none'" not in directives['object-src']:
            security['weak_directives'].append('object-src not set to none')
        
        return security

    def extract_meta_csp(self, html_content):
        """Extract CSP from meta tags"""
        meta_pattern = r'<meta[^>]*http-equiv=["\']Content-Security-Policy["\'][^>]*content=["\']([^"\']+)["\']'
        matches = re.findall(meta_pattern, html_content, re.IGNORECASE)
        return matches[0] if matches else None

    def test_directive_security(self):
        """Test CSP directive security effectiveness"""
        print("[+] Testing CSP directive security...")
        
        directive_tests = {}
        csp_headers = self.test_results['csp_headers']
        
        for header_name, header_analysis in csp_headers.items():
            directives = header_analysis.get('directives', {})
            tests = {}
            
            # Test each directive
            for directive, value in directives.items():
                if directive.endswith('-src'):
                    tests[directive] = self.test_source_directive(directive, value)
                elif directive == 'frame-ancestors':
                    tests[directive] = self.test_frame_ancestors_directive(value)
                elif directive == 'form-action':
                    tests[directive] = self.test_form_action_directive(value)
                elif directive == 'base-uri':
                    tests[directive] = self.test_base_uri_directive(value)
            
            directive_tests[header_name] = tests
        
        self.test_results['directive_tests'] = directive_tests

    def test_source_directive(self, directive, value):
        """Test a source directive for security effectiveness"""
        test_results = {
            'wildcard_allowed': '*' in value,
            'unsafe_inline_allowed': "'unsafe-inline'" in value,
            'unsafe_eval_allowed': "'unsafe-eval'" in value,
            'data_scheme_allowed': 'data:' in value,
            'blob_scheme_allowed': 'blob:' in value,
            'self_allowed': "'self'" in value,
            'none_enforced': "'none'" in value,
            'has_nonce': 'nonce-' in value,
            'has_hashes': 'sha256-' in value or 'sha384-' in value or 'sha512-' in value
        }
        
        # Risk assessment
        risk_factors = []
        if test_results['wildcard_allowed']:
            risk_factors.append('WILDCARD_SOURCE')
        if test_results['unsafe_inline_allowed']:
            risk_factors.append('UNSAFE_INLINE')
        if test_results['unsafe_eval_allowed']:
            risk_factors.append('UNSAFE_EVAL')
        if test_results['data_scheme_allowed']:
            risk_factors.append('DATA_SCHEME')
        
        test_results['risk_factors'] = risk_factors
        test_results['risk_level'] = 'high' if risk_factors else 'low'
        
        return test_results

    def test_csp_bypasses(self):
        """Test CSP bypass techniques"""
        print("[+] Testing CSP bypass techniques...")
        
        bypass_tests = {}
        csp_headers = self.test_results['csp_headers']
        
        for header_name, header_analysis in csp_headers.items():
            directives = header_analysis.get('directives', {})
            bypasses = self.test_bypass_techniques(directives)
            bypass_tests[header_name] = bypasses
        
        self.test_results['bypass_tests'] = bypass_tests

    def test_bypass_techniques(self, directives):
        """Test various CSP bypass techniques"""
        bypasses = {
            'jsonp_endpoints': self.test_jsonp_bypass(directives),
            'angular_injection': self.test_angular_bypass(directives),
            'data_uri_injection': self.test_data_uri_bypass(directives),
            'script_gadgets': self.test_script_gadgets(directives),
            'dynamic_eval': self.test_dynamic_eval_bypass(directives),
            'css_injection': self.test_css_injection(directives),
            'flash_bypass': self.test_flash_bypass(directives),
            'policy_injection': self.test_policy_injection()
        }
        
        return bypasses

    def test_jsonp_bypass(self, directives):
        """Test JSONP endpoint CSP bypass"""
        test_results = {
            'vulnerable': False,
            'techniques': [],
            'risk_level': 'medium'
        }
        
        script_src = directives.get('script-src', '')
        
        # Check if JSONP endpoints are allowed
        jsonp_patterns = ['jsonp', 'callback', 'cb']
        for pattern in jsonp_patterns:
            if pattern in script_src:
                test_results['vulnerable'] = True
                test_results['techniques'].append(f'JSONP endpoint pattern detected: {pattern}')
        
        return test_results

    def test_angular_injection(self, directives):
        """Test AngularJS template injection bypass"""
        test_results = {
            'vulnerable': False,
            'techniques': [],
            'risk_level': 'high'
        }
        
        script_src = directives.get('script-src', '')
        style_src = directives.get('style-src', '')
        
        # Check for AngularJS CSP bypass conditions
        if "'unsafe-eval'" not in script_src:
            # AngularJS requires unsafe-eval for full functionality
            test_results['vulnerable'] = True
            test_results['techniques'].append('AngularJS may be limited without unsafe-eval')
        
        # Check for style injection vectors
        if "'unsafe-inline'" in style_src or 'data:' in style_src:
            test_results['vulnerable'] = True
            test_results['techniques'].append('Style injection possible for AngularJS bypass')
        
        return test_results

    def test_reporting_mechanisms(self):
        """Test CSP reporting mechanisms"""
        print("[+] Testing CSP reporting mechanisms...")
        
        reporting_tests = {}
        csp_headers = self.test_results['csp_headers']
        
        for header_name, header_analysis in csp_headers.items():
            directives = header_analysis.get('directives', {})
            reporting = self.test_reporting_functionality(directives)
            reporting_tests[header_name] = reporting
        
        self.test_results['reporting_tests'] = reporting_tests

    def test_reporting_functionality(self, directives):
        """Test CSP reporting functionality"""
        reporting = {
            'report_uri_present': 'report-uri' in directives,
            'report_to_present': 'report-to' in directives,
            'report_endpoints': [],
            'functionality_tested': False
        }
        
        # Extract report endpoints
        if 'report-uri' in directives:
            endpoints = directives['report-uri'].split(' ')
            reporting['report_endpoints'].extend(endpoints)
        
        # Test report delivery
        if reporting['report_endpoints']:
            reporting['functionality_tested'] = self.test_report_delivery(reporting['report_endpoints'])
        
        return reporting

    def test_report_delivery(self, endpoints):
        """Test CSP report delivery to endpoints"""
        for endpoint in endpoints:
            try:
                # Create a test violation report
                report_payload = {
                    'csp-report': {
                        'document-uri': self.target_url,
                        'referrer': '',
                        'blocked-uri': 'http://evil.com/malicious.js',
                        'violated-directive': 'script-src',
                        'effective-directive': 'script-src',
                        'original-policy': 'script-src self',
                        'disposition': 'enforce',
                        'status-code': 200,
                        'script-sample': 'alert(1)',
                        'line-number': 1,
                        'column-number': 1,
                        'source-file': self.target_url
                    }
                }
                
                # Send test report
                if endpoint.startswith('http'):
                    report_url = endpoint
                else:
                    report_url = urljoin(self.target_url, endpoint)
                
                response = self.session.post(
                    report_url,
                    json=report_payload,
                    headers={'Content-Type': 'application/csp-report'},
                    timeout=5
                )
                
                if response.status_code in [200, 202, 204]:
                    return True
                
            except requests.RequestException:
                continue
        
        return False

    def perform_security_assessment(self):
        """Perform comprehensive security assessment"""
        print("[+] Performing security assessment...")
        
        assessment = {
            'overall_risk_level': self.calculate_overall_risk(),
            'csp_effectiveness_score': self.calculate_effectiveness_score(),
            'coverage_assessment': self.assess_coverage(),
            'compliance_status': self.assess_compliance_status(),
            'security_recommendations': self.generate_security_recommendations()
        }
        
        return assessment

    def calculate_overall_risk(self):
        """Calculate overall risk level based on findings"""
        risk_scores = []
        
        # Analyze CSP headers
        for header_name, header_analysis in self.test_results['csp_headers'].items():
            risk_level = header_analysis.get('risk_level', 'low')
            risk_scores.append(self.risk_level_to_score(risk_level))
        
        # Analyze bypass tests
        bypass_tests = self.test_results.get('bypass_tests', {})
        for header_name, bypasses in bypass_tests.items():
            for bypass_name, bypass_result in bypasses.items():
                if bypass_result.get('vulnerable'):
                    risk_scores.append(self.risk_level_to_score(bypass_result.get('risk_level', 'medium')))
        
        if not risk_scores:
            return 'low'
        
        avg_score = sum(risk_scores) / len(risk_scores)
        
        if avg_score >= 4:
            return 'critical'
        elif avg_score >= 3:
            return 'high'
        elif avg_score >= 2:
            return 'medium'
        else:
            return 'low'

    def risk_level_to_score(self, risk_level):
        """Convert risk level to numerical score"""
        risk_scores = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
        return risk_scores.get(risk_level, 1)

    def calculate_effectiveness_score(self):
        """Calculate CSP effectiveness score (0-100)"""
        score = 100
        penalty = 0
        
        # Penalize based on security issues
        for header_name, header_analysis in self.test_results['csp_headers'].items():
            security_indicators = header_analysis.get('security_indicators', {})
            
            # Unsafe directives
            penalty += len(security_indicators.get('unsafe_directives', [])) * 10
            
            # Wildcard sources
            penalty += len(security_indicators.get('wildcard_sources', [])) * 15
            
            # Missing directives
            penalty += len(security_indicators.get('missing_directives', [])) * 5
        
        # Penalize for bypass vulnerabilities
        bypass_tests = self.test_results.get('bypass_tests', {})
        for header_name, bypasses in bypass_tests.items():
            for bypass_name, bypass_result in bypasses.items():
                if bypass_result.get('vulnerable'):
                    penalty += 20
        
        return max(0, score - penalty)

    def perform_risk_analysis(self):
        """Perform comprehensive risk analysis"""
        risk_analysis = {
            'critical_risks': [],
            'high_risks': [],
            'medium_risks': [],
            'low_risks': []
        }
        
        # Analyze CSP headers for risks
        for header_name, header_analysis in self.test_results['csp_headers'].items():
            security_indicators = header_analysis.get('security_indicators', {})
            
            # Critical risks
            for unsafe in security_indicators.get('unsafe_directives', []):
                if "'unsafe-inline'" in unsafe['pattern'] and 'script-src' in unsafe['directive']:
                    risk_analysis['critical_risks'].append({
                        'risk': 'UNSAFE_INLINE_SCRIPT',
                        'description': f"script-src allows unsafe-inline in {header_name}",
                        'impact': 'Allows inline script execution, bypassing CSP protection',
                        'remediation': "Remove 'unsafe-inline' and use nonces or hashes"
                    })
            
            # High risks
            for wildcard in security_indicators.get('wildcard_sources', []):
                risk_analysis['high_risks'].append({
                    'risk': 'WILDCARD_SOURCE',
                    'description': f"{wildcard['directive']} allows wildcard source in {header_name}",
                    'impact': 'Allows loading resources from any domain',
                    'remediation': 'Replace wildcard with specific allowed sources'
                })
        
        # Analyze bypass vulnerabilities
        bypass_tests = self.test_results.get('bypass_tests', {})
        for header_name, bypasses in bypass_tests.items():
            for bypass_name, bypass_result in bypasses.items():
                if bypass_result.get('vulnerable'):
                    risk_level = bypass_result.get('risk_level', 'medium')
                    risk_analysis[f'{risk_level}_risks'].append({
                        'risk': f'CSP_BYPASS_{bypass_name.upper()}',
                        'description': f"CSP bypass possible via {bypass_name} in {header_name}",
                        'impact': 'Allows bypassing CSP protection mechanisms',
                        'remediation': 'Strengthen CSP policy and test for bypasses'
                    })
        
        return risk_analysis

    def generate_recommendations(self):
        """Generate comprehensive security recommendations"""
        recommendations = {
            'immediate_actions': [],
            'short_term_improvements': [],
            'long_term_strategies': []
        }
        
        # Immediate actions for critical risks
        risk_analysis = self.perform_risk_analysis()
        for risk in risk_analysis['critical_risks']:
            recommendations['immediate_actions'].append({
                'action': f"Fix {risk['risk']}",
                'description': risk['description'],
                'remediation': risk['remediation']
            })
        
        # Short-term improvements
        recommendations['short_term_improvements'].extend([
            "Implement proper nonce-based CSP for scripts and styles",
            "Remove unsafe-inline and unsafe-eval directives",
            "Set object-src to 'none'",
            "Implement frame-ancestors for clickjacking protection",
            "Set up CSP violation reporting and monitoring"
        ])
        
        # Long-term strategies
        recommendations['long_term_strategies'].extend([
            "Implement strict-dynamic for forward compatibility",
            "Deploy Trusted Types for DOM XSS protection",
            "Establish CSP governance and review process",
            "Implement automated CSP testing in CI/CD",
            "Develop comprehensive CSP monitoring and alerting"
        ])
        
        return recommendations

# Advanced CSP Monitoring System
class CSPMonitor:
    def __init__(self, target_urls, monitoring_interval=3600):
        self.target_urls = target_urls
        self.monitoring_interval = monitoring_interval
        self.csp_baseline = {}

    def setup_continuous_monitoring(self):
        """Set up continuous CSP monitoring"""
        print("[+] Setting up continuous CSP monitoring...")
        
        # Establish baseline
        for url in self.target_urls:
            tester = CSPTester(url)
            baseline = tester.comprehensive_csp_testing()
            self.csp_baseline[url] = baseline
        
        self.start_monitoring_loop()

    def detect_csp_changes(self):
        """Detect changes in CSP configurations"""
        changes_detected = {}
        
        for url, baseline in self.csp_baseline.items():
            current_tester = CSPTester(url)
            current_results = current_tester.comprehensive_csp_testing()
            
            changes = self.compare_csp_results(baseline, current_results)
            
            if changes:
                changes_detected[url] = {
                    'changes': changes,
                    'security_impact': self.assess_change_impact(changes),
                    'timestamp': datetime.now().isoformat()
                }
            
            self.csp_baseline[url] = current_results
        
        return changes_detected

    def compare_csp_results(self, baseline, current):
        """Compare CSP results and detect changes"""
        changes = []
        
        # Compare CSP headers
        baseline_headers = baseline['test_results'].get('csp_headers', {})
        current_headers = current['test_results'].get('csp_headers', {})
        
        # Check for new headers
        new_headers = set(current_headers.keys()) - set(baseline_headers.keys())
        for header in new_headers:
            changes.append({
                'type': 'NEW_CSP_HEADER',
                'header': header,
                'impact': 'MEDIUM'
            })
        
        # Check for removed headers
        removed_headers = set(baseline_headers.keys()) - set(current_headers.keys())
        for header in removed_headers:
            changes.append({
                'type': 'REMOVED_CSP_HEADER',
                'header': header,
                'impact': 'HIGH'
            })
        
        # Check for policy changes
        for header_name in baseline_headers:
            if header_name in current_headers:
                baseline_policy = baseline_headers[header_name].get('raw_header', '')
                current_policy = current_headers[header_name].get('raw_header', '')
                
                if baseline_policy != current_policy:
                    changes.append({
                        'type': 'CSP_POLICY_CHANGE',
                        'header': header_name,
                        'impact': 'MEDIUM'
                    })
        
        return changes
```

### 12 CSP Risk Assessment Matrix
```yaml
CSP Risk Assessment:
  Critical Risks:
    - script-src directive with 'unsafe-inline' allowing inline script execution
    - Missing object-src directive or object-src not set to 'none'
    - Wildcard (*) source in script-src directive
    - CSP bypass via JSONP endpoints or AngularJS injection
    - Missing CSP header entirely on sensitive pages
    - report-uri pointing to attacker-controlled domain
    - Nonce reuse or predictable nonce generation
    - Trusted Types policy with unsafe default values

  High Risks:
    - style-src directive with 'unsafe-inline' allowing inline styles
    - connect-src with wildcard allowing data exfiltration to any domain
    - frame-src with wildcard allowing framing by malicious sites
    - Missing frame-ancestors directive allowing clickjacking
    - 'unsafe-eval' in script-src allowing dynamic code evaluation
    - data: or blob: schemes in script-src or object-src
    - CSP implemented only via report-only mode without enforcement
    - Missing base-uri directive allowing base tag hijacking

  Medium Risks:
    - Insufficient source restrictions in img-src or media-src
    - Missing form-action directive allowing form submission to malicious endpoints
    - Weak nonce entropy or insufficient nonce length
    - CSP not implemented on all subdomains consistently
    - Legacy CSP headers (X-Content-Security-Policy) without modern equivalents
    - Missing upgrade-insecure-requests directive
    - Inconsistent CSP policies across different pages
    - Insufficient violation reporting configuration

  Low Risks:
    - Properly configured CSP with nonce-based script and style protection
    - Object-src set to 'none' and other directives properly restricted
    - Frame-ancestors set to 'none' or specific trusted origins
    - Comprehensive reporting and monitoring in place
    - Regular CSP security testing and validation
    - CSP implemented with strict-dynamic for forward compatibility
    - Trusted Types deployed for DOM XSS protection
    - Automated CSP testing in development pipeline
```

### 13 CSP Protection Testing
```python
# CSP Protection Effectiveness Tester
class CSPProtectionTester:
    def __init__(self, target_applications):
        self.target_applications = target_applications

    def test_protection_effectiveness(self):
        """Test CSP protection effectiveness"""
        protection_tests = {}
        
        for app in self.target_applications:
            tester = CSPTester(app['url'])
            results = tester.comprehensive_csp_testing()
            
            protection_tests[app['name']] = {
                'xss_protection': self.test_xss_protection(results),
                'clickjacking_protection': self.test_clickjacking_protection(results),
                'data_exfiltration_protection': self.test_data_exfiltration_protection(results),
                'mixed_content_protection': self.test_mixed_content_protection(results),
                'overall_protection_score': self.calculate_protection_score(results)
            }
        
        return protection_tests

    def generate_protection_report(self):
        """Generate comprehensive protection report"""
        protection_tests = self.test_protection_effectiveness()
        
        report = {
            'protection_analysis': protection_tests,
            'security_gaps': self.identify_protection_gaps(protection_tests),
            'compliance_status': self.assess_protection_compliance(),
            'improvement_recommendations': self.generate_protection_recommendations()
        }
        
        return report
```

### 14 CSP Remediation Checklist
```markdown
## ✅ CONTENT SECURITY POLICY SECURITY REMEDIATION CHECKLIST

### CSP Implementation:
- [ ] Implement Content-Security-Policy HTTP header on all pages
- [ ] Use Content-Security-Policy-Report-Only for testing before enforcement
- [ ] Ensure CSP headers are delivered with correct syntax and format
- [ ] Remove legacy CSP headers (X-Content-Security-Policy, X-WebKit-CSP)
- [ ] Implement consistent CSP across all subdomains and endpoints
- [ ] Test CSP with both HTTP and HTTPS protocols
- [ ] Validate CSP header syntax using automated tools
- [ ] Document CSP policy and maintenance procedures

### Directive Security:
- [ ] Set script-src without 'unsafe-inline' and 'unsafe-eval'
- [ ] Implement nonce-based or hash-based script authorization
- [ ] Set object-src to 'none' to prevent plugin-based attacks
- [ ] Configure frame-ancestors to prevent clickjacking
- [ ] Set base-uri to restrict base URL modifications
- [ ] Configure form-action to control form submission targets
- [ ] Set upgrade-insecure-requests for HTTP to HTTPS upgrading
- [ ] Implement block-all-mixed-content to prevent mixed content

### Source Restrictions:
- [ ] Remove wildcard (*) sources from all directives
- [ ] Restrict data: and blob: schemes to necessary directives only
- [ ] Specify exact host sources instead of wildcard subdomains
- [ ] Implement 'self' source carefully with same-origin consideration
- [ ] Use specific protocols (https:) instead of protocol-relative URLs
- [ ] Restrict connect-src to necessary API endpoints only
- [ ] Limit img-src to trusted image sources and CDNs
- [ ] Control font-src and media-src to trusted providers

### Advanced Security Features:
- [ ] Implement 'strict-dynamic' for forward-compatible CSP
- [ ] Deploy Trusted Types for DOM XSS protection
- [ ] Use hashes for static inline scripts and styles
- [ ] Implement nonce-based authorization for dynamic content
- [ ] Configure sandbox directives for iframe isolation
- [ ] Use require-trusted-types-for for DOM manipulation control
- [ ] Implement report-to for modern reporting endpoints
- [ ] Deploy frame-src and child-src with specific restrictions

### Reporting & Monitoring:
- [ ] Configure report-uri or report-to for violation reporting
- [ ] Set up monitoring and alerting for CSP violations
- [ ] Regularly review and analyze violation reports
- [ ] Implement automated reporting to security teams
- [ ] Test reporting functionality with simulated violations
- [ ] Monitor report endpoint availability and performance
- [ ] Implement log aggregation for CSP violation analysis
- [ ] Set up dashboards for CSP compliance monitoring

### Framework & Library Integration:
- [ ] Configure CSP for React, Angular, Vue, or other frameworks
- [ ] Test CSP with third-party libraries and widgets
- [ ] Implement CSP for single-page applications (SPAs)
- [ ] Configure CSP for server-side rendering (SSR) applications
- [ ] Test CSP with Web Components and custom elements
- [ ] Validate CSP with progressive web apps (PWAs)
- [ ] Implement CSP for CMS platforms (WordPress, Drupal, etc.)
- [ ] Test CSP with e-commerce and payment integrations

### Testing & Validation:
- [ ] Conduct regular CSP security testing and validation
- [ ] Test CSP bypass techniques and evasion methods
- [ ] Validate CSP with different browsers and versions
- [ ] Test CSP with mobile browsers and devices
- [ ] Conduct automated CSP testing in CI/CD pipelines
- [ ] Perform manual CSP testing for complex applications
- [ ] Test CSP with accessibility tools and screen readers
- [ ] Validate CSP performance impact and optimization

### Organizational Controls:
- [ ] Establish CSP governance and policy management
- [ ] Implement CSP change control and review processes
- [ ] Conduct regular CSP security awareness training
- [ ] Establish incident response procedures for CSP issues
- [ ] Implement CSP compliance monitoring and reporting
- [ ] Conduct third-party CSP security assessments
- [ ] Maintain comprehensive CSP documentation
- [ ] Implement continuous improvement for CSP policies
```

### 15 CSP Testing Completion Checklist
```markdown
## ✅ CONTENT SECURITY POLICY TESTING COMPLETION CHECKLIST

### CSP Header Discovery & Analysis:
- [ ] CSP header presence testing completed
- [ ] CSP header syntax and format validation done
- [ ] Multiple CSP header collision testing completed
- [ ] Meta tag CSP implementation analysis done
- [ ] HTTP/HTTPS CSP consistency testing completed
- [ ] Subdomain CSP policy analysis done
- [ ] API endpoint CSP implementation testing completed
- [ ] CSP delivery mechanism analysis done

### CSP Directive Security Testing:
- [ ] Source directive security assessment completed
- [ ] script-src directive source validation done
- [ ] style-src directive source validation completed
- [ ] img-src directive source validation done
- [ ] connect-src directive source validation completed
- [ ] frame-ancestors directive testing done
- [ ] form-action directive testing completed
- [ ] base-uri directive testing done

### CSP Source Validation Testing:
- [ ] Wildcard source security impact testing completed
- [ ] 'self' source scope validation done
- [ ] 'none' source restriction testing completed
- [ ] Scheme source security testing done
- [ ] Nonce implementation security testing completed
- [ ] Hash source implementation testing done
- [ ] Unsafe directive evaluation testing completed
- [ ] Source list security assessment done

### Nonce & Hash Implementation Testing:
- [ ] Nonce generation randomness testing completed
- [ ] Nonce reuse and predictability testing done
- [ ] Nonce delivery mechanism testing completed
- [ ] Hash algorithm support testing done
- [ ] Hash calculation accuracy testing completed
- [ ] Dynamic content hash generation testing done
- [ ] Hash maintenance testing completed
- [ ] Nonce brute force resistance testing done

### CSP Bypass & Evasion Testing:
- [ ] Script injection bypass testing completed
- [ ] JSONP endpoint CSP bypass testing done
- [ ] AngularJS template injection testing completed
- [ ] Data URI scheme bypass testing done
- [ ] Policy injection testing completed
- [ ] Browser parser differential testing done
- [ ] Legacy browser bypass testing completed
- [ ] Advanced evasion technique testing done

### CSP Reporting & Monitoring Testing:
- [ ] report-uri directive functionality testing completed
- [ ] report-to directive endpoint testing done
- [ ] Report format and content validation completed
- [ ] Report delivery reliability testing done
- [ ] Monitoring effectiveness testing completed
- [ ] Real-time alerting capability testing done
- [ ] Compliance reporting testing completed
- [ ] Incident correlation testing done

### Advanced CSP Feature Testing:
- [ ] Trusted Types implementation testing completed
- [ ] Strict dynamic directive testing done
- [ ] Framework-specific CSP testing completed
- [ ] CMS platform CSP testing done
- [ ] Mobile application CSP testing completed
- [ ] Progressive Web App CSP testing done
- [ ] CDN integration CSP testing completed
- [ ] Load balancer CSP testing done

### Compliance and Reporting:
- [ ] Regulatory compliance assessment completed
- [ ] Industry standard compliance validation done
- [ ] Risk assessment and analysis completed
- [ ] Security effectiveness evaluation done
- [ ] Remediation recommendations developed
- [ ] Executive security report generated
- [ ] Management presentation prepared
- [ ] Continuous monitoring plan established
```

### 16 CSP Executive Reporting Template
```markdown
# Content Security Policy Security Assessment Report

## Executive Summary
- **Assessment Scope:** [Applications and pages assessed]
- **Assessment Period:** [Date range]
- **CSP Headers Analyzed:** [Total header count]
- **Critical Vulnerabilities:** [Critical findings count]
- **Overall Risk Level:** [High/Medium/Low]
- **Key Recommendations:** [Priority actions]

## Critical Findings
### [Critical Finding Title]
- **Directive:** [Affected CSP directive]
- **Risk Level:** Critical
- **Description:** [Detailed vulnerability description]
- **Impact:** [Potential security impact analysis]
- **Remediation Priority:** Immediate

## Technical Analysis
### CSP Implementation Status
- **CSP Headers Present:** [Yes/No/Partial]
- **Enforcement vs Report-Only:** [Ratio and coverage]
- **Directive Coverage:** [Completeness assessment]
- **Source Restrictions:** [Effectiveness rating]

### Security Control Assessment
- **XSS Protection:** [Protection effectiveness rating]
- **Clickjacking Protection:** [Control effectiveness rating]
- **Data Exfiltration Protection:** [Prevention capability assessment]
- **Mixed Content Protection:** [Security control rating]

## Risk Assessment
### High Priority Risks
1. **[Risk Title]**
   - **Description:** [Detailed risk explanation]
   - **Impact:** [Security impact analysis]
   - **Likelihood:** [Probability assessment]
   - **Remediation:** [Specific mitigation steps]

### Medium Priority Risks
1. **[Risk Title]**
   - **Description:** [Detailed risk explanation]
   - **Impact:** [Security impact analysis]
   - **Likelihood:** [Probability assessment]
   - **Remediation:** [Specific mitigation steps]

## Recommendations
### Immediate Actions (1-7 days)
- [ ] [Remove unsafe-inline from script-src]
- [ ] [Set object-src to 'none']
- [ ] [Implement frame-ancestors directive]

### Short-term Improvements (1-4 weeks)
- [ ] [Implement nonce-based script authorization]
- [ ] [Set up CSP violation reporting]
- [ ] [Conduct comprehensive CSP testing]

### Long-term Strategies (1-6 months)
- [ ] [Implement strict-dynamic and Trusted Types]
- [ ] [Establish CSP governance framework]
- [ ] [Develop continuous monitoring program]

## Compliance Status
- **Regulatory Compliance:** [PCI DSS, HIPAA, etc. compliance level]
- **Industry Standards:** [Security standards alignment]
- **Internal Policies:** [Policy compliance evaluation]

## Appendices
### Detailed CSP Analysis
- CSP header configurations and findings
- Directive security assessments
- Vulnerability details and locations
- Risk classification details

### Risk Classification Matrix
- Risk scoring methodology
- Impact assessment criteria
- Remediation priority framework
- Compliance mapping

### Testing Methodology
- Tools and techniques used
- Scope and limitations
- Validation procedures
- Quality assurance measures
```

This comprehensive Content Security Policy Security Testing checklist provides complete methodology for assessing, implementing, and maintaining effective CSP protection across web applications. The framework covers header analysis, directive security, bypass testing, advanced features, and comprehensive protection strategies to prevent XSS, clickjacking, data exfiltration, and other client-side attacks through robust content security policies.