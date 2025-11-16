# Testing for DOM-Based Cross Site Scripting

## Comprehensive DOM-Based XSS Testing

### 1 DOM XSS Attack Vectors
- **Source Identification:**
  - Document URL manipulation
  - Location object properties
  - Document referrer analysis
  - Window name manipulation
  - PostMessage event handling
  - Cookie access and manipulation
  - LocalStorage data retrieval
  - SessionStorage data access

- **Sink Identification:**
  - HTML injection sinks (innerHTML, outerHTML)
  - Script execution sinks (eval, setTimeout, setInterval)
  - URL navigation sinks (location, location.href)
  - DOM manipulation sinks (document.write, document.writeln)
  - jQuery insecure methods (html(), append())
  - AngularJS expression injection
  - React dangerouslySetInnerHTML
  - Vue.js v-html directive

### 2 Source-Sink Mapping
- **Direct Source to Sink Flows:**
  - URL → innerHTML
  - location.hash → document.write
  - document.URL → eval
  - window.name → location.href
  - postMessage → innerHTML
  - localStorage → eval
  - sessionStorage → script execution
  - cookie → DOM manipulation

- **Complex Data Flow Chains:**
  - Multi-step source propagation
  - Function parameter passing
  - Object property assignment
  - Array element manipulation
  - Event handler data flow
  - Callback function chains
  - Promise resolution flows
  - Async/await data propagation

### 3 DOM Data Flow Analysis
- **Static Analysis Techniques:**
  - Source code pattern matching
  - Abstract syntax tree analysis
  - Data flow graph construction
  - Taint tracking implementation
  - Control flow analysis
  - Function call graph analysis
  - Object property tracking
  - Array method analysis

- **Dynamic Analysis Methods:**
  - Runtime instrumentation
  - Execution tracing
  - Property access monitoring
  - Function hooking
  - Event listener analysis
  - DOM mutation observation
  - Network request monitoring
  - Storage access tracking

### 4 Common DOM XSS Patterns
- **Location-Based Vulnerabilities:**
  - URL fragment manipulation (#)
  - URL query parameter access
  - Pathname manipulation
  - Search parameter access
  - Hash change event handling
  - Popstate event processing
  - History API manipulation
  - Navigation timing attacks

- **Window Object Exploitation:**
  - window.name persistence
  - window.opener reference
  - window.parent access
  - window.top manipulation
  - window.postMessage handling
  - window.location assignment
  - window.open exploitation
  - window.addEventListener misuse

### 5 JavaScript Framework Testing
- **AngularJS Specific Testing:**
  - Angular expression injection
  - Scope variable manipulation
  - $compile service misuse
  - ng-bind-html exploitation
  - $interpolate service testing
  - Filter function manipulation
  - Directive security testing
  - Controller function injection

- **React Specific Testing:**
  - dangerouslySetInnerHTML usage
  - React.createElement injection
  - JSX expression evaluation
  - Props object manipulation
  - State management vulnerabilities
  - Context API security testing
  - Hooks security analysis
  - Event handler manipulation

- **Vue.js Specific Testing:**
  - v-html directive testing
  - Vue template injection
  - Computed property manipulation
  - Method security testing
  - Watcher function exploitation
  - Directive security analysis
  - Mixin security testing
  - Plugin security evaluation

### 6 Advanced DOM XSS Techniques
- **Mutation XSS (mXSS):**
  - HTML parsing inconsistency exploitation
  - Browser parser differential analysis
  - innerHTML serialization attacks
  - outerHTML manipulation
  - Document fragment exploitation
  - Template element manipulation
  - Custom element exploitation
  - Shadow DOM manipulation

- **Universal XSS (UXSS):**
  - Browser extension vulnerabilities
  - Plugin security flaws
  - Browser engine exploits
  - Protocol handler manipulation
  - Scheme-based exploitation
  - Mobile browser specific vectors
  - PDF reader integration
  - Office document preview

### 7 PostMessage Security Testing
- **PostMessage Source Analysis:**
  - Origin validation testing
  - Message type analysis
  - Data structure manipulation
  - Event listener security
  - Callback function safety
  - Error handling testing
  - Cross-origin communication
  - iframe communication security

- **PostMessage Sink Testing:**
  - Message data to innerHTML
  - Message data to eval
  - Message data to location
  - Message data to script src
  - Message data to function calls
  - Message data to DOM APIs
  - Message data to jQuery methods
  - Message data to framework methods

### 8 Client-Side Storage Testing
- **LocalStorage Security:**
  - LocalStorage data retrieval sinks
  - JSON.parse exploitation
  - Data serialization attacks
  - Storage event manipulation
  - Cross-tab communication
  - Storage quota exploitation
  - Data persistence attacks
  - Clear-text storage analysis

- **SessionStorage Testing:**
  - Tab-specific data isolation
  - Session data manipulation
  - Storage event handling
  - Data lifecycle analysis
  - Cross-origin storage access
  - Browser tab synchronization
  - Private browsing implications
  - Storage size limitations

### 9 DOM Clobbering Attacks
- **HTML Injection to JavaScript:**
  - Form element clobbering
  - Anchor element manipulation
  - Image element exploitation
  - Meta element clobbering
  - Link element manipulation
  - Script element interference
  - Iframe element exploitation
  - Custom element clobbering

- **Property Pollution Techniques:**
  - Global object pollution
  - Prototype chain manipulation
  - Object property overriding
  - Array method clobbering
  - Function property pollution
  - Namespace contamination
  - Configuration object manipulation
  - Environment variable simulation

### 10 Automated DOM XSS Testing Framework
```yaml
DOM XSS Security Assessment Pipeline:
  Discovery Phase:
    - JavaScript source file enumeration
    - Source identification (URL, cookies, storage)
    - Sink identification (innerHTML, eval, etc.)
    - Data flow path discovery
    - Event listener analysis
    - Framework-specific source detection
    - API endpoint client-side analysis
    - Third-party library assessment

  Analysis Phase:
    - Source-to-sink data flow mapping
    - Taint propagation analysis
    - Context sensitivity assessment
    - Sanitization effectiveness evaluation
    - Encoding validation testing
    - Browser-specific behavior analysis
    - Framework security control assessment
    - Exploitation complexity evaluation

  Testing Phase:
    - Direct source-sink testing
    - Complex data flow testing
    - Framework-specific testing
    - PostMessage security testing
    - Storage-based XSS testing
    - DOM clobbering testing
    - Mutation XSS testing
    - Universal XSS testing

  Validation Phase:
    - Vulnerability confirmation
    - Browser compatibility testing
    - Exploit reliability validation
    - Business impact verification
    - Remediation effectiveness testing
    - Client-side monitoring assessment
    - Documentation accuracy verification
    - Continuous monitoring setup
```

### 11 DOM XSS Testing Tools & Commands
```bash
# Automated DOM XSS Testing
python3 dom_xss_scanner.py --url https://target.com --tests all
dominator --url https://target.com --output dom_xss_report.html
burp_suite --target https://target.com --dom-xss-scan --active-scan

# Manual Testing Tools
curl -G --data-urlencode "query=test#<img src=x onerror=alert(1)>" https://target.com
browser_console_testing --url https://target.com --sources all --sinks comprehensive

# Source-Sink Analysis
source_sink_mapper --url https://target.com --analysis static,dynamic
taint_tracking_tester --target https://target.com --sources url,cookies,storage --sinks innerHTML,eval

# Framework-Specific Testing
angular_dom_xss --url https://target.com --angular-versions all
react_dom_xss_tester --url https://target.com --react-analysis --hooks-testing
vue_dom_xss_scanner --target https://target.com --vue-testing --directives all

# Advanced Technique Testing
mutation_xss_tester --url https://target.com --browsers chrome,firefox,safari
dom_clobbering_tester --target https://target.com --clobbering-techniques all
postmessage_xss_tester --url https://target.com --postmessage-analysis --origin-testing

# Browser-Specific Testing
browser_engine_xss --url https://target.com --engines blink,gecko,webkit
mobile_dom_xss --target https://target.com --mobile-browsers safari,chrome,samsung

# Storage-Based Testing
localstorage_xss_tester --url https://target.com --storage-analysis --json-testing
sessionstorage_xss --target https://target.com --session-analysis --tab-isolation

# jQuery Testing
jquery_dom_xss --url https://target.com --jquery-versions all --methods html,append,attr
```

### 12 Advanced DOM XSS Testing Implementation
```python
# Comprehensive DOM XSS Testing Tool
import asyncio
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
import logging
import json
import time
from urllib.parse import urlparse, urljoin
import requests

class DOMXSSTester:
    def __init__(self, target_url, config):
        self.target_url = target_url
        self.config = config
        self.test_results = {
            'sources_identified': [],
            'sinks_identified': [],
            'source_sink_flows': [],
            'vulnerabilities_found': [],
            'framework_analysis': {},
            'browser_analysis': {}
        }
        
        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Browser configuration
        self.driver = self.setup_browser()
        
        # DOM XSS payload libraries
        self.sources = self.load_dom_sources()
        self.sinks = self.load_dom_sinks()
        self.payloads = self.load_dom_payloads()

    def setup_browser(self):
        """Setup Selenium WebDriver for DOM XSS testing"""
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-web-security')
        chrome_options.add_argument('--allow-running-insecure-content')
        
        # Enable logging for better analysis
        chrome_options.set_capability('goog:loggingPrefs', {'browser': 'ALL'})
        
        return webdriver.Chrome(options=chrome_options)

    async def comprehensive_dom_xss_testing(self):
        """Perform comprehensive DOM XSS testing"""
        self.logger.info(f"Starting DOM XSS testing for {self.target_url}")
        
        try:
            # Navigate to target
            self.driver.get(self.target_url)
            
            # Wait for page load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Execute comprehensive tests
            await self.identify_sources()
            await self.identify_sinks()
            await self.analyze_data_flows()
            await self.test_dom_xss_vulnerabilities()
            await self.test_framework_specific()
            await self.test_advanced_techniques()
            
        except Exception as e:
            self.logger.error(f"Error during DOM XSS testing: {e}")
        finally:
            self.driver.quit()
        
        return {
            'test_results': self.test_results,
            'security_assessment': self.perform_security_assessment(),
            'risk_analysis': self.perform_risk_analysis(),
            'remediation_recommendations': self.generate_recommendations()
        }

    async def identify_sources(self):
        """Identify DOM XSS sources in the application"""
        self.logger.info("Identifying DOM XSS sources")
        
        sources_found = []
        
        # Test URL-based sources
        url_sources = [
            'document.URL',
            'document.documentURI',
            'document.baseURI',
            'location.href',
            'location.pathname',
            'location.search',
            'location.hash',
            'location.host',
            'location.hostname',
            'location.port',
            'location.protocol'
        ]
        
        for source in url_sources:
            try:
                value = self.driver.execute_script(f"return {source};")
                if value and len(value) > 0:
                    sources_found.append({
                        'type': 'URL',
                        'source': source,
                        'value': value,
                        'controllable': await self.is_source_controllable(source)
                    })
            except Exception as e:
                self.logger.debug(f"Error checking source {source}: {e}")
        
        # Test window-based sources
        window_sources = [
            'window.name',
            'window.location',
            'window.parent',
            'window.opener'
        ]
        
        for source in window_sources:
            try:
                value = self.driver.execute_script(f"return {source};")
                if value and len(value) > 0:
                    sources_found.append({
                        'type': 'Window',
                        'source': source,
                        'value': str(value),
                        'controllable': await self.is_source_controllable(source)
                    })
            except Exception as e:
                self.logger.debug(f"Error checking window source {source}: {e}")
        
        # Test postMessage sources
        try:
            message_handlers = self.driver.execute_script("""
                let handlers = [];
                if (window.addEventListener) {
                    // Can't directly access, but we can check if it's likely used
                    handlers.push('window.addEventListener("message")');
                }
                return handlers;
            """)
            if message_handlers:
                sources_found.append({
                    'type': 'PostMessage',
                    'source': 'window.message',
                    'value': 'Dynamic',
                    'controllable': True
                })
        except Exception as e:
            self.logger.debug(f"Error checking postMessage: {e}")
        
        # Test storage sources
        storage_sources = [
            'localStorage',
            'sessionStorage',
            'document.cookie'
        ]
        
        for source in storage_sources:
            try:
                value = self.driver.execute_script(f"return {source};")
                if value and len(value) > 0:
                    sources_found.append({
                        'type': 'Storage',
                        'source': source,
                        'value': value,
                        'controllable': await self.is_source_controllable(source)
                    })
            except Exception as e:
                self.logger.debug(f"Error checking storage source {source}: {e}")
        
        self.test_results['sources_identified'] = sources_found
        return sources_found

    async def identify_sinks(self):
        """Identify DOM XSS sinks in the application"""
        self.logger.info("Identifying DOM XSS sinks")
        
        sinks_found = []
        
        # HTML injection sinks
        html_sinks = [
            'innerHTML',
            'outerHTML',
            'document.write',
            'document.writeln',
            'insertAdjacentHTML'
        ]
        
        for sink in html_sinks:
            try:
                # Check if sink is used in the page
                usage = self.driver.execute_script(f"""
                    return {{
                        'used': typeof document !== 'undefined' && 
                               document.documentElement.outerHTML.includes('{sink}'),
                        'examples': Array.from(document.querySelectorAll('*')).filter(el => 
                            el.outerHTML.includes('{sink}')).length
                    }};
                """)
                
                if usage['used']:
                    sinks_found.append({
                        'type': 'HTML Injection',
                        'sink': sink,
                        'usage_count': usage['examples'],
                        'danger_level': 'High'
                    })
            except Exception as e:
                self.logger.debug(f"Error checking HTML sink {sink}: {e}")
        
        # Script execution sinks
        script_sinks = [
            'eval',
            'setTimeout',
            'setInterval',
            'Function',
            'execScript'
        ]
        
        for sink in script_sinks:
            try:
                usage = self.driver.execute_script(f"""
                    return {{
                        'used': typeof window !== 'undefined' && 
                               document.documentElement.outerHTML.includes('{sink}'),
                        'examples': Array.from(document.querySelectorAll('script')).filter(script => 
                            script.innerHTML.includes('{sink}')).length
                    }};
                """)
                
                if usage['used']:
                    sinks_found.append({
                        'type': 'Script Execution',
                        'sink': sink,
                        'usage_count': usage['examples'],
                        'danger_level': 'Critical'
                    })
            except Exception as e:
                self.logger.debug(f"Error checking script sink {sink}: {e}")
        
        # URL navigation sinks
        url_sinks = [
            'location',
            'location.href',
            'location.assign',
            'location.replace',
            'window.open'
        ]
        
        for sink in url_sinks:
            try:
                usage = self.driver.execute_script(f"""
                    return {{
                        'used': typeof window !== 'undefined' && 
                               document.documentElement.outerHTML.includes('{sink}'),
                        'examples': Array.from(document.querySelectorAll('*')).filter(el => 
                            el.outerHTML.includes('{sink}')).length
                    }};
                """)
                
                if usage['used']:
                    sinks_found.append({
                        'type': 'URL Navigation',
                        'sink': sink,
                        'usage_count': usage['examples'],
                        'danger_level': 'Medium'
                    })
            except Exception as e:
                self.logger.debug(f"Error checking URL sink {sink}: {e}")
        
        # jQuery sinks
        jquery_sinks = [
            'html()',
            'append()',
            'prepend()',
            'after()',
            'before()',
            'replaceWith()',
            'attr()',
            'val()'
        ]
        
        for sink in jquery_sinks:
            try:
                jquery_used = self.driver.execute_script("return typeof jQuery !== 'undefined';")
                if jquery_used:
                    usage = self.driver.execute_script(f"""
                        return document.documentElement.outerHTML.includes('{sink.replace("()", "")}');
                    """)
                    
                    if usage:
                        sinks_found.append({
                            'type': 'jQuery',
                            'sink': sink,
                            'usage_count': 1,  # Approximation
                            'danger_level': 'High'
                        })
            except Exception as e:
                self.logger.debug(f"Error checking jQuery sink {sink}: {e}")
        
        self.test_results['sinks_identified'] = sinks_found
        return sinks_found

    async def analyze_data_flows(self):
        """Analyze data flows from sources to sinks"""
        self.logger.info("Analyzing source-to-sink data flows")
        
        flows_found = []
        
        # Get identified sources and sinks
        sources = self.test_results['sources_identified']
        sinks = self.test_results['sinks_identified']
        
        # Test direct flows
        for source in sources:
            for sink in sinks:
                if await self.test_source_sink_flow(source, sink):
                    flow = {
                        'source': source['source'],
                        'sink': sink['sink'],
                        'flow_type': 'Direct',
                        'vulnerable': True,
                        'exploitation_complexity': 'Low'
                    }
                    flows_found.append(flow)
                    self.logger.warning(f"Direct flow found: {source['source']} → {sink['sink']}")
        
        # Test complex flows through JavaScript
        complex_flows = await self.analyze_complex_flows(sources, sinks)
        flows_found.extend(complex_flows)
        
        self.test_results['source_sink_flows'] = flows_found
        return flows_found

    async def test_source_sink_flow(self, source, sink):
        """Test if data from source flows to sink"""
        try:
            # Create a unique test payload
            test_payload = f"DOMXSS_TEST_{int(time.time())}"
            
            # Inject payload into source and check if it reaches sink
            result = self.driver.execute_script(f"""
                try {{
                    // Store original values
                    const originalSource = {source['source']};
                    const testPayload = '{test_payload}';
                    
                    // Attempt to inject into source
                    if ({source['source']} && typeof {source['source']} === 'string') {{
                        {source['source']} = {source['source']} + testPayload;
                    }}
                    
                    // Check various sinks for the payload
                    const sinksToCheck = [
                        document.documentElement.innerHTML,
                        document.documentElement.outerHTML,
                        document.body.innerHTML,
                        document.body.outerHTML
                    ];
                    
                    for (let sinkContent of sinksToCheck) {{
                        if (sinkContent && sinkContent.includes(testPayload)) {{
                            return true;
                        }}
                    }}
                    
                    // Restore original value
                    {source['source']} = originalSource;
                    
                    return false;
                }} catch (e) {{
                    return false;
                }}
            """)
            
            return result
            
        except Exception as e:
            self.logger.debug(f"Error testing flow {source['source']} → {sink['sink']}: {e}")
            return False

    async def test_dom_xss_vulnerabilities(self):
        """Test for actual DOM XSS vulnerabilities"""
        self.logger.info("Testing for DOM XSS vulnerabilities")
        
        vulnerabilities_found = []
        
        # Test each identified flow with actual XSS payloads
        flows = self.test_results['source_sink_flows']
        
        for flow in flows:
            for payload in self.payloads:
                try:
                    vulnerable = await self.test_xss_payload(flow, payload)
                    if vulnerable:
                        vulnerability = {
                            'flow': flow,
                            'payload': payload,
                            'severity': self.calculate_xss_severity(flow, payload),
                            'exploitation_method': 'Automatic',
                            'browser_agnostic': await self.test_browser_compatibility(flow, payload)
                        }
                        vulnerabilities_found.append(vulnerability)
                        self.logger.critical(f"DOM XSS vulnerability found: {flow['source']} → {flow['sink']}")
                except Exception as e:
                    self.logger.error(f"Error testing payload {payload['description']}: {e}")
        
        self.test_results['vulnerabilities_found'] = vulnerabilities_found
        return vulnerabilities_found

    async def test_xss_payload(self, flow, payload):
        """Test specific XSS payload on identified flow"""
        try:
            # Use Selenium to inject payload and detect execution
            result = self.driver.execute_script(f"""
                try {{
                    const testPayload = '{payload['payload']}';
                    let executed = false;
                    
                    // Override alert to detect execution
                    window.alert = function() {{ executed = true; }};
                    
                    // Attempt to inject payload into the flow
                    {flow['source']} = testPayload;
                    
                    // Trigger potential execution
                    if (window.onhashchange && {flow['source']}.includes('#')) {{
                        window.onhashchange();
                    }}
                    
                    // Check if payload was executed
                    return executed;
                }} catch (e) {{
                    return false;
                }}
            """)
            
            return result
            
        except Exception as e:
            self.logger.debug(f"Error testing XSS payload: {e}")
            return False

    async def test_framework_specific(self):
        """Test framework-specific DOM XSS vectors"""
        self.logger.info("Testing framework-specific DOM XSS")
        
        framework_tests = {
            'angular': await self.test_angular_xss(),
            'react': await self.test_react_xss(),
            'vue': await self.test_vue_xss(),
            'jquery': await self.test_jquery_xss()
        }
        
        self.test_results['framework_analysis'] = framework_tests
        return framework_tests

    async def test_angular_xss(self):
        """Test AngularJS-specific XSS vectors"""
        angular_tests = []
        
        try:
            # Check if Angular is used
            angular_used = self.driver.execute_script("return typeof angular !== 'undefined';")
            
            if angular_used:
                # Test ng-bind-html
                ng_bind_elements = self.driver.execute_script("""
                    return Array.from(document.querySelectorAll('[ng-bind-html]')).length;
                """)
                
                if ng_bind_elements > 0:
                    angular_tests.append({
                        'vector': 'ng-bind-html',
                        'vulnerable': True,
                        'severity': 'High'
                    })
                
                # Test $interpolate
                interpolate_used = self.driver.execute_script("""
                    return document.documentElement.outerHTML.includes('$interpolate');
                """)
                
                if interpolate_used:
                    angular_tests.append({
                        'vector': '$interpolate',
                        'vulnerable': True,
                        'severity': 'Medium'
                    })
        
        except Exception as e:
            self.logger.error(f"Error testing Angular XSS: {e}")
        
        return angular_tests

    async def test_react_xss(self):
        """Test React-specific XSS vectors"""
        react_tests = []
        
        try:
            # Check if React is used
            react_used = self.driver.execute_script("""
                return typeof React !== 'undefined' || 
                       typeof react !== 'undefined' ||
                       document.querySelector('[data-reactroot]') !== null;
            """)
            
            if react_used:
                # Test dangerouslySetInnerHTML
                dangerous_elements = self.driver.execute_script("""
                    return Array.from(document.querySelectorAll('*')).filter(el => 
                        el.outerHTML.includes('dangerouslySetInnerHTML')).length;
                """)
                
                if dangerous_elements > 0:
                    react_tests.append({
                        'vector': 'dangerouslySetInnerHTML',
                        'vulnerable': True,
                        'severity': 'High'
                    })
        
        except Exception as e:
            self.logger.error(f"Error testing React XSS: {e}")
        
        return react_tests

    async def test_advanced_techniques(self):
        """Test advanced DOM XSS techniques"""
        self.logger.info("Testing advanced DOM XSS techniques")
        
        advanced_tests = {
            'mutation_xss': await self.test_mutation_xss(),
            'dom_clobbering': await self.test_dom_clobbering(),
            'postmessage_xss': await self.test_postmessage_xss(),
            'storage_xss': await self.test_storage_xss()
        }
        
        self.test_results['advanced_analysis'] = advanced_tests
        return advanced_tests

    async def test_mutation_xss(self):
        """Test Mutation XSS vulnerabilities"""
        mutation_tests = []
        
        try:
            # Test innerHTML serialization issues
            mutation_vulnerable = self.driver.execute_script("""
                try {
                    // Create test element with potentially dangerous content
                    const testDiv = document.createElement('div');
                    testDiv.innerHTML = '<img src=x onerror=alert(1)>';
                    
                    // Check if attributes are preserved
                    const img = testDiv.querySelector('img');
                    return img && img.getAttribute('onerror') !== null;
                } catch (e) {
                    return false;
                }
            """)
            
            if mutation_vulnerable:
                mutation_tests.append({
                    'technique': 'innerHTML serialization',
                    'vulnerable': True,
                    'severity': 'High'
                })
        
        except Exception as e:
            self.logger.error(f"Error testing Mutation XSS: {e}")
        
        return mutation_tests

    def load_dom_sources(self):
        """Load DOM XSS source definitions"""
        return [
            {'type': 'URL', 'source': 'document.URL', 'controllable': True},
            {'type': 'URL', 'source': 'location.href', 'controllable': True},
            {'type': 'URL', 'source': 'location.hash', 'controllable': True},
            {'type': 'URL', 'source': 'location.search', 'controllable': True},
            {'type': 'Window', 'source': 'window.name', 'controllable': True},
            {'type': 'Document', 'source': 'document.referrer', 'controllable': True},
            {'type': 'Storage', 'source': 'localStorage', 'controllable': True},
            {'type': 'Storage', 'source': 'sessionStorage', 'controllable': True},
            {'type': 'Cookie', 'source': 'document.cookie', 'controllable': True}
        ]

    def load_dom_sinks(self):
        """Load DOM XSS sink definitions"""
        return [
            {'type': 'HTML', 'sink': 'innerHTML', 'danger_level': 'High'},
            {'type': 'HTML', 'sink': 'outerHTML', 'danger_level': 'High'},
            {'type': 'HTML', 'sink': 'document.write', 'danger_level': 'High'},
            {'type': 'HTML', 'sink': 'document.writeln', 'danger_level': 'High'},
            {'type': 'Script', 'sink': 'eval', 'danger_level': 'Critical'},
            {'type': 'Script', 'sink': 'setTimeout', 'danger_level': 'High'},
            {'type': 'Script', 'sink': 'setInterval', 'danger_level': 'High'},
            {'type': 'URL', 'sink': 'location.href', 'danger_level': 'Medium'},
            {'type': 'URL', 'sink': 'location.assign', 'danger_level': 'Medium'}
        ]

    def load_dom_payloads(self):
        """Load DOM XSS test payloads"""
        return [
            {
                'description': 'Basic script execution',
                'payload': '<script>alert(1)</script>'
            },
            {
                'description': 'Image with onerror',
                'payload': '<img src=x onerror=alert(1)>'
            },
            {
                'description': 'SVG with onload',
                'payload': '<svg onload=alert(1)>'
            },
            {
                'description': 'JavaScript URL',
                'payload': 'javascript:alert(1)'
            },
            {
                'description': 'Event handler with hash',
                'payload': '#<img src=x onerror=alert(1)>'
            },
            {
                'description': 'Angular expression',
                'payload': '{{1+1}}'
            }
        ]

# Advanced DOM XSS Detection System
class DOMXSSDetector:
    def __init__(self, javascript_files):
        self.javascript_files = javascript_files
        self.patterns = self.load_detection_patterns()

    def analyze_javascript_files(self):
        """Analyze JavaScript files for DOM XSS patterns"""
        vulnerabilities = []
        
        for js_file in self.javascript_files:
            analysis = self.analyze_single_file(js_file)
            vulnerabilities.extend(analysis)
        
        return vulnerabilities

    def analyze_single_file(self, js_file):
        """Analyze single JavaScript file for DOM XSS"""
        file_vulnerabilities = []
        
        # Check for source-sink patterns
        for source_pattern in self.patterns['sources']:
            for sink_pattern in self.patterns['sinks']:
                if self.detect_source_sink_pattern(js_file, source_pattern, sink_pattern):
                    file_vulnerabilities.append({
                        'file': js_file['name'],
                        'source': source_pattern,
                        'sink': sink_pattern,
                        'line': self.find_pattern_line(js_file, source_pattern, sink_pattern),
                        'severity': 'High'
                    })
        
        return file_vulnerabilities

# DOM XSS Protection Testing
class DOMXSSProtectionTester:
    def __init__(self, target_environments):
        self.target_environments = target_environments

    def test_protection_effectiveness(self):
        """Test DOM XSS protection effectiveness"""
        protection_tests = {}
        
        for env in self.target_environments:
            tester = DOMXSSTester(env['url'], env['config'])
            results = tester.comprehensive_dom_xss_testing()
            
            protection_tests[env['name']] = {
                'input_validation_protection': self.test_input_validation_protection(results),
                'output_encoding_protection': self.test_output_encoding_protection(results),
                'csp_protection': self.test_csp_protection(results),
                'framework_protection': self.test_framework_protection(results),
                'overall_protection_score': self.calculate_protection_score(results)
            }
        
        return protection_tests
```

### 13 DOM-Based XSS Risk Assessment Matrix
```yaml
DOM-Based XSS Risk Assessment:
  Critical Risks:
    - Unauthenticated DOM XSS with direct script execution
    - Location.hash to innerHTML without sanitization
    - postMessage to eval without origin validation
    - AngularJS expression injection in untrusted contexts
    - React dangerouslySetInnerHTML with user input
    - jQuery html() method with unsanitized data
    - localStorage to eval without validation
    - DOM clobbering leading to script execution

  High Risks:
    - Multi-step DOM XSS requiring specific user actions
    - URL parameters to insecure DOM manipulation
    - Cookie values to innerHTML without encoding
    - Window.name persistence XSS
    - SessionStorage to script execution sinks
    - Complex data flow chains with insufficient validation
    - Framework-specific vectors with partial protection
    - Browser-specific DOM XSS vectors

  Medium Risks:
    - Self-DOM XSS requiring significant user interaction
    - Context-dependent DOM XSS with encoding requirements
    - Limited scope DOM XSS affecting specific functionality
    - PostMessage XSS with partial origin validation
    - Storage-based XSS with JSON parsing requirements
    - Mutation XSS requiring specific browser conditions
    - DOM clobbering with limited impact
    - Protocol handler XSS

  Low Risks:
    - Properly sanitized DOM operations
    - Strong Content Security Policy implementation
    - Comprehensive input validation
    - Context-aware output encoding
    - Framework security features enabled
    - Regular security testing coverage
    - Browser security controls effective
    - Client-side monitoring in place
```

### 14 DOM-Based XSS Protection Testing
```python
# DOM-Based XSS Protection Effectiveness Tester
class DOMXSSProtectionTester:
    def __init__(self, target_environments):
        self.target_environments = target_environments

    def test_protection_effectiveness(self):
        """Test DOM XSS protection effectiveness"""
        protection_tests = {}
        
        for env in self.target_environments:
            tester = DOMXSSTester(env['url'], env['config'])
            results = tester.comprehensive_dom_xss_testing()
            
            protection_tests[env['name']] = {
                'source_validation_protection': self.test_source_validation_protection(results),
                'sink_sanitization_protection': self.test_sink_sanitization_protection(results),
                'csp_protection': self.test_csp_protection(results),
                'framework_security_protection': self.test_framework_security_protection(results),
                'browser_security_protection': self.test_browser_security_protection(results),
                'overall_protection_score': self.calculate_protection_score(results)
            }
        
        return protection_tests

    def generate_protection_report(self):
        """Generate comprehensive protection report"""
        protection_tests = self.test_protection_effectiveness()
        
        report = {
            'protection_analysis': protection_tests,
            'security_gaps': self.identify_protection_gaps(protection_tests),
            'compliance_status': self.assess_dom_xss_compliance(),
            'improvement_recommendations': self.generate_protection_recommendations()
        }
        
        return report
```

### 15 DOM-Based XSS Remediation Checklist
```markdown
## ✅ DOM-BASED XSS SECURITY REMEDIATION CHECKLIST

### Source Validation:
- [ ] Implement strict validation for all DOM sources
- [ ] Validate URL parameters before DOM usage
- [ ] Sanitize location.hash and location.search
- [ ] Validate window.name and document.referrer
- [ ] Implement postMessage origin validation
- [ ] Sanitize localStorage and sessionStorage data
- [ ] Validate cookie values before DOM usage
- [ ] Regular source validation testing

### Sink Security:
- [ ] Avoid using dangerous sinks with untrusted data
- [ ] Implement safe alternatives to innerHTML/outerHTML
- [ ] Use textContent instead of innerHTML where possible
- [ ] Avoid eval, setTimeout, and setInterval with strings
- [ ] Use safe URL navigation methods
- [ ] Implement jQuery security best practices
- [ ] Use framework-safe DOM manipulation methods
- [ ] Regular sink security testing

### Content Security Policy:
- [ ] Implement strong CSP for DOM XSS protection
- [ ] Use script-src 'self' and 'unsafe-inline' prevention
- [ ] Implement object-src and base-uri restrictions
- [ ] Use frame-ancestors to prevent clickjacking
- [ ] Regular CSP configuration testing
- [ ] Monitor for CSP bypass attempts
- [ ] Implement CSP violation reporting
- [ ] Use strict CSP policies

### Framework Security:
- [ ] Use AngularJS strict contextual escaping
- [ ] Implement React JSX auto-escaping
- [ ] Use Vue.js v-text instead of v-html
- [ ] Implement safe DOM manipulation patterns
- [ ] Regular framework security testing
- [ ] Monitor for framework-specific vulnerabilities
- [ ] Implement secure data binding
- [ ] Use framework security features

### Client-Side Encoding:
- [ ] Implement context-aware client-side encoding
- [ ] Use HTML entity encoding for HTML contexts
- [ ] Apply JavaScript encoding for script contexts
- [ ] Implement URL encoding for URL parameters
- [ ] Use CSS encoding for style contexts
- [ ] Regular encoding implementation testing
- [ ] Monitor for encoding bypass attempts
- [ ] Implement automatic context detection

### PostMessage Security:
- [ ] Implement strict origin validation for postMessage
- [ ] Validate message structure and content
- [ ] Use specific message types and formats
- [ ] Implement message authentication where needed
- [ ] Regular postMessage security testing
- [ ] Monitor for postMessage abuse attempts
- [ ] Implement secure message handling
- [ ] Use secure cross-origin communication

### Storage Security:
- [ ] Validate all data before storage
- [ ] Implement storage data sanitization
- [ ] Use JSON validation for stored data
- [ ] Implement storage size limits
- [ ] Regular storage security testing
- [ ] Monitor for storage manipulation attempts
- [ ] Implement secure storage access patterns
- [ ] Use encryption for sensitive storage data

### Monitoring & Detection:
- [ ] Implement real-time DOM XSS detection
- [ ] Monitor for dangerous source-sink patterns
- [ ] Detect client-side validation bypass attempts
- [ ] Implement comprehensive client-side logging
- [ ] Regular security log analysis
- [ ] Monitor for CSP violation reports
- [ ] Continuous client-side security monitoring
- [ ] Implement automated response mechanisms
```

### 16 DOM-Based XSS Testing Completion Checklist
```markdown
## ✅ DOM-BASED XSS SECURITY TESTING COMPLETION CHECKLIST

### Source Identification:
- [ ] URL source testing completed
- [ ] Location object testing done
- [ ] Window object testing completed
- [ ] PostMessage source testing done
- [ ] Storage source testing completed
- [ ] Cookie source testing done
- [ ] Document source testing completed
- [ ] Custom source testing done

### Sink Identification:
- [ ] HTML injection sink testing completed
- [ ] Script execution sink testing done
- [ ] URL navigation sink testing completed
- [ ] DOM manipulation sink testing done
- [ ] jQuery sink testing completed
- [ ] Framework sink testing done
- [ ] Custom sink testing completed
- [ ] Third-party library sink testing done

### Data Flow Analysis:
- [ ] Direct source-sink flow testing completed
- [ ] Complex data flow testing done
- [ ] Multi-step propagation testing completed
- [ ] Function parameter flow testing done
- [ ] Object property flow testing completed
- [ ] Event handler flow testing done
- [ ] Callback chain testing completed
- [ ] Async data flow testing done

### Framework Testing:
- [ ] AngularJS testing completed
- [ ] React testing done
- [ ] Vue.js testing completed
- [ ] jQuery testing done
- [ ] Backbone.js testing completed
- [ ] Ember.js testing done
- [ ] Meteor testing completed
- [ ] Svelte testing done

### Advanced Technique Testing:
- [ ] Mutation XSS testing completed
- [ ] DOM clobbering testing done
- [ ] PostMessage XSS testing completed
- [ ] Storage XSS testing done
- [ ] Universal XSS testing completed
- [ ] Browser-specific XSS testing done
- [ ] Protocol handler testing completed
- [ ] Extension XSS testing done

### Protection Testing:
- [ ] Source validation testing completed
- [ ] Sink sanitization testing done
- [ ] CSP effectiveness testing completed
- [ ] Framework security testing done
- [ ] Encoding validation testing completed
- [ ] Validation bypass testing done
- [ ] Monitoring effectiveness testing completed
- [ ] Remediation validation testing done
```

### 17 DOM-Based XSS Executive Reporting Template
```markdown
# DOM-Based XSS Security Assessment Report

## Executive Summary
- **Assessment Scope:** [DOM XSS sources, sinks, and flows tested]
- **Assessment Period:** [Date range]
- **Testing Techniques Applied:** [Number and types of DOM XSS tests]
- **Critical Vulnerabilities:** [Critical findings count]
- **Overall Risk Level:** [High/Medium/Low]
- **Key Recommendations:** [Priority actions]

## Critical Findings
### [Critical Finding Title]
- **Vulnerability Type:** [Source-Sink Flow, Framework Vulnerability, etc.]
- **Risk Level:** Critical
- **Description:** [Detailed vulnerability description]
- **Impact:** [Potential security impact analysis]
- **Remediation Priority:** Immediate

## Technical Analysis
### DOM XSS Posture
- **Source Validation Vulnerabilities:** [Count and risk summary]
- **Sink Security Issues:** [Vulnerability count and severity]
- **Data Flow Security Gaps:** [Security gap count and impact]
- **Framework-Specific Vulnerabilities:** [Vulnerability count and severity]

### Protection Mechanism Assessment
- **Source Validation Effectiveness:** [Validation security rating]
- **Sink Security Quality:** [Sink security evaluation]
- **CSP Implementation Strength:** [CSP security assessment]
- **Framework Security Implementation:** [Framework security rating]

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
- [ ] [Fix critical DOM XSS vulnerabilities]
- [ ] [Implement strict source validation]
- [ ] [Apply sink security measures]

### Short-term Improvements (1-4 weeks)
- [ ] [Enhance Content Security Policy]
- [ ] [Implement comprehensive client-side validation]
- [ ] [Add DOM XSS detection and monitoring]

### Long-term Strategies (1-6 months)
- [ ] [Implement advanced DOM XSS protection framework]
- [ ] [Deploy comprehensive client-side security monitoring]
- [ ] [Establish regular DOM XSS security testing program]

## Compliance Status
- **Regulatory Compliance:** [NIST, OWASP, PCI DSS, etc. compliance level]
- **Industry Standards:** [Security standards alignment]
- **Internal Policies:** [Policy compliance evaluation]
- **Audit Readiness:** [Audit preparedness assessment]

## Security Maturity Assessment
- **DOM XSS Protection Maturity:** [Maturity level rating]
- **Source Validation Quality:** [Validation security score]
- **Sink Security Strength:** [Sink security rating]
- **Overall DOM XSS Protection:** [Comprehensive security assessment]

## Appendices
### Detailed Vulnerability Analysis
- Vulnerability descriptions and proof-of-concept
- Technical details and exploitation methods
- Risk classification and impact analysis
- Remediation guidance and references

### Testing Methodology
- Tools and techniques used
- Scope and limitations
- Testing environment details
- Quality assurance measures

### Risk Classification Matrix
- Risk scoring methodology
- Impact assessment criteria
- Likelihood evaluation framework
- Remediation priority guidelines
```

This comprehensive DOM-Based XSS Testing framework provides complete methodology for identifying, assessing, and mitigating DOM-based cross-site scripting vulnerabilities across web applications, single-page applications, and modern JavaScript frameworks. The testing approach covers source identification, sink detection, data flow analysis, framework-specific testing, advanced techniques, and protection mechanisms to prevent client-side script injection, session hijacking, and client-side compromise through robust source validation, sink security, Content Security Policy, and comprehensive client-side security controls implementation.