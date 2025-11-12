
## 🎯 CLIENT-SIDE SECURITY TESTING MASTER LIST

### 11.1 DOM-BASED XSS TESTING
    - Identifying DOM-based XSS vulnerabilities
    - Analyzing document.write/sink sources
    - Testing hash/fragment injection vectors
    - Evaluating innerHTML/textContent manipulation
    - Checking URL parameter DOM injection
    - Testing jQuery sink vulnerabilities
    - AngularJS expression injection testing
    - Vue.js template injection analysis
    - React JSX injection evaluation
    - DOM clobbering attack scenarios

### 11.1.1 SELF-DOM XSS TESTING
    - Identifying same-origin DOM manipulation
    - Testing self-contained DOM injection
    - Evaluating postMessage self-XSS vectors
    - Analyzing storage-based self-XSS
    - Checking reflected self-DOM XSS
    - Testing cookie-based self-execution
    - LocalStorage/SessionStorage self-XSS
    - IndexedDB self-contained XSS testing
    - Service Worker DOM manipulation
    - Blob URL self-XSS evaluation

### 11.2 JAVASCRIPT EXECUTION TESTING
    - Testing eval()/Function() injection
    - setTimeout/setInterval code injection
    - JavaScript URI scheme execution
    - Event handler injection (onclick/onload)
    - Template literal injection
    - Dynamic script tag injection
    - import()/require() dynamic inclusion
    - WebWorker JS execution testing
    - WASM module injection analysis
    - JavaScript obfuscation bypass techniques

### 11.3 HTML INJECTION TESTING
    - Testing unescaped HTML output
    - SVG file HTML injection vectors
    - MathML injection possibilities
    - Custom element name injection
    - Attribute injection testing
    - Form action hijacking
    - Meta tag injection
    - Iframe source injection
    - Object/embed tag testing
    - Template injection attacks

### 11.4 CLIENT-SIDE URL REDIRECT
    - Testing open redirect vulnerabilities
    - Analyzing window.location manipulation
    - Header injection redirects (Location:)
    - meta refresh tag abuse
    - JavaScript redirect testing (href.replace)
    - History API manipulation
    - Document.domain modification
    - PostMessage redirect hijacking
    - Service Worker redirect hijacking
    - OAuth token theft via redirects

### 11.5 CSS INJECTION TESTING
    - Testing style tag injection
    - Attribute selectors for data exfiltration
    - @import CSS rule injection
    - JavaScript URL in stylesheets
    - CSS expression() evaluation
    - @font-face SSRF testing
    - :hover/:active pseudo-class abuse
    - CSS keylogger techniques
    - CSS-based UI redressing
    - Styled XSS payload delivery

### 11.6 CLIENT-SIDE RESOURCE MANIPULATION
    - Testing resource override vulnerabilities
    - Manifest.json tampering
    - Service Worker script hijacking
    - Webpack module.hot abuse
    - Import map manipulation
    - JSONP callback hijacking
    - Static asset modification
    - CDN cache poisoning
    - Subresource Integrity bypass
    - Web bundle manipulation

### 11.7 CORS TESTING
    - Testing misconfigured Access-Control-Allow-Origin
    - Credentialed CORS requests
    - Null origin abuse
    - Preflight request bypass
    - Trusted origin regex flaws
    - Internal network CORS abuse
    - WebSocket CORS bypass
    - Blob URL CORS implications
    - CORS with credentialed cookies
    - CORS via XSS combined attacks

### 11.8 CROSS-SITE FLASHING
    - Testing Flash cross-domain policy
    - Cross-origin Flash embedding
    - getURL()/navigateToURL() abuse
    - ExternalInterface.call exploits
    - Flash parameter injection
    - SWF reflection attacks
    - Flash local storage abuse
    - Flash cookie manipulation
    - Flash WebSocket hijacking
    - Flash to JavaScript bridge attacks

### 11.9 CLICKJACKING TESTING
    - Testing frame busting protections
    - X-Frame-Options bypass techniques
    - CSP frame-ancestors evaluation
    - UI redressing techniques
    - Drag-and-drop clickjacking
    - Multi-stage clickjacking
    - Touch event hijacking
    - Keyboard event hijacking
    - File upload clickjacking
    - Invisible overlay techniques

### 11.10 WEBSOCKETS TESTING
    - Testing unencrypted WS:// usage
    - Origin validation bypass
    - Message injection testing
    - Cross-site WebSocket hijacking
    - Binary data manipulation
    - Subprotocol negotiation flaws
    - WebSocket CSRF testing
    - Rate limiting absence
    - Compression side channels
    - Session fixation via WS

### 11.11 WEB MESSAGING TESTING
    - postMessage origin validation flaws
    - Testing message event handlers
    - BroadcastChannel abuse
    - SharedWorker message passing
    - Service Worker message interception
    - Cross-origin communication risks
    - Message event source spoofing
    - Data exfiltration via messaging
    - Denial of service via messaging
    - Client-side storage via messaging

### 11.12 BROWSER STORAGE TESTING
    - LocalStorage/SessionStorage XSS
    - IndexedDB injection testing
    - WebSQL injection vectors
    - Cache API manipulation
    - Cookie security attributes
    - Partitioned storage testing
    - Storage quota abuse
    - Serialization format attacks
    - Storage event hijacking
    - Service Worker cache poisoning

### 11.13 XSSI TESTING
    - JSONP callback injection
    - JavaScript file inclusion
    - CSRF via static JS includes
    - AngularJS sandbox escapes
    - Prototype pollution via XSSI
    - Cache probing via script tags
    - CSP bypass via trusted scripts
    - Same-origin policy bypasses
    - Import map abuse
    - Module namespace pollution

### 11.14 REVERSE TABNABBING
    - Testing window.opener access
    - noopener/noreferrer evaluation
    - Cross-origin opener policy
    - document.referrer leakage
    - PostMessage-based tabnabbing
    - History manipulation attacks
    - Location.href spoofing
    - Phishing via tab switching
    - Combined clickjacking vectors
    - Browser UI spoofing

### 11.15 CLIENT-SIDE TEMPLATE INJECTION
    - AngularJS sandbox escape testing
    - Vue.js template injection vectors
    - React JSX injection scenarios
    - Handlebars/SafeString evaluation
    - Jade/Pug template compilation
    - Template literal injection
    - Dynamic code generation analysis
    - Prototype pollution in templates
    - DOM clobbering via templates
    - Server-side/client-side template confusion
