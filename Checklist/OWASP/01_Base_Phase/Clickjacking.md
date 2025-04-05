# ULTIMATE CLICKJACKING TESTING CHECKLIST (v1.0)

### Comprehensive Methodology for UI Redress Attacks

### 🛡️ DEFENSE DETECTION

    - Check for X-Frame-Options header - Test with DENY, SAMEORIGIN, ALLOW-FROM
    - Verify Content-Security-Policy (CSP) frame-ancestors - Test with 'none', 'self', or domain whitelist
    - Check for legacy framebusting JavaScript
    - Verify if site works when loaded in iframe
    - Test with multiple browsers (Chrome, Firefox, Safari)

### 🧩 BASIC ATTACK VECTORS

    - Test with transparent overlay iframe
    - Verify drag-and-drop clickjacking
    - Check cursorjacking (position manipulation)
    - Test with double iframe nesting
    - Verify mouse movement tracking

### 🔍 ADVANCED TECHNIQUES

    - Test with opacity:0 iframes
    - Verify position:absolute/fixed attacks
    - Check viewport-based attacks
    - Test with zoom/scale CSS manipulation
    - Verify scrollbar manipulation
    - Check keyboard event hijacking
    - Test touch event hijacking (mobile)
    - Verify file upload clickjacking
    - Check cross-domain iframe communication
    - Test with Safari legacy behaviors

### 🛠️ TESTING METHODOLOGY

    - Create basic PoC HTML page
    - Gradually increase iframe opacity for testing
    - Test with Burp Suite Clickbandit
    - Verify with OWASP Zap clickjacking scanner
    - Check with browser developer tools
    - Test multiple page states (login, forms)
    - Verify dynamic content loading
    - Check AJAX-heavy applications
    - Test single-page applications (SPAs)
    - Verify WebSocket interactions

### ⚠️ DANGEROUS SCENARIOS

    - Test login button hijacking
    - Verify form submission hijacking
    - Check password manager interaction
    - Test payment flow manipulation
    - Verify social media sharing hijack
    - Check "like" button manipulation
    - Test file download interception
    - Verify permission grant dialogs
    - Check OAuth authorization flows
    - Test biometric authentication bypass

### 📝 REPORTING

    - Document missing security headers
    - Record effective framebusting bypasses
    - Note business impact scenarios
    - Document user interaction sequences
    - Provide visual PoC (screenshot/video)
    - Include reproducible HTML test case
    - Note browser-specific behaviors
    - Document session handling issues
    - Report CSRF-clickjacking combinations
    - Provide remediation guidance

### 🛠️ REMEDIATION

    - Recommend X-Frame-Options: DENY
    - Suggest CSP frame-ancestors policy
    - Advocate for modern framebusting JS
    - Propose UI confirmation dialogs
    - Suggest visual anti-CJ measures
    - Recommend session timeout reduction
    - Advocate for sensitive action CAPTCHAs
    - Propose user interaction monitoring
    - Suggest Content-DPR header
    - Recommend regular retesting

### 🌐 SPECIAL CASES

    - Test cross-origin iframe communication
    - Verify postMessage() vulnerabilities
    - Check CORS misconfigurations
    - Test with sandboxed iframes
    - Verify same-site cookie protections
    - Check mobile-specific implementations
    - Test browser extension interactions
    - Verify WebView implementations
    - Check Electron/CEF applications
    - Test WebRTC interactions

### 🔮 FUTURE PROTECTIONS

    - Test with Permissions-Policy header
    - Verify COEP/COOP headers
    - Check Cross-Origin-Opener-Policy
    - Test Trusted Types protection
    - Verify sameSite cookie attributes
    - Check Referrer-Policy headers
    - Test Feature-Policy restrictions
    - Verify document.domain handling
    - Check Shadow DOM vulnerabilities
    - Recommend ongoing clickjacking audits
