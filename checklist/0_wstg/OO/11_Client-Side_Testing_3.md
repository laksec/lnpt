## 🎯 CLIENT-SIDE SECURITY TESTING MASTER LIST

### 11.31 BROWSER EXTENSION RISKS
    - Content script injection
    - Background page manipulation
    - Cross-extension attacks
    - Permission escalation
    - Message passing flaws
    - Storage synchronization risks
    - Extension CSP bypasses
    - WebAccessibleResources abuse
    - DeclarativeNetRequest bypass
    - Extension update hijacking

### 11.32 AUTHENTICATION TOKEN THEFT
    - localStorage token harvesting
    - Session cookie extraction
    - OAuth token interception
    - JWT replay attacks
    - Refresh token abuse
    - Bearer token leakage
    - CSRF token prediction
    - SAML assertion theft
    - OpenID Connect flaws
    - WebAuthn bypass techniques

### 11.33 CLIENT-SIDE RATE LIMIT BYPASS
    - IP rotation via WebRTC
    - Browser fingerprint spoofing
    - Storage-based request tracking
    - WebSocket flood attacks
    - Event loop manipulation
    - setTimeout/setInterval abuse
    - WebWorker parallel requests
    - Service Worker cache bypass
    - Beacon API exploitation
    - Fetch API abort controller abuse

### 11.34 CLIENT-SIDE REQUEST SMUGGLING
    - Browser HTTP stack differences
    - CRLF injection in fetch()
    - Header name normalization
    - Chunked encoding abuse
    - Connect-time poisoning
    - Browser cache poisoning
    - H2C upgrade attacks
    - Request splitting via CORS
    - Preflight request smuggling
    - Early request termination

### 11.35 PRIVATE NETWORK ATTACKS
    - Localhost port scanning
    - RFC1918 address probing
    - mDNS/LLMNR spoofing
    - WebRTC internal IP leaks
    - HSTS preload bypass
    - CORS private network access
    - Cloud metadata API abuse
    - Browser proxy detection
    - VPN IP leakage
    - WiFi captive portal abuse

### 11.36 CLIENT-SIDE SUPPLY CHAIN ATTACKS
    - NPM package hijacking
    - CDN resource poisoning
    - Typo-squatting attacks
    - Dependency confusion
    - Package.json override
    - Webpack module hijacking
    - Babel plugin compromise
    - Third-party script abuse
    - CSP nonce leakage
    - SRI hash collision

### 11.37 BROWSER JIT EXPLOITATION
    - JavaScript engine vulnerabilities
    - Type confusion attacks
    - Array prototype pollution
    - JIT spray techniques
    - Wasm JIT bypasses
    - Turbofan exploitation
    - Ignition bytecode abuse
    - SpiderMonkey weaknesses
    - JavaScriptCore flaws
    - V8 engine sandbox escapes

### 11.38 CLIENT-SIDE SSRF TECHNIQUES
    - fetch() internal network probing
    - WebSocket localhost scanning
    - img-src internal IP leaks
    - video-src port scanning
    - SVG foreignObject abuse
    - XHR withCredentials abuse
    - DNS rebinding attacks
    - Browser protocol handlers
    - iframe srcdoc exploitation
    - Blob URL internal access

### 11.39 CLIENT-SIDE INPUT VALIDATION BYPASS
    - HTML5 form override
    - input pattern attribute bypass
    - maxlength DOM manipulation
    - File type spoofing
    - Client-side validation stripping
    - disabled attribute removal
    - hidden input modification
    - checkbox/radio state abuse
    - select option injection
    - color picker manipulation

### 11.40 BROWSER SANDBOX ESCAPES
    - WebAssembly memory abuse
    - SharedArrayBuffer timing
    - WebGPU low-level access
    - WebAudio sample rate leaks
    - FileSystem Access API abuse
    - WebNFC hardware access
    - WebHID device control
    - WebSerial port access
    - WebUSB endpoint abuse
    - Web Bluetooth exploits

### 11.41 CLIENT-SIDE PROTOCOL HANDLERS
    - Testing custom URI scheme abuse
    - mailto: parameter injection
    - tel: URI command injection
    - sms: phishing techniques
    - whatsapp: deep link abuse
    - intent: Android scheme hijacking
    - feed: subscription attacks
    - magnet: torrent manipulation
    - web+ schemes exploitation
    - registerProtocolHandler abuse

### 11.42 WEB PUSH NOTIFICATION VULNERABILITIES
    - Notification spoofing attacks
    - Silent push abuse
    - Notification clickjacking
    - Badge manipulation
    - Vibration API abuse
    - Notification data leaks
    - Subscription hijacking
    - Push message encryption flaws
    - Notification permission fatigue
    - Service Worker push event abuse

### 11.43 CLIENT-SIDE CRYPTO IMPLEMENTATION FLAWS
    - WebCrypto API misuse
    - SubtleCrypto timing attacks
    - RSA key generation weaknesses
    - ECDSA nonce reuse
    - AES-GCM IV reuse
    - PBKDF2 weak iterations
    - localStorage key storage
    - JavaScript crypto library flaws
    - Math.random() predictability
    - Entropy source weaknesses

### 11.44 CLIENT-SIDE DATA EXFILTRATION TECHNIQUES
    - DNS prefetch exfiltration
    - Beacon API data leakage
    - CSS selector exfiltration
    - Error message leaks
    - Timing attacks for data theft
    - Favicon-based exfiltration
    - SVG filter data leaks
    - WebRTC STUN server abuse
    - Battery API information leaks
    - Clipboard exfiltration

### 11.45 BROWSER STORAGE QUOTA ABUSE
    - localStorage quota exhaustion
    - IndexedDB object store flooding
    - Cache API storage bombing
    - Service Worker cache overflow
    - FileSystem API abuse
    - WebSQL database flooding
    - Cookie jar overflow
    - Blob storage exhaustion
    - Origin private file system abuse
    - Storage pressure events