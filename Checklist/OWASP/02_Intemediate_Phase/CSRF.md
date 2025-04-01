# ULTIMATE CSRF TESTING CHECKLIST (v1.0)

## Techniques for Finding CSRF Vulnerabilities

### 🌐 RECONNAISSANCE

    - Identify all state-changing requests (POST/PUT/DELETE)

    - Map all form submissions in the application

    - Document all sensitive actions (password change, email update)

    - Find all API endpoints that modify data

    - Check for administrative functions exposed to users

    - Identify password reset functionality

    - Locate email change requests

    - Find user profile update endpoints

    - Discover account deletion features

    - Check payment processing forms

    - Identify address book modifications

    - Locate permission/role change functions

    - Find two-factor authentication settings

    - Check API key generation endpoints

    - Identify all file upload functionality

    - Locate comment/forum posting endpoints

    - Find voting/poll submission forms

    - Check shopping cart modifications

    - Identify wishlist management

    - Locate subscription management

    - Find social media sharing features

    - Check contact form submissions

    - Identify survey response endpoints

    - Locate support ticket creation

    - Find document signing features

    - Check approval workflow endpoints

    - Identify data export requests

    - Locate import functionality

    - Find system configuration changes

    - Check notification preferences

    - Identify all GET requests that change state

    - Locate logout functionality

    - Find session extension endpoints

    - Check "remember me" features

    - Identify password hint questions

    - Locate security question updates

    - Find backup code generation

    - Check recovery email updates

    - Identify connected app integrations

    - Locate OAuth authorization endpoints

    - Find third-party service connections

    - Check webhook configuration

    - Identify SSO configuration

    - Locate federation settings

    - Find device management

    - Check location tracking settings

    - Identify privacy preferences

    - Locate data sharing controls

    - Find advertisement preferences

    - Check newsletter subscriptions

### 🛡️ CSRF PROTECTION ANALYSIS

    - Verify presence of CSRF tokens

    - Check if tokens are bound to user session

    - Test if tokens are predictable

    - Verify token randomness

    - Check if tokens are single-use

    - Test token expiration time

    - Verify token validation on server

    - Check for token leakage in logs

    - Test if tokens are in GET parameters

    - Verify Referer header validation

    - Test Referer header stripping

    - Check Origin header validation

    - Test Origin header spoofing

    - Verify SameSite cookie attribute

    - Test SameSite=None bypasses

    - Check for custom headers (X-Requested-With)

    - Test header stripping vulnerabilities

    - Verify double-submit cookie pattern

    - Test encrypted token patterns

    - Check HMAC-protected requests

    - Verify state parameters in OAuth

    - Test OAuth state parameter bypass

    - Check for CAPTCHA protections

    - Verify re-authentication requirements

    - Test password confirmation bypass

    - Check for transaction signing

    - Verify one-time token usage

    - Test time-limited tokens

    - Check IP address binding

    - Verify user-agent validation

    - Test browser fingerprint checks

    - Check for challenge-response

    - Verify Proof-of-Work requirements

    - Test rate limiting on sensitive actions

    - Check concurrent request handling

    - Verify session timeout enforcement

    - Test session fixation vulnerabilities

    - Check for logout CSRF protections

    - Verify cache-control headers

    - Test clickjacking protections

    - Check frame-busting scripts

    - Verify X-Frame-Options header

    - Test Content-Security-Policy frame-ancestors

    - Check for form autocomplete=off

    - Verify secure flag on cookies

    - Test HttpOnly cookie flag

    - Check for DOM-based CSRF

    - Verify CORS restrictions

    - Test JSON CSRF with Flash

    - Check for Flash-based protections

### ⚔️ CSRF EXPLOITATION TECHNIQUES

    - Test basic form submission CSRF

    - Verify GET request CSRF

    - Test JSON POST CSRF

    - Verify XML POST CSRF

    - Test multipart form CSRF

    - Verify file upload CSRF

    - Test AJAX request CSRF

    - Verify fetch() API CSRF

    - Test WebSocket CSRF

    - Verify Server-Sent Events CSRF

    - Test GraphQL CSRF

    - Verify gRPC CSRF

    - Test REST API CSRF

    - Verify SOAP API CSRF

    - Test XML-RPC CSRF

    - Verify JSON-RPC CSRF

    - Test OAuth authorization CSRF

    - Verify SAML assertion CSRF

    - Test OpenID Connect CSRF

    - Verify JWT CSRF

    - Test cookie-based CSRF

    - Verify localStorage CSRF

    - Test sessionStorage CSRF

    - Verify IndexedDB CSRF

    - Test WebSQL CSRF

    - Verify Cache API CSRF

    - Test Service Worker CSRF

    - Verify Web Worker CSRF

    - Test Shared Worker CSRF

    - Verify iframe CSRF

    - Test popup window CSRF

    - Verify tabnabbing CSRF

    - Test window.opener CSRF

    - Verify postMessage CSRF

    - Test Broadcast Channel CSRF

    - Verify WebRTC CSRF

    - Test WebUSB CSRF

    - Verify Web Bluetooth CSRF

    - Test Web NFC CSRF

    - Verify Web MIDI CSRF

    - Test Gamepad API CSRF

    - Verify Device Orientation CSRF

    - Test Geolocation CSRF

    - Verify Payment Request CSRF

    - Test Credential Management CSRF

    - Verify Web Authentication CSRF

    - Test Clipboard API CSRF

    - Verify Drag and Drop CSRF

    - Test Fullscreen API CSRF

    - Verify Pointer Lock CSRF

    - Test Vibration API CSRF

    - Verify Battery Status CSRF

    - Test Network Info CSRF

    - Verify Presentation API CSRF

    - Test Remote Playback CSRF

    - Verify Web Share API CSRF

    - Test Contact Picker CSRF

    - Verify Badging API CSRF

    - Test Idle Detection CSRF

    - Verify Web Locks CSRF

    - Test File System Access CSRF

    - Verify WebHID CSRF

    - Test Web Serial CSRF

    - Verify WebGPU CSRF

    - Test WebNN CSRF

    - Verify WebTransport CSRF

    - Test WebCodecs CSRF

    - Verify WebAssembly CSRF

    - Test WebGL CSRF

    - Verify Canvas CSRF

    - Test SVG CSRF

    - Verify MathML CSRF

    - Test Web Components CSRF

    - Verify Shadow DOM CSRF

    - Test Custom Elements CSRF

    - Verify HTML Templates CSRF

    - Test HTML Imports CSRF

    - Verify Polymer CSRF

    - Test Angular CSRF

    - Verify React CSRF

    - Test Vue CSRF

    - Verify Ember CSRF

    - Test Svelte CSRF

    - Verify Meteor CSRF

    - Test Backbone CSRF

    - Verify Knockout CSRF

    - Test Alpine CSRF

    - Verify Stimulus CSRF

    - Test Lit CSRF

    - Verify Stencil CSRF

    - Test Preact CSRF

    - Verify Solid CSRF

    - Test Marko CSRF

    - Verify Mithril CSRF

    - Test Riot CSRF

    - Verify Inferno CSRF

    - Test Cycle CSRF

    - Verify Elm CSRF

    - Test ClojureScript CSRF

    - Verify ReasonML CSRF

### 🛡️ CSRF MITIGATION TESTING

    - Verify token per-form implementation

    - Test token per-request validation

    - Check token synchronization

    - Verify token cryptographically signed

    - Test token replay attacks

    - Check token expiration enforcement

    - Verify token binding to session

    - Test token binding to IP

    - Check token binding to user-agent

    - Verify token binding to device

    - Test token scope limitations

    - Check token path restrictions

    - Verify token domain restrictions

    - Test token port restrictions

    - Check token protocol restrictions

    - Verify token HTTP method binding

    - Test token action binding

    - Check token parameter binding

    - Verify token nonce implementation

    - Test token timestamp validation

    - Check token sequence numbers

    - Verify token one-time usage

    - Test token revocation

    - Check token blacklisting

    - Verify token refresh mechanism

    - Test token rotation

    - Check token key derivation

    - Verify token encryption

    - Test token compression

    - Check token encoding

    - Verify token transport security

    - Test token storage security

    - Check token generation entropy

    - Verify token PRNG quality

    - Test token prediction resistance

    - Check token side-channel resistance

    - Verify token fault injection resistance

    - Test token timing attacks

    - Check token power analysis resistance

    - Verify token EM analysis resistance

    - Test token acoustic analysis resistance

    - Check token optical analysis resistance

    - Verify token thermal analysis resistance

    - Test token glitch attacks

    - Check token fault attacks

    - Verify token DPA resistance

    - Test token SPA resistance

    - Check token DFA resistance

    - Verify token SFA resistance

    - Test token LPA resistance

### 🔄 CSRF CHAINING TECHNIQUES

    - Test CSRF to XSS chaining

    - Verify CSRF to SSRF chaining

    - Test CSRF to RCE chaining

    - Verify CSRF to LFI chaining

    - Test CSRF to RFI chaining

    - Verify CSRF to SQLi chaining

    - Test CSRF to XXE chaining

    - Verify CSRF to redirect chaining

    - Test CSRF to file upload chaining

    - Verify CSRF to auth bypass chaining

    - Test CSRF to privilege escalation

    - Verify CSRF to info disclosure

    - Test CSRF to DoS chaining

    - Verify CSRF to business logic chaining

    - Test CSRF to payment bypass

    - Verify CSRF to coupon abuse

    - Test CSRF to inventory manipulation

    - Verify CSRF to price manipulation

    - Test CSRF to auction tampering

    - Verify CSRF to bidding manipulation

    - Test CSRF to review manipulation

    - Verify CSRF to rating manipulation

    - Test CSRF to poll manipulation

    - Verify CSRF to survey manipulation

    - Test CSRF to contest manipulation

    - Verify CSRF to lottery manipulation

    - Test CSRF to drawing manipulation

    - Verify CSRF to giveaway manipulation

    - Test CSRF to sweepstakes manipulation

    - Verify CSRF to promotion manipulation

    - Test CSRF to membership manipulation

    - Verify CSRF to subscription manipulation

    - Test CSRF to service manipulation

    - Verify CSRF to plan manipulation

    - Test CSRF to tier manipulation

    - Verify CSRF to level manipulation

    - Test CSRF to status manipulation

    - Verify CSRF to role manipulation

    - Test CSRF to permission manipulation

    - Verify CSRF to access manipulation

    - Test CSRF to ACL manipulation

    - Verify CSRF to policy manipulation

    - Test CSRF to configuration manipulation

    - Verify CSRF to settings manipulation

    - Test CSRF to preference manipulation

    - Verify CSRF to option manipulation

    - Test CSRF to feature manipulation

    - Verify CSRF to toggle manipulation

    - Test CSRF to switch manipulation

    - Verify CSRF to flag manipulation
