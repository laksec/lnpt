# ULTIMATE XSS TESTING CHECKLIST

## Focused on Methodology Without Code Snippets

### 🌐 RECONNAISSANCE PHASE

    - Identify all user-input entry points including search fields, comment sections, and contact forms

    - Locate every URL parameter that gets reflected in the page response

    - Document all form submissions that display user-provided data back to the user

    - Find hidden parameters by analyzing client-side JavaScript and network traffic

    - Identify all cookie values that get reflected in HTML responses

    - Locate API endpoints that return user-supplied data in their responses

    - Discover file upload functionality that may allow HTML/JS file uploads

    - Check for user profile fields that get displayed to other users

    - Identify chat/messaging systems that display raw user input

    - Locate administrative interfaces that might be vulnerable to stored XSS

    - Find CSV/PDF generators that might inject user input into documents

    - Identify error messages that reflect user-provided data

    - Locate login/registration forms with username enumeration features

    - Discover password reset functionality that reflects email/username

    - Find survey/feedback forms that display user submissions

    - Identify e-commerce product review systems

    - Locate forum/comment systems with rich text editing

    - Find user dashboard elements that display unescaped data

    - Identify newsletter subscription forms with confirmation messages

    - Locate search functionality with reflected results

    - Discover autocomplete/search suggestion endpoints

    - Find social media sharing features that accept URLs

    - Identify "share with friend" email forms

    - Locate user preference panels that display saved values

    - Find shopping cart systems that reflect product details

    - Identify wishlist functionality that shows user input

    - Locate auction/bidding interfaces with user-provided data

    - Find survey tools embedded in the application

    - Identify customer support ticket systems

    - Locate user profile pages with custom bios/descriptions

    - Find document annotation/commenting systems

    - Identify collaborative editing features

    - Locate real-time chat applications

    - Find notification systems that display user data

    - Identify user dashboard widgets with dynamic content

    - Locate reporting systems that reflect input parameters

    - Find data export functionality that includes user input

    - Identify calendar/event systems with user-provided details

    - Locate map applications with custom markers/popups

    - Find document generation tools (invoices, reports)

    - Identify email template editors

    - Locate form builder/preview functionality

    - Find quiz/test applications showing user answers

    - Identify voting/polling systems showing results

    - Locate e-signature platforms with custom messages

    - Find workflow/approval systems with comments

    - Identify knowledge base/article comment sections

    - Locate product customization tools

    - Find event registration systems with confirmation pages

    - Identify all third-party integrations that handle user data

### 🔍 REFLECTED XSS TECHNIQUES

    - Test all URL parameters with basic script tag payloads

    - Verify if angle brackets are filtered or encoded

    - Check if quote characters are properly escaped

    - Test for JavaScript URI schemes in redirect parameters

    - Verify if forward slashes are filtered in tags

    - Check if spaces are converted to other characters

    - Test for case sensitivity in tag filtering

    - Verify if event handlers are stripped from elements

    - Check for unusual tag filtering patterns

    - Test if comments can bypass filters

    - Verify if hex encoding bypasses input filters

    - Check if HTML entity encoding works

    - Test for Unicode normalization issues

    - Verify if UTF-7 encoding can be exploited

    - Check for string concatenation vulnerabilities

    - Test if JavaScript functions can be broken up

    - Verify if arithmetic operations bypass filters

    - Check for template literal vulnerabilities

    - Test for indirect eval() execution

    - Verify if setTimeout/setInterval can execute strings

    - Check for Function constructor exploitation

    - Test for prototype pollution vectors

    - Verify if with() statements bypass sanitization

    - Check for JavaScript pseudo-protocol execution

    - Test for vbscript: protocol execution in IE

    - Verify if data: URIs can execute scripts

    - Check for about:blank frame injection

    - Test for jar: protocol exploitation

    - Verify if view-source: can be abused

    - Check for nested execution contexts

    - Test for improper HTML5 sandboxing

    - Verify if srcdoc attributes are filtered

    - Check for iframe injection possibilities

    - Test for object/embed tag exploitation

    - Verify if applet/archive tags work

    - Check for base tag manipulation

    - Test for meta tag refresh abuse

    - Verify if link tags can execute scripts

    - Check for style tag CSS expression abuse

    - Test for SVG tag script execution

    - Verify if mathml tags can be exploited

    - Check for custom tag processing

    - Test for HTML5 drag/drop event abuse

    - Verify if web components can be abused

    - Check for shadow DOM manipulation

    - Test for template tag vulnerabilities

    - Verify if inert attribute bypasses filters

    - Check for dialog element exploitation

    - Test for details/summary tag abuse

    - Verify if picture/source tags can be exploited

    - Check for video/audio tag onerror events

    - Test for track tag vulnerabilities

    - Verify if sourcemap references can be abused

    - Check for preload header manipulation

    - Test for CSP header bypasses

### 💾 STORED XSS TECHNIQUES

    - Test all user profile fields for persistent injection

    - Verify comment sections for unescaped output

    - Check file uploads for HTML/JS file execution

    - Test message boards for persistent payloads

    - Verify product reviews for script injection

    - Check support tickets for stored XSS

    - Test contact forms for admin interface exposure

    - Verify user avatars for script execution

    - Check signature fields for persistent payloads

    - Test forum signatures for XSS

    - Verify "about me" sections in profiles

    - Check status update functionality

    - Test private messaging systems

    - Verify notification preferences

    - Check dashboard widgets configuration

    - Test saved search functionality

    - Verify email template editors

    - Check document annotation systems

    - Test collaborative editing features

    - Verify real-time chat systems

    - Check calendar event descriptions

    - Test meeting scheduling systems

    - Verify poll/survey creation tools

    - Check quiz/test question fields

    - Test e-learning course content

    - Verify knowledge base articles

    - Check FAQ management systems

    - Test blog post commenting

    - Verify news/article commenting

    - Check product description fields

    - Test inventory item details

    - Verify shopping cart notes

    - Check wishlist item comments

    - Test auction item descriptions

    - Verify bidding comment systems

    - Check donation message fields

    - Test event registration forms

    - Verify ticket booking systems

    - Check hotel/reservation systems

    - Test travel itinerary notes

    - Verify food delivery instructions

    - Check medical record notes

    - Test patient portal messaging

    - Verify insurance claim forms

    - Check financial transaction memos

    - Test banking transfer descriptions

    - Verify investment portfolio notes

    - Check tax filing comments

    - Test legal document annotations

    - Verify contract clause fields

    - Check e-signature comment boxes

    - Test workflow approval comments

    - Verify project management tasks

    - Check bug tracking systems

    - Test help desk ticket systems

    - Verify CRM contact notes

    - Check marketing campaign content

    - Test newsletter editor content

    - Verify social media integrations

    - Check API documentation examples

    - Test webhook configuration

    - Verify third-party integrations

    - Check analytics tracking codes

    - Test tag management systems

    - Verify A/B testing tools

    - Check heatmap recording

    - Test session replay tools

    - Verify customer feedback widgets

    - Check live chat transcripts

    - Test chatbot configuration

    - Verify voice assistant skills

    - Check IoT device naming

    - Test smart home controls

    - Verify vehicle telemetry

    - Check industrial control systems

### 🧠 DOM-BASED XSS TECHNIQUES

    - Test location.hash manipulation

    - Verify window.name exploitation

    - Check postMessage handling

    - Test document.write usage

    - Verify innerHTML assignments

    - Check outerHTML manipulation

    - Test insertAdjacentHTML calls

    - Verify jQuery html() methods

    - Check DOMParser output

    - Test createContextualFragment

    - Verify Range.createContextualFragment

    - Check eval() usage patterns

    - Test Function constructor calls

    - Verify setTimeout string usage

    - Check setInterval string usage

    - Test script.src manipulation

    - Verify iframe.src assignments

    - Check object.data assignments

    - Test embed.src assignments

    - Verify applet/archive attributes

    - Check meta refresh values

    - Test base href manipulation

    - Verify link href assignments

    - Check a href attributes

    - Test area href attributes

    - Verify form action attributes

    - Check input formaction

    - Test button formaction

    - Verify frame src assignments

    - Check iframe srcdoc content

    - Test object param values

    - Verify embed attribute values

    - Check applet parameter values

    - Test SVG script content

    - Verify mathml script usage

    - Check HTML5 sandbox bypasses

    - Test CSP nonce reuse

    - Verify strict-dynamic bypasses

    - Check AngularJS sandbox escapes

    - Test Vue.js template injection

    - Verify React JSX injection

    - Check Ember.js template issues

    - Test Meteor client-side vulns

    - Verify Backbone.js rendering

    - Check Knockout.js bindings

    - Test Polymer component issues

    - Verify Web Components security

    - Check Shadow DOM boundaries

    - Test template tag usage

    - Verify custom element behavior

    - Check HTML imports security

    - Test data binding frameworks

    - Verify model-view patterns

    - Check single-page app routing

    - Test history API manipulation

    - Verify pushState handling

    - Check replaceState usage

    - Test hashchange events

    - Verify popstate events

    - Check beforeunload events

    - Test message event handling

    - Verify storage events

    - Check indexedDB access

    - Test localStorage usage

    - Verify sessionStorage access

    - Check cookie manipulation

    - Test WebSQL injection

    - Verify Cache API security

    - Check Service Worker scripts

    - Test Web Worker communication

    - Verify Shared Worker access

    - Check Broadcast Channel API

    - Test WebSocket message handling

    - Verify EventSource security

    - Check WebRTC data channels

    - Test WebUSB interface

    - Verify Web Bluetooth API

    - Check Web NFC access

    - Test Web MIDI API

    - Verify Gamepad API

    - Check Device Orientation

    - Test Geolocation API

    - Verify Payment Request API

    - Check Credential Mgmt API

    - Test Web Authentication API

    - Verify Clipboard API

    - Check Drag and Drop API

    - Test Fullscreen API

    - Verify Pointer Lock API

    - Check Vibration API

    - Test Battery Status API

    - Verify Network Info API

    - Check Presentation API

    - Test Remote Playback API

    - Verify Web Share API

    - Check Contact Picker API

    - Test Badging API

    - Verify Idle Detection

    - Check Web Locks API

    - Test File System Access

### 🛡️ DEFENSE BYPASS TECHNIQUES

    - Test WAF fingerprinting

    - Verify input normalization bypass

    - Check filter evasion techniques

    - Test encoding variations

    - Verify case manipulation

    - Check null byte injection

    - Test comment obfuscation

    - Verify whitespace variations

    - Check tab/newline usage

    - Test control characters

    - Verify Unicode normalization

    - Check homoglyph attacks

    - Test right-to-left override

    - Verify zero-width spaces

    - Check combining characters

    - Test surrogate pairs

    - Verify HTML entity encoding

    - Check hex encoding

    - Test octal encoding

    - Verify UTF-7 encoding

    - Check chunked encoding

    - Test multipart forms

    - Verify gzip compression

    - Check deflate encoding

    - Test HTTP/2 prioritization

    - Verify HTTP/3 QUIC usage

    - Check WebSocket compression

    - Test WebTransport channels

    - Verify Brotli encoding

    - Check zstd compression

    - Test protocol smuggling

    - Verify request splitting

    - Check header injection

    - Test cookie jar overflow

    - Verify HPP techniques

    - Check parameter pollution

    - Test fragment confusion

    - Verify path normalization

    - Check query string parsing

    - Test matrix parameters

    - Verify URL standard variations

    - Check legacy URL formats

    - Test IPv6 address formats

    - Verify IDN homograph attacks

    - Check DNS rebinding

    - Test SNI manipulation

    - Verify ALPN negotiation

    - Check OCSP stapling

    - Test certificate pinning

    - Verify HPKP bypasses
