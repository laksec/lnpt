# Unsafe Consumption of APIs

## End-to-End, Methodology-First — No Code Needed

### 🌐 INTEGRATION & DEPENDENCY MAPPING

  - Enumerate all third-party, federated, or external APIs/services the target API relies on: address enrichment, payments, storage, messaging, business logic, data feeds, analytics, notification, authentication.[1]
  - Document directionality (pull/push), transport mechanisms (HTTP/HTTPS, WebSocket, RPC), and authentication/authorization on each integration point.
  - Inspect network traffic and API code for endpoints, schemas, and logic paths linked to external integrations.
  - Map redirect chains, callback endpoints, webhook flows, and upstream/downstream components.

### 🔍 DATA VALIDATION, SANITIZATION & TRUST BOUNDARY PROBES

  - Test all returned data from external APIs for proper input validation and sanitization (SQLi, XSS, command injection, malformed JSON).
  - Fuzz complex nested data, encoded structures, and unusual content returned by 3rd party APIs and observe processing.
  - Attempt crafted exploit payloads via 3rd party API: inject SQLi, stored XSS, SSRF, or command injection vectors into external data flows.
  - Analyze for blind following of redirects or location headers—supply redirections to attacker-controlled URLs, and inspect for sensitive data leakage.[1]
  - Monitor follow-up requests and logs for evidence the API trusted unsafe data, performed a request, or exfiltrated payloads.

### 💾 TRANSPORT, REDIRECT, & TIMEOUT ABUSE

  - Probe weak or absent transport security—interact with third-party APIs over HTTP, observe for info leakage or MITM vulnerability.
  - Fuzz for protocol downgrade, broken authentication, and incomplete integration of OAuth/mTLS or federated flows.
  - Abuse redirects: configure third-party responses to trigger location changes or permanent redirections, test if API follows blindly with user/context data attached.
  - Test known slow endpoints or time-wasting payloads—does API allocated excessive resources, miss or ignore timeouts in integration flows?

### 🧠 SUPPLY CHAIN & INDIRECTION

  - Map third-party API’s own integrations: where can data transited through the supply chain become tainted, weaken trust, or be leaked?
  - Attempt multi-layer attacks, inject payloads into third-party and review how they propagate and are processed by final API or downstream services.
  - Review for indirect risks—if partner API gets compromised or is malicious, can it force business logic, data exposure, or service DoS by relaying poisoned data?
  - Probe for excessive permissions, privilege escalation, or overbroad service scopes in integrations.

### 🎯 AUTOMATED SCANNING & LOG ANALYSIS

  - Set up automation to regularly probe integrations for unexpected data, redirects, malformed structures, or exploit vectors.
  - Use canary tokens, payload tracking, and HTTP log review to trace data flow end-to-end and find leaks.
  - Monitor both server-side and network logs for anomalies in requests, error messages, redirected traffic, or generic HTTP codes.

### 🛡️ DEFENSE VALIDATION & MITIGATION TESTS

  - Validate that all third-party interactions take place over encrypted channels (TLS), and downgrade is impossible.[1]
  - Confirm that no redirect is followed without strict allowlist/approval checking.
  - Test schema validation and input sanitization on ALL external data before trusting or processing downstream.
  - Ensure resource/time/batch limits on third-party interaction—timeouts, rate limiting, circuit breakers for slow or excessive requests.
  - Monitor and audit permission scope of all integrations; use least privilege and regular permission reviews.
  - Assess supply chain risk—verify security posture of all third-party integrations, and retest after provider updates, mergers, or security incidents.

### 🏁 BUSINESS IMPACT & REPORTING

  - Map exploit chains and business risk: data leaks, injection attacks, loss of privacy, privilege escalation, supply chain compromise.[1]
  - Document exploit steps, redirection/chain flows, and remediation recommendations.
  - Plan incident response for third-party compromise affecting your API’s security boundary.
  - Validate fixes with retesting after changes to external or partner APIs.
