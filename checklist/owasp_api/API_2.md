# Broken Authentication

## End-to-End Methodology, No Code—Maximum Detail

### 🌐 RECONNAISSANCE & MAPPING

  - Catalog each API authentication mechanism (form login, JWT, OAuth2, API keys, SAML, OpenID Connect, passwordless).
  - Document all authentication-required endpoints, noting granularity (resource, action, session, token).
  - Map user roles—include admins, special users, guests, service/bots, linked third-party users.
  - Identify all authentication touchpoints from mobile, web, CLI, and service accounts.
  - Observe flows for signup, login, logout, account recovery/reset, password change, and privilege escalation.
  - Use network analysis tools (proxy, API monitoring) to capture login traffic across devices and platforms.
  - Check for alternative endpoints (legacy/mobile/graphQL/third-party integrations) that may have different authentication logic.
  - Review authentication/authorization libraries/frameworks used (custom, OSS, cloud).
  - Probe internal APIs, admin panels, B2B integrations for distinct or weaker authentication schemes.
  - Note session lifecycle rules: how sessions start, persist, expire, and recover.

### 🔍 CORE AUTHENTICATION CHALLENGES

  - ***Credential Management:***
    - Enumerate possible username/email formats and discover valid accounts via error messages/timing.
    - Test for common, weak, and default credentials across all flows.
    - Try all password reset workflows; verify knowledge, rate limit, and token expiration.
    - Attempt login with leaked or syntactically similar credentials.
  - ***Session/Token Logic:***
    - Analyze cookies/tokens/session data for structure, entropy, expiry, storage, and transmission.
    - Test session fixation: set session cookie, then authenticate and see if session persists.
    - Hijack session tokens/Cookies via referrer/URL/CORS/logs leakage; replay to check persistence.
    - Predict token/cookie values (low entropy, sequential, guessable).
    - Attempt concurrent logins: validate session invalidation, synchronization, and token rotation.
    - Replay expired or tampered JWTs with and without signature checking.
  - ***Authentication Protocols:***
    - Probe OAuth2/OpenID/SSO for token substitution/forgery, weak scopes, unvalidated state/redirects.
    - Try public endpoints without credentials, check for anonymous data leakage.
    - Automate brute-force/credential stuffing and check lockout, alerts, monitoring.
  - ***Error Handling & Enumeration:***
    - Check for user/account enumeration via error responses, validation messages, timing/side-channels.
    - Inspect multifactor, account recovery, and signup flows for information leakage.

### 💾 ADVANCED SESSION & TOKEN ATTACKS

  - Probe session management using multiple devices, IP addresses, browsers, and roles.
  - Test token handling: refresh tokens for expiry, reuse after password change, and post-logout reuse.
  - Analyze JWT structure for none-alg attacks, claim confusion, signature bypass, and audience misconfiguration.
  - Tamper with token format, encoding (base64, Unicode, binary) and measure backend response.
  - Fuzz for token replay, permutation, and token swapping between users.
  - Test session timeout logic, persistent/“remember me” flows, OTP/MFA lifecycles for weak session or token invalidation.

### 🧠 BUSINESS LOGIC & WORKFLOW EDGE CASES

  - Simulate account recovery and password reset with guessed, replayed, expired, and mixed tokens.
  - Register, login, and escalate privileges using chained actions (change password, switch roles, update contact info).
  - Exploit multi-user flows—e.g., team invites, delegated access; check if role or token inheritance is secure.
  - Analyze OAuth consents, redirect URIs, state/nonce handling for unvalidated redirects and openID flow manipulation.
  - Test backup, secondary, or “forgotten” authentication endpoints; probe lost password/account deletion flows.
  - Abuse session creation during critical business logic (checkout, transaction approval, workflow actions).

### 🎯 AUTOMATION, TOOLS, & FUZZING STRATEGY

  - Integrate automation for brute-force, token permutation, role switching, session replay, and error response mapping.
  - Use security tools capable of OpenAPI/Swagger import and fuzzing for authentication bypasses.
  - Set up custom scripts with credential lists, token structures, and session brokers for scale.
  - Correlate server-side logs for failed, anomalous, or excessive authentication attempts.

### 🛡️ DEFENSE VALIDATION & MITIGATION TESTS

  - Validate password complexity, rotation, and expired/compromised credential handling.
  - Confirm robust rate limiting, CAPTCHA/automation defenses, and proper monitoring/alerting.
  - Validate session/token rotation on privilege change, password reset, account update, or device switch.
  - Ensure MFAs, step-up authentication, and timeouts are mandatory for sensitive/privileged actions.
  - Audit session and token revocation—no stale or zombie tokens remain after logout/change.
  - Evaluate error messages for minimal information leakage and constant timing.
  - Confirm monitoring for suspicious authentication activity and integration with incident response tools.
  - Review code and configuration for authentication bypasses, direct object reference flaws, and edge-case permission gaps.

### 🏁 BUSINESS CONTEXT & FINAL VERIFICATION

  - Map authentication weaknesses to real-world business impact (account takeover, privilege escalation, data theft).
  - Produce evidence and impact statements for discovered vulnerabilities, including reproduction steps.
  - Validate all fixes and defensive mechanisms—retest, automate, and monitor continuously.
  - Prepare and share comprehensive reporting and training with developers and stakeholders.
