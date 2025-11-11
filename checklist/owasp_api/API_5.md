# Broken Function Level Authorization (BFLA)

## Full-Coverage, Methodology-First—No Code Needed

### 🌐 RECONNAISSANCE & FUNCTION MAPPING

  - Enumerate all exposed API functions (endpoints, methods, actions): identify CRUD, export/import, admin, reporting, configuration, and workflow APIs.[1]
  - Document which functions are for regular users, privileged roles, groups, guests, sub-users, and administrators.
  - Analyze network traffic and monitor all endpoints being called during authentication, onboarding, admin and normal use.
  - Map user role, group, and hierarchy logic from both documentation and practical app testing.
  - Use API discovery tools and brute-forcing to find hidden/admin endpoints or alternate HTTP methods.

### 🔍 FUNCTION ACCESS ABUSE VECTORS

  - Attempt to access privileged/admin endpoints using regular or anonymous accounts—try all HTTP verbs (GET, POST, PUT, PATCH, DELETE) for function-specific attacks.[1]
  - Manipulate URL paths and endpoint parameters to call administrative or restricted functions (guess endpoints, use docs, analyze client code).
  - Submit requests with role escalation (change roles in request body, swap tokens, spoof cookies or headers) and see if functions are exposed.
  - Replay legitimate privileged requests as low-privilege or unauthenticated users.
  - Attempt forced browsing—manually or with automation—in the hope of finding misconfigured function access controls.
  - Test function-level access on batch/bulk operations (e.g., exporting all users, deleting all objects).
  - Analyze multi-tenant and cross-group APIs for lateral access across organizational boundaries.

### 💾 BUSINESS LOGIC ABUSE & PRIVILEGE ESCALATION

  - Abuse onboarding flows—register, reset password, invite new users— and attempt privileged actions (create admin users, invite with elevated roles).
  - Attempt to invoke sensitive actions by simply switching HTTP methods, e.g., from `GET /record` (read) to `DELETE /record` (delete).
  - Exploit endpoints not clearly marked as admin or privileged (hidden under standard paths, undocumented, legacy).
  - Test workflow and configuration APIs—can you publish, approve, administrate, or change settings beyond your role?
  - Mix and match requests from multiple user sessions/tokens to test privilege isolation.

### 🧠 EDGE CASES & DEFENSE BYPASS

  - Probe for alternate pathing, legacy endpoints, or deprecated methods for "forgotten" authorization.
  - Test APIs with different parameters, payloads, encodings, and malformed data to bypass validation logic.
  - Attempt function access from mobile, browser, CLI, or integrations to spot client-side enforcement gaps.
  - Analyze if function exposure changes based on user state (pending, inactive, unverified, guest).
  - Monitor error messages—do they reveal existence of restricted functions or disclose internal logic?
  - Try parallel requests for race conditions—does rapid switching between roles/sessions expose functions?

### 🎯 AUTOMATION, TOOLING, BULK SCANNING

  - Use automated tools/scripts for endpoint brute-forcing, path guessing, HTTP method permutations, role switching, and access reporting.
  - Import OpenAPI/Swagger docs for comprehensive function enumeration and schema analysis.
  - Bulk test all action endpoints for security validation and response differences across roles.
  - Integrate findings with server logs for unauthorized access attempts and monitoring.

### 🛡️ DEFENSE VALIDATION & MITIGATION TESTS

  - Ensure that all business functions enforce access control, checking explicit group/role for every operation.[1]
  - Confirm "deny by default" in authorization: only explicitly granted functions should be reachable by each user type, irrespective of endpoint naming.
  - Test inheritance of authorization mechanisms in code—admin controllers/functions should robustly check user roles.
  - Confirm error and response handling properly hides privilege and functional boundaries.
  - Review coverage for function-level checks in automated unit and integration tests.
  - Apply defense-in-depth: combine function-level checks with endpoint authentication, business logic, and auditing.

### 🏁 BUSINESS IMPACT & REPORTING

  - Map discovered BFLA issues to business impact: data leaks, corruption, loss, privilege takeover, service disruption.[1]
  - Document reproducible exploit steps, full attack scenarios, and chain-of-impact details.
  - Suggest prioritized remediation from code refactoring to policy configuration.
  - Retest and automate coverage for all fixes; update management, monitoring, and code review standards.
