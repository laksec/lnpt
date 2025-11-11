## Methodology-First, BROKEN OBJECT LEVEL AUTHORIZATION (BOLA) 

### 🌐 RECONNAISSANCE & API MAPPING

  - Enumerate all endpoints that accept object identifiers (path, query, body, headers): `/users/{id}`, `/files/{fileId}`, `/vehicle/{VIN}`.[1]
  - Document all data models used in requests/responses (users, organizations, devices, accounts, orders, documents).
  - Check client and server code for places where object IDs are handled, referenced, or exposed in the frontend.
  - Analyze network traffic from mobile, web, and integrations; watch for endpoints returning or accepting third-party object IDs.
  - Investigate bulk/batch operations: are APIs returning lists or allowing modifications for multiple objects in one call?
  - Map object relationships: many APIs link resources (e.g., comments on a post, devices on account).
  - Review authentication/authorization boundaries in documentation or source (OpenAPI specs, client SDKs, backend code).
  - Probe API for guessable, sequential, or predictable object IDs (simple integers, UUIDs, slugs).
  - Identify endpoints generating or consuming object IDs via business flows (invitation, sharing, linking, multi-tenancy).

### 🔎 BROKEN OBJECT ID ATTACK VECTORS

  - Manipulate object IDs in every API request—swap, increment, randomize, replay—to check for unauthorized access (read, update, delete, execute).[1]
  - Enumerate IDs from related accounts, tenants, or organizations. Attempt horizontal and vertical privilege escalation.
  - Exploit batch endpoints by combining your object ID with those from other users.
  - Use reconnaissance data to script bulk requests with mutated IDs, mapping authorization boundaries and possible data leaks.
  - Replace nested object IDs inside deeply structured payloads.
  - Probe endpoints that return lists or pagination for hidden or unauthorized objects.
  - Test relationship/sequencing flows (parent-child objects, linked resource trees) for navigation outside permitted scope.

### 💾 ADVANCED BUSINESS LOGIC & PROCESS ABUSE

  - Abuse business flows: approvals, status changes, assignments, linking, unlinking. Attempt these with object IDs you don’t own.
  - Replay legitimate requests with third-party IDs for destructive actions (delete, modify, transfer).
  - Create complex scenarios: chain requests across different endpoints to pivot from one object to another, e.g., modify a document and then delete it with another user's ID.[1]
  - Check integrations, partner flows, and admin APIs for relaxed or missing authorization checks on object actions.
  - Use fuzzing and automation to brute-force object ID parameters under rate limits.

### 🧠 EDGE CASES & DEFENSE BYPASS

  - Probe for alternate data types: mixed GUID/slug/integer IDs, string coercion, NULL/empty values, special characters.
  - Test API endpoints as guest, low-privilege, and highest-privilege users for inconsistent access control.
  - Mix object ID attacks with session replay, token permutation, and authentication boundary manipulation.
  - try to access deleted, archived, or hidden objects via direct ID manipulation.
  - Analyze logs, error messages, and audit records for leaks or hints about valid object IDs and access controls.
  - Attempt time-based, race-condition, and chained request attacks that might bypass authorization checks in transactional flows.

### 🎯 MASS ENUMERATION & AUTOMATED SCANNING

  - Use automated tools/scripts to enumerate all possible object IDs in the application’s namespace—watch for API rate limiting and blocking.
  - Test endpoints for bulk exports and large object lists for unauthorized data exposure.
  - Scan for object-level access in search, analytics, reporting, and notification endpoints returning cross-account objects.
  - Fuzz with high-speed requests—map authorization boundaries with thousands of IDs.

### 🛡️ AUTHORIZATION VERIFICATION & DEFENSE VALIDATION

  - Confirm object-level authorization logic is enforced server-side for every endpoint that touches data (read, write, update, delete, approve, assign).
  - Validate role checks are performed per object, not just at session or function level.
  - Test random/unpredictable ID generation—confirm they add value but do not replace authorization logic.
  - Review error handling—ensure no information leakage about the presence, name, or status of unowned objects.
  - Check defensive coding: test/unit/e2e coverage for object ownership checks and data access logic.
  - Evaluate RBAC/ABAC implementation for gaps—are policies enforced by business logic, not just function wrappers?
  - Confirm mitigations still allow legitimate business flows without breaking expected functionality.

### 🏁 BUSINESS IMPACT & FINAL REPORTING

  - Map all identified BOLA issues to real business impact: data disclosure, unauthorized modification, full account takeover.[1]
  - Document clear reproduction steps and attack scenarios.
  - Describe potential chain attacks, escalation routes, and mitigation strategies.
  - Validate fixes with robust retesting and monitoring scripts.
  - Deliver complete impact analysis and technical details for remediation.
