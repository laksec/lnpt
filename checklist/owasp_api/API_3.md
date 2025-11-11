# Broken Object Property Level Authorization (BOPLA)

## Full-Coverage Methodology—No Code Required

### 🌐 RECONNAISSANCE & API MAPPING

  - Enumerate all API endpoints that expose or accept object properties in requests/responses (REST, GraphQL, RPC).[1]
  - Document every resource type and its properties (user profiles, bookings, transactions, videos, products).
  - Review API documentation and models for fields marked `internal`, `admin_only`, or sensitive (location, price, privilege flags).
  - Analyze every returned object in the API (response, error, notifications) for properties not relevant to the client’s context.
  - Identify auto-generated responses (e.g., via `to_json()`, `to_string()`) and mass-assignment patterns.
  - Explore different API protocols (REST, GraphQL) for property-specific queries, mutations, and batch operations.
  - Gather sample payloads for create, update, and read actions; note which properties are modifiable or exposed.

### 🔍 ATTACK VECTORS & PROPERTY FUZZING

  - Fuzz request payloads by adding, manipulating, or deleting object properties not intended for regular users (e.g., `isAdmin`, `blocked`, `total_stay_price`).[1]
  - Exploit mass assignment by inserting extra fields in create/update requests and observe unintended side effects.
  - Enumerate properties in API responses; review for sensitive/private/internal/protected fields (fullName, location, internal status, pricing).
  - Replay legitimate requests with modified properties—try changing values that should be immutable (status flags, payment amount).
  - Test batch operations and nested data updates: can you change hidden properties for multiple objects at once?
  - Use GraphQL introspection, input fuzzing, and nested queries for property-level enumeration and exploitation.
  - Analyze client logic for assumptions about what properties can/can’t be modified—override via direct API calls.
  - Probe side-effects by sending requests that change data not directly visible in the response (toggle moderation, enable features).
  - Monitor error messages for hints on forbidden, missing, or unexpected fields.

### 💾 BUSINESS LOGIC ABUSE & PRIVILEGE ESCALATION

  - Abuse business flows by manipulating object properties:
    - Change payment amount, internal notes, or approval status beyond your authority.[1]
    - Manipulate flags that grant access or bypass restrictions (blocked, verified, premium).
    - Chain requests: perform approvals, assignments, or deletions with rogue properties.
    - Elevate privileges by injecting admin-only fields into user-level requests.
    - Unlock, unban, or escalate objects by altering hidden moderation or business state properties.

### 🧠 ADVANCED ENUMERATION & DEFENSE BYPASS

  - Test with mixed property types (numeric, string, boolean, arrays, nested objects, null/empty values).
  - Analyze all endpoints for excessive data exposure (fields irrelevant to current user, global state leakage).
  - Check if response varies based on role—compare normal and admin-level accounts for property access differences.
  - Probe internal, deprecated, or undocumented APIs for missing property validation.
  - Test versioning and alternate protocols (e.g., mobile vs web, v1 vs v2) for inconsistent property handling.

### 🎯 AUTOMATION, TOOLING & BULK SCANNING

  - Use automated tools and custom scripts for property fuzzing, mass assignment, and schema validation bypass.
  - Integrate OpenAPI/GraphQL schemas for property enumeration and permission checks.
  - Perform batch testing for response validation, excessive data exposure, and unintended property modifications.
  - Correlate server logs for unauthorized access or manipulation attempts on critical fields.

### 🛡️ DEFENSE VALIDATION & REMEDIATION TESTS

  - Validate that only permitted properties are exposed in every API response—no excess/internal fields.[1]
  - Confirm that every update request is strictly whitelisted for allowed properties by user role/context.
  - Test schema-based input validation and ensure it rejects unknown, forbidden, or unexpected fields.
  - Avoid using automatic binding (`to_json()`, generic deserialization) for user input—cherry-pick exposed/accepted properties.
  - Limit returned data structures to the bare minimum—no information leakage beyond business requirements.
  - Verify logging, alerting, and monitoring for suspicious access or modification of internal object properties.

### 🏁 BUSINESS IMPACT & FINAL REPORTING

  - Map discovered BOPLA issues to real business impacts: privilege escalation, financial fraud, data leaks, account takeover.[1]
  - Document reproducible steps, attack scenarios, and remediation priorities.
  - Collaborate with developers to apply schema validation, whitelisting, and least-privilege patterns in code.
  - Retest and verify all fixes with both manual and automated tools.
