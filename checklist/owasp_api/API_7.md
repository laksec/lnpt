# Server Side Request Forgery (SSRF)

## Full-Coverage, Methodology-First — No Code Required

### 🌐 RECONNAISSANCE & SURFACE MAPPING

  - Identify all API endpoints that accept URLs, domains, IP addresses, or file paths as input (webhooks, file/image URL uploads, metadata fetchers, link preview APIs, integrations, custom SSO, redirectors, remote PDF or content converters).[2][7][1]
  - Gather a list of all parameter names commonly associated with URL input (url, uri, path, dest, target, redirect, next, callback, feed, host, domain, file, reference).[5]
  - Document the network environment—from the API’s perspective, what internal resources can it reach (e.g., cloud metadata, local admin ports, flat network for microservices)?
  - Look for features commonly used by automation, backend integrations, or trusted internal systems.

### 🔍 SSRF TESTING & PAYLOAD INJECTION

  - Probe parameters with URLs that resolve to internal IPs (127.0.0.1, 10.x.x.x, 169.254.x.x) or reserved domains (localhost, metadata.google.internal).[4][7][1][2]
  - Attempt response-based SSRF: supply attacker-controlled or internet-facing URLs, watch for evidence the server fetched and included remote content.[4]
  - Test blind SSRF: supply URLs to systems you control (public logs, request bin, Collaborator, etc.); monitor for DNS, HTTP, or ICMP callbacks.[4]
  - Fuzz for URL parsing tricks: scheme confusion (file://, gopher://, ftp://, data://); encoded IPs/hostnames; mixed URLs (`http://127.1/`, `http://0x7f000001/`, IPv6, localhost aliases).[7]
  - Chain redirects, open proxies, and chained SSRF: send URLs that bounce through one service to another.
  - Attempt port scanning via URL: try targets with different ports (`http://localhost:8000`, `http://internal:5005`); monitor based on timing, responses, errors.
  - Supply malformed, reserved, or non-standard URLs and monitor for varied network activity (timeouts, resets, unique error messages).
  - Explore callback flows (webhooks, notifications) — can you get the server to ping arbitrary endpoints at your control?

### 💾 ADVANCED ABUSE CASES & ENVIRONMENT ESCALATION

  - Test for access to cloud provider metadata endpoints (AWS: `http://169.254.169.254/latest/meta-data/...`, GCP: `http://metadata.google.internal/`).[6][1]
  - Probe for access to internal admin interfaces (monitoring, databases, container orchestrators) exposed as HTTP APIs.
  - Chain SSRF with other attacks: access privileged endpoints, retrieve internal secrets, or escalate to RCE in vulnerable frameworks.
  - Analyze API error and side-channel behavior: different response codes/timing based on internal host accessibility.
  - Trigger SSRF from multiple API contexts and roles (user, admin, service accounts).

### 🧠 DEFENSE BYPASS & FILTER EVASION

  - Test all possible URL encodings (hex, octal, decimal, Unicode, mixed case).[7]
  - Bypass naïve blacklist filters (use alternate schemes, subdomains, double encoding, DNS rebinding).
  - Attempt to skirt egress and allowlists with chained requests, secondary redirections or intermediate endpoints not covered by policy.
  - Inspect for lack of hostname resolution (DNS rebinding, internal aliases, incomplete parsing).

### 🎯 DETECTION, TOOLING & AUTOMATION

  - Use public interaction tools (Burp Collaborator, Canary tokens, requestbin.net, DNS logging) for blind SSRF.
  - Automate parameter and payload fuzzing for every endpoint and context that could trigger network activity.
  - Monitor API and infrastructure logs for unusual outbound traffic, DNS requests to rare domains, or spikes in error rates.
  - Test both immediate (response-based) and delayed (side-channel, out-of-band) SSRF variants.

### 🛡️ DEFENSE VALIDATION & REMEDIATION CHECKS

  - Validate strict allowlists for external URL fetching—enforced server-side for domain, scheme, and port.[1][2][7]
  - Ensure all input URLs are strictly parsed by well-maintained libraries.
  - Block access to internal IPs, cloud metadata or admin endpoints at the network or firewall level.
  - Forbid/strip non-HTTP(S) schemes unless absolutely required.
  - Limit or turn off HTTP redirections.
  - Never return raw fetch responses or errors to users without sanitization.
  - Monitor and alert on anomalous outbound requests, especially to internal or sensitive destinations.

### 🏁 BUSINESS IMPACT & REPORTING

  - Map SSRF exploits to potential real-world harm: internal reconnaissance, metadata theft, credential compromise, firewall bypass, lateral movement, accidental open proxy or DoS.[6][1]
  - Document exploit steps, payloads, and network impacts.
  - Summarize the potential for critical escalation (internal resource takeovers, supply chain targets, RCE, cloud account access).
  - Offer prioritized remediation, validate with retesting and post-fix automation.
