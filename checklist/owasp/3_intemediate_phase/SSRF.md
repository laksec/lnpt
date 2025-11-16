# ULTIMATE SSRF TESTING METHODOLOGY (v2.0)

## Complete Server-Side Request Forgery Exploitation Framework

### RECONNAISSANCE PHASE

    - Begin by mapping all application endpoints that accept URLs or file paths as input - these are primary SSRF candidates.
    - Identify hidden API endpoints through JavaScript file analysis and network traffic inspection.
    - Document all file processing features (PDF generators, image processors, document converters).
    - Locate webhook configuration panels where users can set callback URLs.
    - Find import functionalities (CSV, XML, Excel) that might fetch external resources.
    - Check for features that fetch or display remote content (previews, thumbnails).
    - Identify administrative interfaces with server management capabilities.
    - Discover email processing systems that might render remote images.
    - Locate social media sharing features that accept URLs.
    - Find any functionality that interacts with third-party services.

### BASIC EXPLOITATION TECHNIQUES

    - Test all URL parameters by replacing values with internal IP addresses.
    - Attempt to access localhost using every variant (127.0.0.1, ::1, localhost).
    - Probe for internal services using common ports (22, 80, 443, 3306, 6379).
    - Try different protocol schemes beyond HTTP/HTTPS (file://, ftp://, gopher://).
    - Test IPv6 address representations of localhost and internal networks.
    - Use decimal IP conversions to bypass basic filters (2130706433 = 127.0.0.1).
    - Experiment with URL-encoded characters in the target address.
    - Attempt to access cloud provider metadata endpoints from all identified SSRF vectors.
    - Test for DNS rebinding vulnerabilities by using TTL=0 domains.
    - Verify if the application follows redirects by setting up controlled redirect chains.

### CLOUD METADATA EXPLOITATION

    - Always test AWS EC2 metadata endpoint (169.254.169.254) first.
    - Check for IMDSv2 token requirements by analyzing response headers.
    - Attempt to retrieve IAM credentials from all cloud metadata services.
    - Probe for Azure metadata service at 169.254.169.254 and 168.63.129.16.
    - Test Google Cloud metadata endpoint at metadata.google.internal.
    - Check DigitalOcean's metadata service at 169.254.169.254.
    - Attempt to access Kubernetes API server at 10.0.0.1.
    - Probe for OpenStack metadata at 169.254.169.254.
    - Test Alibaba Cloud's metadata service at 100.100.100.200.
    - Verify Oracle Cloud metadata endpoint at 192.0.0.192.

### PROTOCOL HANDLING TESTS

    - Verify if the server processes file:///etc/passwd requests.
    - Test FTP protocol support by attempting ftp://attacker-controlled-server.
    - Check for Gopher protocol support which can help exploit other services.
    - Attempt to use the dict:// protocol to probe internal services.
    - Test Java's jar: protocol which can lead to deserialization attacks.
    - Verify if ldap:// or ldaps:// protocols are accepted.
    - Check for tftp:// protocol support in legacy systems.
    - Test php://filter for potential LFI when combined with SSRF.
    - Attempt to use the expect:// protocol for command execution.
    - Verify data: URI support which could enable XSS chaining.

### FILTER EVASION METHODS

    - Use URL encoding on special characters to bypass naive filters.
    - Try double encoding vulnerable parameters for deeper WAF bypass.
    - Test case variation (e.g., File:// vs file://) for case-sensitive filters.
    - Add arbitrary subdomains (127.0.0.1.xip.io) to bypass domain checks.
    - Insert benign characters like @ in URLs (http://example.com@malicious).
    - Use alternative IP representations (0x7f000001 for 127.0.0.1).
    - Add port numbers to bypass IP blacklists (127.0.0.1:80).
    - Include path traversal sequences (http://external/../../internal).
    - Mix protocols in a single URL (http://localhost#@evil.com).
    - Use HTML entities or Unicode encoding for special characters.

### DNS TRICKS AND REBINDING

    - Set up DNS rebinding attacks with very short TTL records.
    - Use services like xip.io or nip.io for quick DNS rebinding tests.
    - Test subdomain wildcard resolution for internal service discovery.
    - Verify if the application caches DNS responses by timing requests.
    - Attempt DNS pinning bypasses using multiple A records.
    - Check for DNS tunneling possibilities through long subdomains.
    - Test for DNS SRV record lookups in internal networks.
    - Verify if the application follows CNAME records to internal addresses.
    - Attempt to poison DNS caches through SSRF vectors.
    - Test for DNS-based service discovery protocols like mDNS.

### INTERNAL NETWORK MAPPING

    - Use SSRF to scan common internal ports (80, 443, 8080).
    - Probe for management interfaces (Jenkins, Docker, Kubernetes).
    - Check for database interfaces (Redis, MongoDB, MySQL).
    - Identify internal APIs by testing common API gateway addresses.
    - Look for version control systems (Git, SVN) on internal networks.
    - Probe for internal cloud services (AWS S3, Azure Blob).
    - Check for internal authentication services (LDAP, AD).
    - Identify CI/CD systems (Jenkins, GitLab CI, CircleCI).
    - Look for monitoring systems (Prometheus, Grafana).
    - Probe for messaging queues (RabbitMQ, Kafka).

### CLOUD-SPECIFIC ATTACKS

    - Attempt to retrieve AWS temporary credentials via metadata API.
    - Check for Azure automation account credentials.
    - Probe Google Cloud service account tokens.
    - Try to access Kubernetes service account tokens.
    - Check for Docker API exposure through SSRF.
    - Attempt to access cloud storage buckets via internal endpoints.
    - Probe for cloud SQL instances through internal networking.
    - Check for serverless function invocation endpoints.
    - Attempt to access cloud logging services internally.
    - Probe for secret management systems (Vault, AWS Secrets Manager).

### SERVICE-SPECIFIC EXPLOITS

    - Use SSRF to attack Redis with SLAVEOF commands.
    - Attempt Memcached UDP amplification through SSRF.
    - Probe for internal Elasticsearch instances with sensitive data.
    - Check for internal SMTP servers that accept relay.
    - Attempt to interact with internal FTP servers.
    - Probe for internal Git servers with exposed repositories.
    - Check for internal NoSQL databases with weak authentication.
    - Attempt to access internal Docker registries.
    - Probe for internal package repositories (npm, PyPI).
    - Check for internal certificate authorities.

### BLIND SSRF TECHNIQUES

    - Use timing differences to detect internal service availability.
    - Set up out-of-band detection with DNS lookups.
    - Monitor for subtle response time variations.
    - Check for error message differences between internal/external.
    - Attempt to trigger visible side effects (email sends, webhooks).
    - Use HTTP header reflection to confirm request processing.
    - Check for partial response leakage in error messages.
    - Attempt to trigger secondary vulnerabilities (DoS, logging).
    - Monitor application behavior changes after SSRF attempts.
    -  Use differential analysis comparing allowed vs blocked requests.

### DEFENSE BYPASS METHODS

    - Test WAF bypasses using mixed-case protocols (HtTp://).
    - Verify if the application normalizes URLs before processing.
    - Check for parser inconsistencies between components.
    - Test with malformed HTTP headers in SSRF requests.
    - Attempt to use HTTP request smuggling techniques.
    - Verify if the application follows 30x redirects differently.
    - Test with chunked transfer encoding variations.
    - Attempt to use HTTP/2 exclusive features for bypasses.
    - Check for differential processing of absolute vs relative URLs.
    - Test with non-standard port numbers in URLs.

### HEADER MANIPULATION

    - Inject X-Forwarded-For headers to bypass IP restrictions.
    - Add X-Real-IP headers to spoof internal addresses.
    - Manipulate Host headers to access internal vhosts.
    - Test with X-Forwarded-Host for virtual hosting bypass.
    - Add arbitrary headers to probe for header injection.
    - Verify if headers influence URL resolution.
    - Check for CRLF injection in headers leading to SSRF.
    - Test with duplicate headers to confuse parsers.
    - Verify if headers can override URL scheme.
    - Check for custom headers that might enable SSRF.

### PROTOCOL SMUGGLING

    - Attempt HTTP request smuggling via SSRF vectors.
    - Test for HTTP/2 downgrade possibilities.
    - Verify if the application processes HTTP/0.9 requests.
    - Check for HTTP pipeline handling differences.
    - Test with malformed HTTP versions in requests.
    - Attempt to exploit Keep-Alive header handling.
    - Verify if chunked encoding can bypass filters.
    - Test with oversized headers to trigger edge cases.
    - Check for differential processing of HTTP methods.
    - Attempt to exploit HTTP verb tunneling techniques.

### APPLICATION-SPECIFIC TESTS

    - Check for GraphQL internal service introspection.
    - Test OAuth callback URL validation weaknesses.
    - Verify SAML metadata processing for SSRF.
    - Check OpenID Connect configuration endpoints.
    - Test WebSocket connections to internal services.
    - Verify if SOAP endpoints process external entities.
    - Check for XML External Entity processing.
    - Test JSONP endpoints with callback URLs.
    - Verify if PDF generators fetch remote resources.
    - Check email systems for remote image loading.

### NETWORK TOPOLOGY EXPLOITS

    - Attempt to access internal load balancer APIs.
    - Probe for service mesh control planes (Istio, Linkerd).
    - Check for internal API gateways and management consoles.
    - Attempt to access internal DNS resolvers.
    - Probe for internal NTP servers for time manipulation.
    - Check for internal certificate transparency logs.
    - Attempt to access internal logging systems.
    - Probe for internal configuration management tools.
    - Check for internal package mirror servers.
    - Attempt to access internal artifact repositories.

### CLOUD PROVIDER ESCALATION

    - Attempt to retrieve AWS EC2 user data scripts.
    - Check for Azure VM custom data endpoints.
    - Probe Google Cloud instance metadata attributes.
    - Attempt to access cloud-init configurations.
    - Check for cloud formation template references.
    - Probe for Terraform state file access.
    - Attempt to retrieve Ansible playbooks from metadata.
    - Check for Puppet/Chef client configurations.
    - Probe for cloud deployment manager templates.
    - Attempt to access cloud build logs and artifacts.

### CONTAINER ESCALATION

    - Attempt to access Docker socket via SSRF.
    - Probe for Kubernetes API server access.
    - Check for container orchestration dashboards.
    - Attempt to access container registry APIs.
    - Probe for service mesh control planes.
    - Check for container runtime interfaces.
    - Attempt to access cluster monitoring systems.
    - Probe for container log aggregation systems.
    - Check for container security scanners.
    - Attempt to access container network plugins.

### MIDDLEWARE EXPLOITS

    - Attempt to access internal Apache Tomcat managers.
    - Probe for JBoss administration consoles.
    - Check for WebLogic server administration.
    - Attempt to access IIS configuration APIs.
    - Probe for Nginx status endpoints.
    - Check for internal HAProxy stats pages.
    - Attempt to access internal Varnish admins.
    - Probe for internal Redis commanders.
    - Check for internal PHP-FPM status pages.
    - Attempt to access internal NET debug endpoints.

### ENTERPRISE SERVICE TESTS

    - Probe for internal Active Directory endpoints.
    - Check for Exchange Web Services access.
    - Attempt to access SharePoint admin interfaces.
    - Probe for internal CRM system APIs.
    - Check for ERP system administration consoles.
    - Attempt to access internal HR management systems.
    - Probe for financial system interfaces.
    - Check for internal document management systems.
    - Attempt to access internal BI tool APIs.
    - Probe for internal help desk systems.

### STORAGE SYSTEM TESTS

    - Attempt to access internal S3-compatible storage.
    - Probe for internal NFS server interfaces.
    - Check for internal SMB share access.
    - Attempt to access internal iSCSI targets.
    - Probe for internal SAN management interfaces.
    - Check for internal backup system APIs.
    - Attempt to access internal database dumps.
    - Probe for internal tape library controls.
    - Check for internal object storage systems.
    - Attempt to access internal CDN management.

### MONITORING SYSTEM TESTS

    - Attempt to access internal Prometheus endpoints.
    - Probe for Grafana administration interfaces.
    - Check for internal Nagios configurations.
    - Attempt to access internal Zabbix APIs.
    - Probe for internal Splunk management.
    - Check for ELK stack administration consoles.
    - Attempt to access internal New Relic APIs.
    - Probe for internal Datadog configurations.
    - Check for internal AppDynamics controls.
    - Attempt to access internal Dynatrace APIs.

### CI/CD SYSTEM TESTS

    - Attempt to access Jenkins script consoles.
    - Probe for GitLab CI runner controls.
    - Check for internal CircleCI configurations.
    - Attempt to access internal Travis CI APIs.
    - Probe for internal GitHub Actions runners.
    - Check for internal Azure DevOps controls.
    - Attempt to access internal Bamboo APIs.
    - Probe for internal TeamCity configurations.
    - Check for internal Drone CI controls.
    - Attempt to access internal Buildkite APIs.

### CHAINING OPPORTUNITIES

    - Chain SSRF with XXE for deeper exploitation.
    - Combine with DNS rebinding for persistent access.
    - Use to bypass firewalls for internal service attacks.
    - Chain with RFI for remote code execution.
    - Combine with CSRF for privilege escalation.
    - Use to access internal admin interfaces.
    - Chain with JWT weaknesses for authentication bypass.
    - Combine with insecure deserialization.
    - Use to poison internal caches.
    - Chain with header injection for request smuggling.

### POST-EXPLOITATION TECHNIQUES

    - Use retrieved credentials for lateral movement.
    - Access internal version control for source code.
    - Retrieve configuration files for further attacks.
    - Access backup files for sensitive data.
    - Intercept internal API communications.
    - Modify internal application configurations.
    - Access log files for additional information.
    - Interact with internal messaging systems.
    - Manipulate internal job queues.
    - Access internal monitoring for system intelligence.

### DEFENSIVE EVASION

    - Rotate IPs to avoid detection systems.
    - Use legitimate-looking user agents.
    - Mimic normal application traffic patterns.
    - Space out requests to avoid rate limiting.
    - Use common browser headers for stealth.
    - Avoid scanning well-known dangerous ports.
    - Use HTTPS for outbound callbacks.
    - Randomize subdomains for DNS callbacks.
    - Use common cloud domains for metadata requests.
    - Mimic legitimate API client behavior.

### REPORTING CONSIDERATIONS

    - Document all vulnerable endpoints precisely.
    - Record exact request/response pairs.
    - Note all bypass techniques that worked.
    - Document internal services discovered.
    - Provide risk assessment for each finding.
    - Include proof-of-concept steps without code.
    - Note potential business impacts.
    - Document credential exposures separately.
    - Provide clear remediation guidance.
    - Highlight critical chain possibilities.

### REMEDIATION STRATEGIES

    - Implement allowlisting for URL schemes.
    - Enforce strict domain validation.
    - Use network-level restrictions for internal access.
    - Implement proper authentication for internal services.
    - Add logging for all outbound requests.
    - Deploy WAF rules specifically for SSRF patterns.
    - Regularly test SSRF protections.
    - Educate developers about SSRF risks.
    - Implement mandatory security reviews for features accepting URLs.
    - Monitor for suspicious outbound connections.

### CONTINUOUS TESTING

    - Integrate SSRF tests into CI/CD pipelines.
    - Perform regular manual SSRF testing.
    - Include SSRF in red team exercises.
    - Monitor for new SSRF bypass techniques.
    - Update test cases as applications evolve.
    - Test all new URL-processing features immediately.
    - Verify fixes with regression testing.
    - Include SSRF in security training.
    - Share findings across development teams.
    - Track SSRF vulnerabilities industry-wide.

### EMERGING TECHNIQUES

    - Monitor for new protocol support vulnerabilities.
    - Watch for parser differentials in new libraries.
    - Track cloud service metadata API changes.
    - Research new DNS rebinding methods.
    - Study WAF bypass innovations.
    - Analyze new web protocol implementations.
    - Track changes in HTTP/3 handling.
    - Research browser-based SSRF variations.
    - Monitor serverless architecture risks.
    - Study edge computing SSRF implications.

### LEGAL CONSIDERATIONS

    - Always obtain proper authorization before testing.
    - Document all testing activities thoroughly.
    - Avoid accessing actual sensitive data during tests.
    - Use controlled environments for exploitation proofs.
    - Follow responsible disclosure procedures.
    - Understand data protection regulation impacts.
    - Consider third-party service implications.
    - Document all actions taken during testing.
    - Obtain explicit permission for production testing.
    - Consult legal teams before advanced testing.
