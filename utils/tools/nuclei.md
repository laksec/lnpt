# 🔍 NUCLEI AUTOMATED SECURITY SCANNING | VULNERABILITY ASSESSMENT & EXPLOITATION FRAMEWORK

## Comprehensive Nuclei Security Assessment Framework

### 1 Nuclei Fundamentals & Core Concepts
- **Nuclei Architecture Understanding:**
  - Template-based vulnerability detection
  - YAML template structure comprehension
  - HTTP protocol interaction testing
  - DNS protocol vulnerability assessment
  - Network service security scanning
  - Headless browser integration testing
  - JavaScript-based vulnerability detection
  - Workflow automation capabilities

- **Template Categories Mastery:**
  - **Network Security Templates:**
    - Service-specific vulnerability detection
    - Protocol-level security testing
    - Banner grabbing and service identification
    - Default credential testing
    - Configuration vulnerability assessment
  - **Web Application Templates:**
    - OWASP Top 10 vulnerability detection
    - CMS-specific security testing
    - Framework vulnerability assessment
    - API security testing
    - Authentication bypass testing
  - **Cloud Security Templates:**
    - AWS misconfiguration detection
    - Azure security assessment
    - GCP configuration testing
    - Kubernetes security scanning
    - Docker container vulnerability assessment

### 2 Template Development & Customization
- **Advanced Template Creation:**
  - **HTTP Template Development:**
    ```yaml
    id: custom-sql-injection
    
    info:
      name: Custom SQL Injection Detection
      author: security-team
      severity: high
      description: Detects SQL injection vulnerabilities in specific parameters
      reference: https://example.com/sql-injection
      tags: sqli,injection
    
    requests:
      - method: GET
        path:
          - "{{BaseURL}}/search?query=test'"
          - "{{BaseURL}}/user?id=1'"
        
        matchers:
          - type: word
            part: body
            words:
              - "sql syntax"
              - "mysql_fetch"
              - "ora-"
              - "postgresql"
            condition: or
    ```

  - **DNS Template Development:**
    ```yaml
    id: dns-zone-transfer
    
    info:
      name: DNS Zone Transfer Vulnerability
      author: security-team
      severity: medium
      description: Checks for DNS zone transfer vulnerabilities
    
    dns:
      - name: "{{FQDN}}"
        type: AXFR
        class: in
        
        matchers:
          - type: word
            words:
              - "IN"
              - "A"
              - "NS"
            condition: and
    ```

  - **Network Template Development:**
    ```yaml
    id: redis-unauthorized-access
    
    info:
      name: Redis Unauthorized Access
      author: security-team
      severity: critical
      description: Checks for unauthorized Redis access
    
    network:
      - inputs:
          - data: "PING\r\n"
        host:
          - "{{Hostname}}"
        port: 6379
        
        read-size: 1024
        
        matchers:
          - type: word
            part: data
            words:
              - "+PONG"
    ```

### 3 Advanced Scanning Techniques
- **Comprehensive Target Management:**
  - **Target Specification Methods:**
    ```bash
    # Single target scanning
    nuclei -u https://example.com
    
    # Multiple target file scanning
    nuclei -l targets.txt
    
    # Subdomain integration scanning
    subfinder -d example.com | nuclei -t http-vuln/
    
    # Live target discovery scanning
    naabu -list domains.txt | nuclei -t network-vuln/
    ```

  - **Template Selection Strategies:**
    ```bash
    # Specific template category scanning
    nuclei -t cves/ -l targets.txt
    nuclei -t vulnerabilities/ -l targets.txt
    nuclei -t exposed-panels/ -l targets.txt
    
    # Severity-based scanning
    nuclei -severity critical,high -l targets.txt
    
    # Tag-based template selection
    nuclei -tags sqli,xss -l targets.txt
    
    # Author-based template selection
    nuclei -author geeknik -l targets.txt
    ```

### 4 Workflow Automation & Orchestration
- **Advanced Workflow Development:**
  ```yaml
  id: comprehensive-web-assessment
  
  info:
    name: Comprehensive Web Application Assessment
    author: security-team
    description: Multi-stage web application security assessment
  
  workflows:
    - template: http/technologies/tech-detect.yaml
      matchers:
        - name: wordpress
          subtemplates:
            - template: http/vulnerabilities/wordpress/
            - template: http/exposures/wordpress/
        
        - name: joomla
          subtemplates:
            - template: http/vulnerabilities/joomla/
            - template: http/exposures/joomla/
        
        - name: apache
          subtemplates:
            - template: http/vulnerabilities/apache/
            - template: http/misconfigurations/apache/
  
    - template: http/exposed-panels/
      matchers:
        - type: dsl
          dsl:
            - 'contains(tolower(body), "admin")'
          subtemplates:
            - template: http/default-logins/
  ```

### 5 Custom Template Development Framework
```yaml
# Advanced Custom Template Structure
id: advanced-custom-detection

info:
  name: Advanced Custom Security Detection
  author: security-team
  severity: medium
  description: Comprehensive detection with multiple attack vectors
  reference:
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-12345
    - https://example.com/security-advisory
  tags: custom,rce,injection
  metadata:
    max-request: 5
    shodan-query: "product:custom-app"

# HTTP Request Configuration
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/endpoint"
      - "{{BaseURL}}/admin/panel"
    
    headers:
      User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      X-Custom-Header: "test-value"
    
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 302
      
      - type: word
        part: header
        words:
          - "server: custom-app"
          - "x-powered-by: custom-framework"
        condition: or
      
      - type: regex
        part: body
        regex:
          - 'version: ([0-9]+\.[0-9]+\.[0-9]+)'
    
    extractors:
      - type: regex
        name: version
        part: body
        regex:
          - 'version: ([0-9]+\.[0-9]+\.[0-9]+)'
        group: 1

# Second Request - Authentication Bypass Testing
  - method: POST
    path:
      - "{{BaseURL}}/login"
    
    body: 'username=admin&password=admin{{random_int}}'
    
    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200'
          - '!contains(tolower(body), "invalid credentials")'
          - 'contains(tolower(header), "set-cookie")'
```

### 6 Protocol-Specific Testing Templates
- **HTTP/HTTPS Protocol Testing:**
  ```yaml
  id: http-security-headers-check
  
  info:
    name: HTTP Security Headers Check
    author: security-team
    severity: info
    description: Checks for missing security headers
  
  http:
    - method: GET
      path:
        - "{{BaseURL}}"
      
      matchers-condition: and
      matchers:
        - type: dsl
          dsl:
            - '!contains(header, "content-security-policy")'
            - '!contains(header, "x-frame-options")'
            - '!contains(header, "x-content-type-options")'
            - '!contains(header, "strict-transport-security")'
  ```

- **DNS Protocol Security Testing:**
  ```yaml
  id: dns-security-checks
  
  info:
    name: Comprehensive DNS Security Checks
    author: security-team
    severity: medium
  
  dns:
    - name: "{{FQDN}}"
      type: A
      class: in
      recursion: true
      
      matchers:
        - type: word
          words:
            - "NOERROR"
  ```

- **Network Service Testing:**
  ```yaml
  id: network-service-detection
  
  info:
    name: Network Service Version Detection
    author: security-team
    severity: info
  
  network:
    - inputs:
        - data: "HEAD / HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"
      host:
        - "{{Hostname}}"
      port: "{{Port}}"
      
      matchers:
        - type: word
          part: data
          words:
            - "Server:"
            - "Apache"
            - "nginx"
  ```

### 7 Advanced Matchers & Extractors
- **Complex Matching Conditions:**
  ```yaml
  # DSL-based Advanced Matchers
  matchers:
    - type: dsl
      name: advanced-dsl-matcher
      dsl:
        - 'status_code == 200'
        - 'contains(tolower(body), "admin")'
        - '!contains(tolower(body), "error")'
        - 'len(body) > 1000'
        - 'contains(header, "session")'
        - 'duration < 2'  # Response time less than 2 seconds
      condition: and

  # Multiple Extractors for Data Collection
  extractors:
    - type: regex
      name: version
      part: body
      regex:
        - 'Version: ([0-9]+\.[0-9]+\.[0-9]+)'
      group: 1
    
    - type: json
      name: api_token
      part: body
      json:
        - '.access_token'
    
    - type: xpath
      name: csrf_token
      part: body
      xpath: '/html/head/meta[@name="csrf-token"]/@content'
  ```

### 8 Integration with Reconnaissance Tools
- **Complete Reconnaissance Pipeline:**
  ```bash
  # Comprehensive Nuclei Scanning Pipeline
  # Phase 1: Subdomain Discovery
  subfinder -d example.com -silent | tee subdomains.txt
  assetfinder --subs-only example.com | tee -a subdomains.txt
  amass enum -d example.com -o amass_subdomains.txt
  
  # Phase 2: Live Host Discovery
  cat subdomains.txt | httpx -silent | tee live_hosts.txt
  cat subdomains.txt | naabu -silent | tee open_ports.txt
  
  # Phase 3: Technology Detection
  cat live_hosts.txt | nuclei -t http/technologies/ -silent | tee technologies.txt
  
  # Phase 4: Vulnerability Scanning
  cat live_hosts.txt | nuclei -t http/vulnerabilities/ -silent | tee vulnerabilities.txt
  cat live_hosts.txt | nuclei -t http/exposed-panels/ -silent | tee exposed_panels.txt
  
  # Phase 5: CVE-Specific Scanning
  cat live_hosts.txt | nuclei -t cves/ -severity critical,high -silent | tee critical_cves.txt
  
  # Phase 6: Custom Template Scanning
  cat live_hosts.txt | nuclei -t custom-templates/ -silent | tee custom_findings.txt
  ```

### 9 Custom Template Repository Management
```yaml
# Nuclei Template Configuration
# .nuclei-config.yaml

templates:
  # Custom template directories
  - /home/user/custom-nuclei-templates
  - /opt/security-templates
  - ./organization-templates

  # Enable community templates
  - https://github.com/projectdiscovery/nuclei-templates.git

# Reporting Configuration
reporting:
  # File-based reporting
  - type: file
    options:
      output: scan-results.json
      format: json
  
  # Webhook integration
  - type: webhook
    options:
      url: https://hooks.slack.com/services/XXX/XXX/XXX
      format: json
  
  # Elasticsearch integration
  - type: elastic
    options:
      url: http://localhost:9200
      index: nuclei-scans

# Scanning Configuration
scan:
  rate-limit: 150
  timeout: 10
  retries: 2
  headless: true
  system-resolvers: true
```

### 10 Advanced Scanning Strategies
- **Progressive Scanning Approach:**
  ```bash
  # Step 1: Quick Security Headers & Basic Checks
  nuclei -l targets.txt -t http/security-misconfigurations/ -o quick_scan.txt
  
  # Step 2: Technology-Specific Scanning
  nuclei -l targets.txt -t http/technologies/ -o technologies.txt
  grep "wordpress" technologies.txt | cut -d' ' -f2 | nuclei -t http/vulnerabilities/wordpress/
  
  # Step 3: Comprehensive Vulnerability Assessment
  nuclei -l targets.txt -t http/vulnerabilities/ -o vulnerabilities.txt
  
  # Step 4: CVE-Specific Deep Scan
  nuclei -l targets.txt -t cves/ -o cves.txt
  
  # Step 5: Custom Business Logic Testing
  nuclei -l targets.txt -t custom-templates/ -o custom_findings.txt
  ```

### 11 Template Development Best Practices
```yaml
# Template Quality Assurance Checklist
id: quality-assured-template

info:
  name: Quality Assured Security Template
  author: security-team
  severity: high
  description: Template following best practices
  reference: 
    - https://security-standards.example.com
  tags: best-practice,tested,verified

# Request Configuration Best Practices
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/endpoint"
    
    # Rate limiting consideration
    attack: batteringram
    threads: 1
    
    # Proper headers for realistic traffic
    headers:
      User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      Accept-Language: "en-US,en;q=0.5"
    
    # Cookie support if needed
    cookie-reuse: true
    
    # Redirect handling
    redirects: true
    max-redirects: 3
    
    # Matchers with proper conditions
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      
      - type: word
        part: body
        words:
          - "vulnerable_component"
        condition: and
      
      - type: dsl
        dsl:
          - 'len(body) < 10000'
          - 'duration < 5'

# Extractor for version information
extractors:
  - type: regex
    part: body
    regex:
      - 'version["\']?\s*:\s*["\']?([0-9]+\.[0-9]+\.[0-9]+)'
    group: 1
```

### 12 Performance Optimization & Scaling
```bash
# High-Performance Nuclei Scanning Configuration

# Mass Scanning with Performance Tuning
nuclei -l targets.txt \
  -t http/vulnerabilities/ \
  -rate-limit 200 \
  -timeout 10 \
  -retries 1 \
  -bulk-size 50 \
  -concurrency 20 \
  -disable-update-check \
  -stats \
  -silent \
  -o results.json

# Distributed Scanning Setup
# Worker Node Configuration
nuclei -l targets.txt -t http/vulnerabilities/ -o worker_results.json -stats

# Results Aggregation
cat worker_*.json | jq -s '.[]' > combined_results.json

# Resource Monitoring During Scanning
watch -n 1 'echo "Memory: $(free -h | grep Mem | awk "{print \$3}") | CPU: $(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk "{print 100 - \$1}")%"'
```

### 13 Continuous Security Monitoring
```yaml
# nuclei-monitoring-config.yaml
monitoring:
  targets:
    - file: /opt/monitoring/targets.txt
      update-frequency: 1h
    
    - url: https://internal-targets-api.example.com/targets
      update-frequency: 30m

  templates:
    - directory: /opt/nuclei-templates/cves/
      update-frequency: 1h
    
    - directory: /opt/nuclei-templates/custom/
      update-frequency: 1d

  scanning:
    schedule: "0 */6 * * *"  # Every 6 hours
    concurrency: 10
    rate-limit: 100

  reporting:
    - type: file
      options:
        output: /var/log/nuclei/monitoring-results-{{timestamp}}.json
    
    - type: webhook
      options:
        url: {{SLACK_WEBHOOK_URL}}
        format: json
    
    - type: elasticsearch
      options:
        url: {{ELASTICSEARCH_URL}}
        index: nuclei-monitoring-{{date}}

# Automated Response Actions
actions:
  critical-findings:
    - type: webhook
      url: {{CRITICAL_ALERT_WEBHOOK}}
    
    - type: email
      to: security-team@example.com
      subject: "Critical Vulnerability Detected"
  
  high-findings:
    - type: webhook
      url: {{HIGH_ALERT_WEBHOOK}}
```

### 14 Custom Template Examples by Category
- **Authentication Bypass Templates:**
  ```yaml
  id: auth-bypass-test
  
  info:
    name: Authentication Bypass Testing
    author: security-team
    severity: high
    description: Tests for common authentication bypass techniques
  
  http:
    - method: GET
      path:
        - "{{BaseURL}}/admin"
        - "{{BaseURL}}/dashboard"
        - "{{BaseURL}}/manager"
      
      headers:
        X-Original-URL: /admin
        X-Rewrite-URL: /admin
        X-Forwarded-For: 127.0.0.1
      
      matchers:
        - type: dsl
          dsl:
            - 'status_code == 200'
            - 'contains(tolower(body), "dashboard")'
            - '!contains(tolower(body), "login")'
  ```

- **API Security Testing Templates:**
  ```yaml
  id: api-security-test
  
  info:
    name: API Security Testing
    author: security-team
    severity: medium
    description: Comprehensive API security assessment
  
  http:
    - method: GET
      path:
        - "{{BaseURL}}/api/v1/users"
        - "{{BaseURL}}/api/v1/admin"
      
      matchers:
        - type: dsl
          dsl:
            - 'status_code == 200'
            - 'contains(tolower(header), "application/json")'
            - 'contains(body, "password") || contains(body, "email")'
  ```

- **Information Disclosure Templates:**
  ```yaml
  id: information-disclosure
  
  info:
    name: Sensitive Information Disclosure
    author: security-team
    severity: medium
    description: Checks for sensitive information exposure
  
  http:
    - method: GET
      path:
        - "{{BaseURL}}/.git/config"
        - "{{BaseURL}}/.env"
        - "{{BaseURL}}/backup.zip"
        - "{{BaseURL}}/database.sql"
      
      matchers:
        - type: word
          part: body
          words:
            - "[core]"
            - "DB_PASSWORD"
            - "INSERT INTO"
          condition: or
  ```

### 15 Advanced Reporting & Analytics
```python
# nuclei-results-processor.py

import json
import pandas as pd
from datetime import datetime

class NucleiResultsProcessor:
    def __init__(self, results_file):
        self.results_file = results_file
        self.findings = []
    
    def load_results(self):
        """Load and parse Nuclei results"""
        with open(self.results_file, 'r') as f:
            for line in f:
                if line.strip():
                    finding = json.loads(line.strip())
                    self.findings.append(finding)
    
    def generate_severity_report(self):
        """Generate severity-based analysis"""
        severity_counts = {}
        for finding in self.findings:
            severity = finding.get('info', {}).get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return severity_counts
    
    def generate_template_analysis(self):
        """Analyze template effectiveness"""
        template_stats = {}
        for finding in self.findings:
            template_id = finding.get('templateID', 'unknown')
            template_stats[template_id] = template_stats.get(template_id, 0) + 1
        
        return template_stats
    
    def generate_timeline_analysis(self):
        """Generate finding timeline"""
        timeline = []
        for finding in self.findings:
            timestamp = finding.get('timestamp', '')
            template = finding.get('templateID', '')
            host = finding.get('host', '')
            
            timeline.append({
                'timestamp': timestamp,
                'template': template,
                'host': host,
                'severity': finding.get('info', {}).get('severity', '')
            })
        
        return timeline
    
    def export_to_excel(self, output_file):
        """Export results to Excel format"""
        df_data = []
        for finding in self.findings:
            df_data.append({
                'Template ID': finding.get('templateID', ''),
                'Host': finding.get('host', ''),
                'Severity': finding.get('info', {}).get('severity', ''),
                'Name': finding.get('info', {}).get('name', ''),
                'Description': finding.get('info', {}).get('description', ''),
                'Matched At': finding.get('matched-at', ''),
                'Timestamp': finding.get('timestamp', '')
            })
        
        df = pd.DataFrame(df_data)
        df.to_excel(output_file, index=False)

# Usage
processor = NucleiResultsProcessor('nuclei_results.json')
processor.load_results()

print("Severity Analysis:", processor.generate_severity_report())
print("Template Analysis:", processor.generate_template_analysis())

processor.export_to_excel('vulnerability_report.xlsx')
```

### 16 Integration with CI/CD Pipelines
```yaml
# .gitlab-ci.yml
stages:
  - security-scan

nuclei-scan:
  stage: security-scan
  image: projectdiscovery/nuclei:latest
  script:
    # Update templates
    - nuclei -update-templates
    
    # Scan staging environment
    - echo $STAGING_URLS > targets.txt
    - nuclei -l targets.txt -t http/vulnerabilities/ -o nuclei-results.json
    
    # Process results
    - |
      if [ -s nuclei-results.json ]; then
        echo "Vulnerabilities found!"
        cat nuclei-results.json
        exit 1
      else
        echo "No vulnerabilities found"
      fi
  only:
    - main
    - staging
  allow_failure: false
```

```yaml
# GitHub Actions Workflow
name: Nuclei Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  nuclei-scan:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v2
    
    - name: Nuclei Security Scan
      uses: projectdiscovery/nuclei-action@main
      with:
        target: https://example.com
        templates: http/vulnerabilities/
    
    - name: Upload Results
      uses: actions/upload-artifact@v2
      with:
        name: nuclei-results
        path: nuclei-output/
```

### 17 Advanced Configuration Management
```yaml
# nuclei-config.yaml
# Comprehensive Configuration File

templates:
  - /home/user/nuclei-templates
  - /opt/custom-templates

  # GitHub template repositories
  - https://github.com/projectdiscovery/nuclei-templates.git
  - https://github.com/your-org/custom-templates.git

reporting:
  # File outputs
  - type: file
    options:
      output: /var/log/nuclei/scan-{{timestamp}}.json
      format: json
  
  - type: file
    options:
      output: /var/log/nuclei/scan-{{timestamp}}.html
      format: html
  
  # Webhook integrations
  - type: webhook
    options:
      url: "https://hooks.slack.com/services/XXX/XXX/XXX"
      http-method: POST
      headers:
        Content-Type: "application/json"
        Authorization: "Bearer {{SLACK_TOKEN}}"
  
  # Database integrations
  - type: elasticsearch
    options:
      url: "http://elasticsearch:9200"
      index: "nuclei-scans-{{date}}"
      username: "{{ELASTIC_USER}}"
      password: "{{ELASTIC_PASSWORD}}"

scan:
  # Rate limiting
  rate-limit: 150
  bulk-size: 25
  concurrency: 25
  
  # Timeouts
  timeout: 10
  retries: 2
  max-host-error: 10
  
  # Headless browser
  headless: true
  system-resolvers: true
  
  # Filtering
  severity: info,low,medium,high,critical
  tags: cve,rce,sqli,xss

# Authentication for scanned targets
authentication:
  - type: basic
    username: "{{USERNAME}}"
    password: "{{PASSWORD}}"
  
  - type: bearer
    token: "{{BEARER_TOKEN}}"

# Custom headers for all requests
http:
  headers:
    User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    X-Scanner: "Nuclei Security Scanner"
    X-Scan-ID: "{{SCAN_ID}}"
```

### 18 Template Testing & Validation
```bash
#!/bin/bash
# template-validation-script.sh

# Template Syntax Validation
echo "Validating template syntax..."
for template in $(find custom-templates/ -name "*.yaml"); do
    echo "Validating $template"
    nuclei -validate -t "$template"
    if [ $? -ne 0 ]; then
        echo "ERROR: Template validation failed for $template"
        exit 1
    fi
done

# Template Testing Against Test Servers
echo "Testing templates against test servers..."
nuclei -u http://test-server.example.com -t custom-templates/ -o template-test-results.json

# Results Analysis
echo "Analyzing test results..."
CRITICAL_COUNT=$(jq 'select(.info.severity == "critical")' template-test-results.json | wc -l)
HIGH_COUNT=$(jq 'select(.info.severity == "high")' template-test-results.json | wc -l)

if [ $CRITICAL_COUNT -gt 0 ] || [ $HIGH_COUNT -gt 0 ]; then
    echo "CRITICAL: Templates detected vulnerabilities in test environment"
    exit 1
else
    echo "SUCCESS: All templates passed testing"
    exit 0
fi
```

### 19 Enterprise Deployment Architecture
```yaml
# enterprise-nuclei-deployment.yaml
deployment:
  architecture: distributed
  components:
    - name: nuclei-coordinator
      role: scan-orchestration
      replicas: 1
      resources:
        memory: "2Gi"
        cpu: "1"
    
    - name: nuclei-worker
      role: scan-execution
      replicas: 10
      resources:
        memory: "4Gi"
        cpu: "2"
    
    - name: results-processor
      role: results-analysis
      replicas: 2
      resources:
        memory: "8Gi"
        cpu: "4"
    
    - name: reporting-service
      role: report-generation
      replicas: 1
      resources:
        memory: "2Gi"
        cpu: "1"

  storage:
    - type: persistent
      name: template-storage
      size: "10Gi"
      mount: /templates
    
    - type: persistent
      name: results-storage
      size: "100Gi"
      mount: /results

  networking:
    - service: nuclei-coordinator
      port: 8080
      protocol: HTTP
    
    - service: results-processor
      port: 8081
      protocol: HTTP

  monitoring:
    - type: prometheus
      endpoint: /metrics
      port: 9090
    
    - type: grafana
      dashboard: nuclei-monitoring
      port: 3000
```

### 20 Compliance & Regulatory Scanning
```yaml
# compliance-scanning-workflow.yaml
id: compliance-scanning-workflow

info:
  name: Compliance and Regulatory Scanning Workflow
  author: compliance-team
  description: Automated compliance scanning for various regulations

workflows:
  # PCI DSS Compliance Scanning
  - template: http/security-misconfigurations/
    matchers:
      - name: pci-dss
        subtemplates:
          - template: http/vulnerabilities/ssl-tls/
          - template: http/vulnerabilities/authentication/
          - template: http/exposures/credit-card-data/
  
  # HIPAA Compliance Scanning
  - template: http/exposures/
    matchers:
      - name: hipaa
        subtemplates:
          - template: http/exposures/health-data/
          - template: http/vulnerabilities/phi-exposure/
          - template: http/misconfigurations/medical-systems/
  
  # GDPR Compliance Scanning
  - template: http/exposures/personal-data/
    matchers:
      - name: gdpr
        subtemplates:
          - template: http/exposures/pii/
          - template: http/exposures/email-addresses/
          - template: http/misconfigurations/privacy-settings/
  
  # NIST Framework Scanning
  - template: http/security-misconfigurations/
    matchers:
      - name: nist
        subtemplates:
          - template: http/vulnerabilities/access-control/
          - template: http/misconfigurations/audit-logging/
          - template: http/vulnerabilities/cryptography/

# Compliance Reporting
reporting:
  - type: file
    options:
      output: compliance-scan-{{timestamp}}.json
      format: json
  
  - type: file
    options:
      output: compliance-report-{{timestamp}}.pdf
      format: pdf
  
  - type: webhook
    options:
      url: {{COMPLIANCE_WEBHOOK_URL}}
      format: json
```

This comprehensive Nuclei framework provides security professionals with a complete methodology for automated vulnerability assessment, from basic template usage to advanced enterprise deployment. The framework covers template development, workflow automation, integration strategies, and compliance scanning to ensure comprehensive security testing across all organizational assets.