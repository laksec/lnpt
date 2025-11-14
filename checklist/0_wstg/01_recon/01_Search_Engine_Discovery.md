# 🔍 INFORMATION GATHERING | SEARCH ENGINE DISCOVERY RECONNAISSANCE FOR INFORMATION LEAKAGE

## Comprehensive Search Engine Discovery & Information Leakage Assessment

### 1 Search Engine Reconnaissance Fundamentals
- **Basic Search Engine Techniques:**
  - Google dorking operators testing
  - Bing advanced search testing
  - DuckDuckGo privacy-focused searching
  - Shodan IoT and service discovery
  - Censys network device discovery
  - ZoomEye web service discovery
  - BinaryEdge threat intelligence gathering
  - PublicWWW source code searching

- **Search Engine Operator Testing:**
  - Site-specific searching (site:)
  - File type filtering (filetype:)
  - Directory listing discovery (intitle:"index of")
  - Configuration file exposure (ext:xml | ext:conf | ext:cnf)
  - Database file exposure (ext:sql | ext:dbf | ext:mdb)
  - Log file exposure (ext:log | ext:txt)
  - Backup file exposure (ext:bak | ext:backup | ext:old)
  - Administrative interface discovery (intitle:"admin" | intitle:"login")

### 2 Corporate Information Exposure
- **Organization Intelligence Gathering:**
  - Employee information discovery testing
  - Email address harvesting testing
  - Organizational chart reconstruction testing
  - Internal directory exposure testing
  - Company document leakage testing
  - Meeting calendar exposure testing
  - Internal project information testing
  - Corporate network information testing

- **Infrastructure Discovery:**
  - Subdomain enumeration via search engines
  - IP range discovery and mapping
  - Server technology identification
  - Cloud infrastructure discovery
  - Third-party service identification
  - CDN and hosting provider discovery
  - Network topology reconstruction
  - Technology stack profiling

### 3 Technical Information Leakage
- **Source Code Exposure:**
  - GitHub repository discovery testing
  - GitLab project exposure testing
  - Bitbucket source code leakage testing
  - Pastebin code snippet discovery
  - Configuration file exposure testing
  - API key and secret discovery testing
  - Database connection string exposure
  - Environment variable leakage

- **Server Information Disclosure:**
  - Server banner grabbing via search engines
  - Error message information leakage
  - Debug information exposure testing
  - Stack trace disclosure testing
  - Directory listing exposure testing
  - Backup file accessibility testing
  - Log file public exposure testing
  - Version information disclosure

### 4 Authentication & Authorization Data
- **Credential Exposure:**
  - Password file discovery testing
  - Session token leakage testing
  - API key exposure testing
  - OAuth token discovery testing
  - Private key exposure testing
  - Certificate file discovery testing
  - Authentication log exposure
  - Password reset token leakage

- **Access Control Information:**
  - User role information disclosure
  - Permission structure exposure
  - Administrative interface discovery
  - Privilege escalation information
  - Authentication bypass techniques
  - Default credential discovery
  - Hardcoded credential exposure
  - Service account information

### 5 Application-Specific Information
- **Web Application Discovery:**
  - CMS-specific information leakage (WordPress, Joomla, Drupal)
  - E-commerce platform exposure (Magento, Shopify, WooCommerce)
  - Framework-specific information (Laravel, Django, Spring)
  - API endpoint discovery testing
  - Web service WSDL exposure
  - API documentation leakage
  - Mobile application backend discovery
  - Single-page application information

- **Database Information Exposure:**
  - Database dump discovery testing
  - SQL file exposure testing
  - Database backup accessibility
  - NoSQL database information
  - Data schema exposure testing
  - Query log disclosure testing
  - Database error information
  - ORM configuration exposure

### 6 Cloud & Infrastructure Leakage
- **Cloud Service Exposure:**
  - AWS S3 bucket discovery testing
  - Azure storage account exposure
  - Google Cloud Storage discovery
  - Cloud formation template exposure
  - Terraform state file discovery
  - Docker container information
  - Kubernetes configuration exposure
  - Cloud credential leakage

- **Infrastructure-as-Code Exposure:**
  - Terrafile file discovery
  - Ansible playbook exposure
  - Puppet manifest discovery
  - Chef recipe exposure testing
  - Dockerfile discovery testing
  - Kubernetes YAML exposure
  - Cloud formation template leakage
  - Infrastructure diagram exposure

### 7 Personal & Sensitive Data
- **Personal Information Leakage:**
  - PII exposure testing (names, addresses, phone numbers)
  - Email address harvesting testing
  - Social security number discovery
  - Credit card information exposure
  - Medical information leakage testing
  - Financial record exposure testing
  - Government ID discovery testing
  - Personal document leakage

- **Business Sensitive Information:**
  - Financial report exposure testing
  - Business plan discovery testing
  - Contract document leakage testing
  - Intellectual property exposure
  - Trade secret discovery testing
  - Merger and acquisition information
  - Internal communication leakage
  - Strategic planning documents

### 8 Social Media & Professional Networks
- **Social Platform Intelligence:**
  - LinkedIn organizational reconnaissance
  - Facebook company information gathering
  - Twitter employee activity monitoring
  - GitHub technical capability assessment
  - Stack Overflow technical expertise mapping
  - Reddit company mentions discovery
  - Professional forum participation analysis
  - Technical community engagement assessment

- **Employee Information Gathering:**
  - Employee skill mapping testing
  - Project participation analysis
  - Technology preference assessment
  - Professional relationship mapping
  - Contact information harvesting
  - Work history reconstruction
  - Social engineering preparation
  - Phishing target identification

### 9 Archived & Historical Information
- **Web Archive Reconnaissance:**
  - Wayback Machine historical analysis
  - Archive.is snapshot discovery
  - Google cache examination
  - Bing cached page analysis
  - Historical version comparison
  - Deleted content recovery testing
  - Content change tracking
  - Historical vulnerability discovery

- **Historical Data Analysis:**
  - Previous version exposure testing
  - Old backup file discovery
  - Historical configuration analysis
  - Legacy system information
  - Previous employee information
  - Historical security incident data
  - Old credential discovery
  - Previous infrastructure data

### 10 Specialized Search Engines
- **IoT and Device Discovery:**
  - Shodan device fingerprinting testing
  - Censys service discovery testing
  - ZoomEye web service mapping
  - BinaryEdge threat intelligence
  - Greynoise internet-wide scanning
  - Onyphe data collection analysis
  - Criminal IP device discovery
  - Netlas internet asset discovery

- **Code and Repository Search:**
  - GitHub code search reconnaissance
  - GitLab repository discovery
  - Bitbucket project searching
  - SourceForge code examination
  - Google BigQuery public datasets
  - PublicWWW source code searching
  - SearchCode code search engine
  - Nerdydata database querying

### 11 Automated Reconnaissance Framework
```yaml
Search Engine Reconnaissance Pipeline:
  Discovery Phase:
    - Target organization identification
    - Domain and subdomain enumeration
    - Technology stack fingerprinting
    - Employee information gathering
    - Infrastructure mapping
    - Cloud asset discovery
    - Social media intelligence
    - Historical data collection

  Analysis Phase:
    - Information correlation and analysis
    - Sensitivity classification
    - Risk assessment scoring
    - Attack surface mapping
    - Vulnerability identification
    - Exposure impact analysis
    - Data leakage assessment
    - Threat modeling preparation

  Exploitation Phase:
    - Credential harvesting testing
    - System access attempt testing
    - Social engineering preparation
    - Phishing campaign planning
    - Technical vulnerability exploitation
    - Access control testing
    - Privilege escalation planning
    - Persistence mechanism testing

  Reporting Phase:
    - Information exposure documentation
    - Risk assessment completion
    - Remediation recommendations
    - Monitoring implementation
    - Awareness training recommendations
    - Policy development guidance
    - Continuous monitoring setup
    - Compliance assessment
```

### 12 Testing Tools and Commands
```bash
# Google Dorking Examples
google-chrome "site:example.com ext:pdf"
google-chrome "site:example.com intitle:'index of'"
google-chrome "site:example.com ext:sql"
google-chrome "site:example.com 'password'"
google-chrome "site:example.com 'api_key'"
google-chrome "site:example.com 'admin'"
google-chrome "site:example.com filetype:log"
google-chrome "site:example.com inurl:admin"

# Shodan CLI Usage
shodan domain example.com
shodan search "org:Example Company"
shodan scan submit example.com
shodan download --limit 1000 example-com-results "hostname:example.com"

# GitHub Reconnaissance
gh api --paginate search/repositories?q=example.com
gh api --paginate search/code?q=example.com
gh repo list example-org --limit 100

# Subdomain Discovery
subfinder -d example.com -o subdomains.txt
amass enum -d example.com -o amass_results.txt
assetfinder --subs-only example.com | tee assetfinder.txt

# Email Harvesting
theharvester -d example.com -b google,linkedin,bing -f results.html
h8mail -t example.com -c all

# Wayback Machine
waybackurls example.com | tee wayback_urls.txt
gau example.com | sort -u | tee gau_urls.txt
```

### 13 Advanced Search Engine Payloads
```python
# Automated Search Engine Reconnaissance Tool
import requests
import time
import re
from bs4 import BeautifulSoup
import json

class SearchEngineRecon:
    def __init__(self):
        self.dork_patterns = {
            'sensitive_files': [
                'site:{} ext:sql "password"',
                'site:{} ext:log "error"',
                'site:{} ext:conf "password"',
                'site:{} "index of" "parent directory"',
                'site:{} ext:bak "backup"',
                'site:{} "api_key" "example.com"',
                'site:{} "admin" "password"',
                'site:{} "config" "database"'
            ],
            'employee_info': [
                'site:linkedin.com "Example Company"',
                'site:github.com "Example Company"',
                '"@example.com" "password"',
                '"Example Company" "email"',
                'site:twitter.com "Example Company"'
            ],
            'infrastructure': [
                'site:{} intitle:"Apache" "Server at"',
                'site:{} "nginx" "Server"',
                'site:{} "Microsoft-IIS" "Server"',
                'site:{} "X-Powered-By" "PHP"',
                'site:{} "Server: AWS"',
                'site:{} "Server: GSE"'
            ]
        }
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]

    def google_dork_search(self, domain, dork_type='sensitive_files'):
        """Perform automated Google dorking"""
        results = []
        
        for dork_template in self.dork_patterns[dork_type]:
            dork = dork_template.format(domain)
            search_url = f"https://www.google.com/search?q={dork}&num=100"
            
            try:
                headers = {'User-Agent': self.user_agents[0]}
                response = requests.get(search_url, headers=headers)
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Extract search results
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if 'url?q=' in href:
                        url = href.split('url?q=')[1].split('&')[0]
                        if domain in url:
                            results.append({
                                'dork': dork,
                                'url': url,
                                'title': link.get_text()
                            })
                
                time.sleep(2)  # Rate limiting
                
            except Exception as e:
                print(f"Error searching for {dork}: {e}")
        
        return results

    def shodan_search(self, api_key, query):
        """Perform Shodan search for infrastructure discovery"""
        results = []
        
        try:
            api = shodan.Shodan(api_key)
            results = api.search(query)
            
            for result in results['matches']:
                print(f"IP: {result['ip_str']}")
                print(f"Port: {result['port']}")
                print(f"Organization: {result.get('org', 'N/A')}")
                print(f"Data: {result['data'][:200]}...")
                print("-" * 50)
                
        except shodan.APIError as e:
            print(f"Shodan API Error: {e}")
        
        return results

    def github_recon(self, organization):
        """Perform GitHub reconnaissance"""
        repos_info = []
        
        try:
            # Search for organization repositories
            repos_url = f"https://api.github.com/orgs/{organization}/repos"
            response = requests.get(repos_url)
            repos = response.json()
            
            for repo in repos:
                repo_info = {
                    'name': repo['name'],
                    'description': repo['description'],
                    'url': repo['html_url'],
                    'language': repo['language'],
                    'stars': repo['stargazers_count'],
                    'forks': repo['forks_count']
                }
                
                # Search for sensitive content in repository
                sensitive_content = self.search_repo_content(repo['name'], organization)
                repo_info['sensitive_content'] = sensitive_content
                
                repos_info.append(repo_info)
                
        except Exception as e:
            print(f"GitHub recon error: {e}")
        
        return repos_info

    def search_repo_content(self, repo, organization):
        """Search for sensitive content in GitHub repository"""
        sensitive_patterns = {
            'api_keys': r'[aA][pP][iI]_?[kK]e[Yy].*=[\'"]?[A-Za-z0-9]{20,}',
            'passwords': r'[pP]asswo?r?d.*=[\'"]?[A-Za-z0-9!@#$%^&*()]{8,}',
            'database_urls': r'[dD]atabase[_ ][uU]rl.*=[\'"]?[A-Za-z0-9+/=]{10,}',
            'aws_keys': r'AKIA[0-9A-Z]{16}',
            'private_keys': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'
        }
        
        found_sensitive = []
        
        try:
            # Search code in repository
            search_url = f"https://api.github.com/search/code?q=repo:{organization}/{repo}+"
            
            for pattern_name, pattern in sensitive_patterns.items():
                search_response = requests.get(search_url + pattern)
                search_results = search_response.json()
                
                if search_results.get('total_count', 0) > 0:
                    found_sensitive.append({
                        'type': pattern_name,
                        'count': search_results['total_count'],
                        'items': search_results.get('items', [])
                    })
                    
        except Exception as e:
            print(f"Error searching repo content: {e}")
        
        return found_sensitive

    def wayback_machine_search(self, domain):
        """Search Wayback Machine for historical data"""
        wayback_urls = []
        
        try:
            # Get Wayback Machine URLs
            wayback_api = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey"
            response = requests.get(wayback_api)
            data = response.json()
            
            for entry in data[1:]:  # Skip header
                wayback_urls.append({
                    'url': entry[2],
                    'timestamp': entry[1],
                    'mimetype': entry[3],
                    'status': entry[4]
                })
                
        except Exception as e:
            print(f"Wayback Machine error: {e}")
        
        return wayback_urls

# Social Media Intelligence Gatherer
class SocialMediaIntelligence:
    def __init__(self):
        self.platforms = ['linkedin', 'twitter', 'github', 'facebook']

    def linkedin_recon(self, company_name):
        """Gather LinkedIn intelligence"""
        employees = []
        
        try:
            # Note: This is a conceptual example - actual LinkedIn scraping requires official API
            search_url = f"https://www.linkedin.com/search/results/people/?keywords={company_name}"
            
            # In practice, you would use:
            # - LinkedIn Sales Navigator
            # - Official LinkedIn API
            # - Legal compliance tools
            
            print(f"LinkedIn reconnaissance for {company_name} requires proper API access")
            
        except Exception as e:
            print(f"LinkedIn recon error: {e}")
        
        return employees

    def github_organization_analysis(self, org_name):
        """Analyze GitHub organization"""
        org_data = {}
        
        try:
            # Get organization info
            org_url = f"https://api.github.com/orgs/{org_name}"
            response = requests.get(org_url)
            org_data = response.json()
            
            # Get members
            members_url = f"https://api.github.com/orgs/{org_name}/members"
            members_response = requests.get(members_url)
            org_data['members'] = members_response.json()
            
            # Get repositories
            repos_url = f"https://api.github.com/orgs/{org_name}/repos"
            repos_response = requests.get(repos_url)
            org_data['repositories'] = repos_response.json()
            
        except Exception as e:
            print(f"GitHub organization analysis error: {e}")
        
        return org_data
```

### 14 Continuous Monitoring Setup
```python
# Search Engine Monitoring System
class InformationLeakageMonitor:
    def __init__(self, target_domains):
        self.target_domains = target_domains
        self.sensitive_keywords = [
            'password', 'secret', 'key', 'token', 'credential',
            'confidential', 'internal', 'admin', 'backup', 'database'
        ]
        
        self.previous_findings = set()

    def setup_continuous_monitoring(self):
        """Set up continuous search engine monitoring"""
        # Monitor Google for new exposures
        self.monitor_google_dorks()
        
        # Monitor GitHub for code leaks
        self.monitor_github_repos()
        
        # Monitor Pastebin for sensitive data
        self.monitor_paste_sites()
        
        # Monitor Shodan for infrastructure changes
        self.monitor_shodan_exposure()

    def monitor_google_dorks(self):
        """Continuously monitor Google for information leaks"""
        for domain in self.target_domains:
            new_findings = self.check_google_dorks(domain)
            if new_findings:
                self.alert_information_leak(domain, new_findings, 'Google')

    def monitor_github_repos(self):
        """Monitor GitHub for new code commits and leaks"""
        for domain in self.target_domains:
            # Extract organization from domain
            org_name = domain.split('.')[0]
            
            new_repos = self.check_new_github_repos(org_name)
            if new_repos:
                self.alert_github_activity(org_name, new_repos)

    def monitor_paste_sites(self):
        """Monitor paste sites for leaked information"""
        paste_sites = [
            'pastebin.com',
            'ghostbin.com',
            'justpaste.it',
            'paste.org'
        ]
        
        for site in paste_sites:
            leaks = self.search_paste_site(site)
            if leaks:
                self.alert_paste_leaks(site, leaks)

    def check_google_dorks(self, domain):
        """Check for new Google dork findings"""
        current_findings = set()
        
        dork_queries = [
            f'site:{domain} "password"',
            f'site:{domain} "api_key"',
            f'site:{domain} "secret"',
            f'site:{domain} "confidential"',
            f'site:{domain} filetype:sql',
            f'site:{domain} filetype:log'
        ]
        
        for query in dork_queries:
            findings = self.execute_google_search(query)
            current_findings.update(findings)
        
        # Compare with previous findings
        new_findings = current_findings - self.previous_findings
        self.previous_findings = current_findings
        
        return new_findings

    def search_paste_site(self, site):
        """Search paste site for target domain information"""
        leaks = []
        
        try:
            # This is a conceptual example - actual implementation varies by site
            search_url = f"https://{site}/search?q={self.target_domains[0]}"
            response = requests.get(search_url)
            
            # Parse response for relevant pastes
            if response.status_code == 200:
                # Extract paste URLs and content
                soup = BeautifulSoup(response.content, 'html.parser')
                paste_links = soup.find_all('a', href=True)
                
                for link in paste_links:
                    if '/raw/' in link['href']:
                        paste_content = self.fetch_paste_content(link['href'])
                        if self.contains_sensitive_info(paste_content):
                            leaks.append({
                                'url': link['href'],
                                'content_sample': paste_content[:500],
                                'sensitive_keywords': self.extract_sensitive_keywords(paste_content)
                            })
                            
        except Exception as e:
            print(f"Error searching {site}: {e}")
        
        return leaks

    def contains_sensitive_info(self, content):
        """Check if content contains sensitive information"""
        content_lower = content.lower()
        
        for keyword in self.sensitive_keywords:
            if keyword in content_lower:
                return True
        
        # Check for common patterns
        patterns = [
            r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}',  # Email
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b(?:\d[ -]*?){13,16}\b'  # Credit card
        ]
        
        for pattern in patterns:
            if re.search(pattern, content):
                return True
        
        return False

    def alert_information_leak(self, domain, findings, source):
        """Alert on information leakage findings"""
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'domain': domain,
            'source': source,
            'findings': list(findings),
            'severity': self.calculate_leak_severity(findings),
            'recommendations': self.generate_leak_recommendations(findings)
        }
        
        self.report_to_security_team(alert_data)
        logger.warning(f"Information leak detected: {alert_data}")

# Automated Dork Generator
class DorkGenerator:
    def __init__(self):
        self.dork_templates = {
            'files': {
                'documents': 'site:{} (ext:pdf OR ext:doc OR ext:docx OR ext:ppt OR ext:pptx)',
                'spreadsheets': 'site:{} (ext:xls OR ext:xlsx OR ext:csv)',
                'archives': 'site:{} (ext:zip OR ext:rar OR ext:tar OR ext:gz)',
                'configs': 'site:{} (ext:conf OR ext:config OR ext:cfg OR ext:ini)'
            },
            'content': {
                'login': 'site:{} (intitle:"login" OR inurl:"login")',
                'admin': 'site:{} (intitle:"admin" OR inurl:"admin")',
                'dashboard': 'site:{} (intitle:"dashboard" OR inurl:"dashboard")',
                'debug': 'site:{} ("debug" OR "testing" OR "staging")'
            },
            'sensitive': {
                'passwords': 'site:{} ("password" OR "passwd" OR "pwd")',
                'keys': 'site:{} ("api_key" OR "secret" OR "token")',
                'database': 'site:{} ("database" OR "db" OR "mysql" OR "postgresql")',
                'errors': 'site:{} ("error" OR "exception" OR "stack trace")'
            }
        }

    def generate_dorks(self, domain, dork_type='all'):
        """Generate comprehensive dorks for a domain"""
        dorks = []
        
        if dork_type == 'all':
            for category in self.dork_templates.values():
                for template in category.values():
                    dorks.append(template.format(domain))
        else:
            category = self.dork_templates.get(dork_type, {})
            for template in category.values():
                dorks.append(template.format(domain))
        
        return dorks

    def generate_advanced_dorks(self, domain, specific_terms=None):
        """Generate advanced dorks with specific terms"""
        advanced_dorks = []
        
        base_dorks = [
            f'site:{domain} "{term}"' for term in specific_terms
        ] if specific_terms else []
        
        # Combine with file types
        file_types = ['pdf', 'doc', 'xls', 'sql', 'log', 'bak']
        for file_type in file_types:
            advanced_dorks.append(f'site:{domain} ext:{file_type}')
        
        return advanced_dorks
```

### 15 Risk Assessment Matrix
```yaml
Search Engine Information Leakage Risk Assessment:
  Critical Risk Exposures:
    - Database dumps with user credentials
    - Source code with API keys and secrets
    - Configuration files with passwords
    - Private keys and certificates
    - Financial records and PII exposure
    - Administrative interface exposure
    - Backup files with sensitive data
    - Internal network documentation

  High Risk Exposures:
    - Employee contact information lists
    - Internal project documentation
    - Meeting notes and minutes
    - Network topology diagrams
    - System architecture documents
    - API documentation with examples
    - Error messages with stack traces
    - Log files with user activity

  Medium Risk Exposures:
    - Organizational charts
    - Departmental information
    - Technology stack details
    - Vendor and partner information
    - Marketing and sales materials
    - Public code repositories
    - Technical specifications
    - Development documentation

  Low Risk Exposures:
    - Public job postings
    - Company news and updates
    - General corporate information
    - Public financial reports
    - Marketing presentations
    - Press releases
    - Product documentation
    - Public-facing policies
```

### 16 Defense & Mitigation Testing
```python
# Information Leakage Defense Tester
class LeakageDefenseTester:
    def __init__(self, target_domain):
        self.target_domain = target_domain
        self.test_cases = []

    def test_robots_txt(self):
        """Test robots.txt for information leakage"""
        results = []
        
        try:
            robots_url = f"https://{self.target_domain}/robots.txt"
            response = requests.get(robots_url)
            
            if response.status_code == 200:
                content = response.text
                
                # Check for sensitive directories
                sensitive_indicators = [
                    '/admin/', '/config/', '/database/', '/backup/',
                    '/logs/', '/temp/', '/tmp/', '/secret/'
                ]
                
                for indicator in sensitive_indicators:
                    if indicator in content:
                        results.append({
                            'test': 'Robots.txt Analysis',
                            'issue': f'Sensitive directory exposed: {indicator}',
                            'severity': 'MEDIUM',
                            'recommendation': 'Review robots.txt for sensitive path exposure'
                        })
        
        except Exception as e:
            results.append({
                'test': 'Robots.txt Analysis',
                'issue': f'Error accessing robots.txt: {str(e)}',
                'severity': 'LOW',
                'recommendation': 'Ensure robots.txt is properly configured'
            })
        
        return results

    def test_directory_listing(self):
        """Test for directory listing vulnerabilities"""
        results = []
        
        test_directories = [
            '/images/', '/css/', '/js/', '/admin/', '/backup/',
            '/logs/', '/temp/', '/uploads/', '/assets/'
        ]
        
        for directory in test_directories:
            test_url = f"https://{self.target_domain}{directory}"
            
            try:
                response = requests.get(test_url)
                
                if response.status_code == 200:
                    # Check if directory listing is enabled
                    if 'Index of' in response.text or 'Directory listing' in response.text:
                        results.append({
                            'test': 'Directory Listing',
                            'issue': f'Directory listing enabled: {directory}',
                            'severity': 'MEDIUM',
                            'recommendation': 'Disable directory listing'
                        })
            
            except Exception as e:
                continue
        
        return results

    def test_error_messages(self):
        """Test for information disclosure in error messages"""
        results = []
        
        # Trigger various errors
        test_payloads = [
            '/nonexistent-page-12345',
            '/../etc/passwd',
            '/api/v1/invalid-endpoint',
            '/admin/../config'
        ]
        
        for payload in test_payloads:
            test_url = f"https://{self.target_domain}{payload}"
            
            try:
                response = requests.get(test_url)
                
                # Check for information disclosure in error messages
                sensitive_info_indicators = [
                    'stack trace', 'exception', 'error at', 'file path',
                    'database', 'sql', 'mysql', 'postgresql', 'oracle'
                ]
                
                for indicator in sensitive_info_indicators:
                    if indicator.lower() in response.text.lower():
                        results.append({
                            'test': 'Error Message Disclosure',
                            'issue': f'Sensitive information in error: {indicator}',
                            'severity': 'HIGH',
                            'recommendation': 'Implement custom error pages'
                        })
                        break
            
            except Exception as e:
                continue
        
        return results

    def test_github_exposure(self):
        """Test for information exposure on GitHub"""
        results = []
        
        try:
            # Search for company-related repositories
            search_url = f"https://api.github.com/search/repositories?q={self.target_domain}"
            response = requests.get(search_url)
            repos = response.json().get('items', [])
            
            for repo in repos:
                # Check for sensitive files in repository
                sensitive_files = ['config.json', '.env', 'secrets.yml', 'database.yml']
                
                for file in sensitive_files:
                    file_url = f"https://raw.githubusercontent.com/{repo['full_name']}/main/{file}"
                    file_response = requests.get(file_url)
                    
                    if file_response.status_code == 200:
                        results.append({
                            'test': 'GitHub Exposure',
                            'issue': f'Sensitive file exposed: {file} in {repo["full_name"]}',
                            'severity': 'CRITICAL',
                            'recommendation': 'Remove sensitive files from public repositories'
                        })
        
        except Exception as e:
            results.append({
                'test': 'GitHub Exposure',
                'issue': f'Error checking GitHub: {str(e)}',
                'severity': 'LOW',
                'recommendation': 'Monitor GitHub for organizational leaks'
            })
        
        return results

    def generate_defense_report(self):
        """Generate comprehensive defense assessment report"""
        robots_test = self.test_robots_txt()
        directory_test = self.test_directory_listing()
        error_test = self.test_error_messages()
        github_test = self.test_github_exposure()
        
        report = {
            'robots_txt_analysis': robots_test,
            'directory_listing_analysis': directory_test,
            'error_message_analysis': error_test,
            'github_exposure_analysis': github_test,
            'overall_security_score': self.calculate_security_score(
                robots_test, directory_test, error_test, github_test
            ),
            'recommendations': self.generate_security_recommendations(
                robots_test, directory_test, error_test, github_test
            )
        }
        
        return report
```

### 17 Remediation Checklist
```markdown
## ✅ SEARCH ENGINE INFORMATION LEAKAGE REMEDIATION CHECKLIST

### Technical Controls:
- [ ] Implement proper robots.txt configuration
- [ ] Disable directory listing on web servers
- [ ] Configure custom error pages
- [ ] Remove sensitive information from source code
- [ ] Secure configuration files and backups
- [ ] Implement proper access controls
- [ ] Use environment variables for secrets
- [ ] Regular security scanning and monitoring

### Code Management:
- [ ] Implement pre-commit hooks for secret detection
- [ ] Use  gitignore properly for sensitive files
- [ ] Conduct regular code repository audits
- [ ] Implement secret scanning in CI/CD pipelines
- [ ] Use private repositories for internal projects
- [ ] Educate developers on secure coding practices
- [ ] Implement code review processes
- [ ] Use automated security testing tools

### Employee Awareness:
- [ ] Conduct security awareness training
- [ ] Establish social media usage policies
- [ ] Implement data classification policies
- [ ] Train employees on information sharing
- [ ] Establish clear BYOD policies
- [ ] Implement phishing awareness training
- [ ] Regular security policy reviews
- [ ] Incident response training

### Monitoring & Detection:
- [ ] Implement Google Alerts for company mentions
- [ ] Set up GitHub monitoring for code leaks
- [ ] Monitor paste sites for sensitive data
- [ ] Implement dark web monitoring
- [ ] Set up brand monitoring services
- [ ] Regular search engine reconnaissance
- [ ] Implement SIEM for detection
- [ ] Continuous external threat monitoring

### Incident Response:
- [ ] Establish information leakage response plan
- [ ] Implement takedown procedures for leaked data
- [ ] Establish legal response capabilities
- [ ] Create communication plans for breaches
- [ ] Practice incident response scenarios
- [ ] Maintain contact with service providers
- [ ] Establish relationships with legal counsel
- [ ] Regular incident response plan testing

### Policy & Governance:
- [ ] Develop information classification policy
- [ ] Establish data handling procedures
- [ ] Implement third-party risk management
- [ ] Create social media governance policies
- [ ] Establish clear roles and responsibilities
- [ ] Implement regular security assessments
- [ ] Develop business continuity plans
- [ ] Establish compliance monitoring

### Technical Hardening:
- [ ] Implement web application firewalls (WAF)
- [ ] Configure security headers properly
- [ ] Use subresource integrity (SRI)
- [ ] Implement content security policy (CSP)
- [ ] Regular vulnerability scanning
- [ ] Penetration testing exercises
- [ ] Security code reviews
- [ ] Infrastructure security hardening
```

### 18 Secure Configuration Examples
```nginx
# Secure Nginx Configuration to Prevent Information Leakage
server {
    listen 80;
    server_name example.com;
    
    # Disable server tokens
    server_tokens off;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    # Disable directory listing
    autoindex off;
    
    # Custom error pages
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    
    # Location blocks for sensitive directories
    location /admin/ {
        deny all;
        return 404;
    }
    
    location /config/ {
        deny all;
        return 404;
    }
    
    location /backup/ {
        deny all;
        return 404;
    }
    
    # Restrict access to sensitive files
    location ~* \.(env|config|sql|bak|backup|old)$ {
        deny all;
        return 404;
    }
}

# robots.txt to prevent sensitive directory indexing
User-agent: *
Disallow: /admin/
Disallow: /config/
Disallow: /backup/
Disallow: /logs/
Disallow: /database/
Disallow: /tmp/
Disallow: /temp/
```

```python
# Django Settings to Prevent Information Leakage
# settings.py

# Security settings
DEBUG = False
SECRET_KEY = os.environ.get('SECRET_KEY')  # Use environment variables

# Security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Custom error handlers
handler404 = 'myapp.views.custom_404'
handler500 = 'myapp.views.custom_500'

# Logging configuration - avoid sensitive data in logs
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
        'remove_sensitive_data': {
            '()': 'myapp.logging.SensitiveDataFilter',
        }
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': '/var/log/django/app.log',
            'formatter': 'verbose',
            'filters': ['remove_sensitive_data']
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}
```

### 19 Testing Completion Checklist
```markdown
## ✅ SEARCH ENGINE DISCOVERY RECONNAISSANCE TESTING COMPLETION CHECKLIST

### Basic Search Engine Testing:
- [ ] Google dorking testing completed
- [ ] Bing advanced search testing completed
- [ ] DuckDuckGo privacy search testing completed
- [ ] Specialized search engine testing completed
- [ ] File type specific searching completed
- [ ] Directory listing discovery completed
- [ ] Configuration file exposure testing completed
- [ ] Backup file discovery testing completed

### Corporate Intelligence Gathering:
- [ ] Employee information discovery completed
- [ ] Organizational structure mapping completed
- [ ] Email address harvesting completed
- [ ] Internal document discovery completed
- [ ] Meeting information gathering completed
- [ ] Project information discovery completed
- [ ] Network information gathering completed
- [ ] Infrastructure mapping completed

### Technical Information Discovery:
- [ ] Source code repository searching completed
- [ ] Configuration file exposure testing completed
- [ ] API key and secret discovery completed
- [ ] Database information gathering completed
- [ ] Error message information leakage testing
- [ ] Log file exposure testing completed
- [ ] Version information disclosure testing
- [ ] Debug information exposure testing

### Cloud & Infrastructure Discovery:
- [ ] Cloud storage bucket discovery completed
- [ ] Infrastructure-as-code exposure testing
- [ ] Container configuration discovery completed
- [ ] API endpoint discovery completed
- [ ] Service configuration exposure testing
- [ ] Network device discovery completed
- [ ] Third-party service identification completed
- [ ] Technology stack profiling completed

### Social Media Intelligence:
- [ ] LinkedIn organizational reconnaissance completed
- [ ] GitHub technical assessment completed
- [ ] Twitter activity monitoring completed
- [ ] Professional network analysis completed
- [ ] Employee skill mapping completed
- [ ] Project participation analysis completed
- [ ] Contact information harvesting completed
- [ ] Social engineering preparation completed

### Historical & Archive Research:
- [ ] Wayback Machine analysis completed
- [ ] Web archive snapshot review completed
- [ ] Historical version comparison completed
- [ ] Deleted content recovery testing completed
- [ ] Previous version exposure testing completed
- [ ] Legacy system information gathering completed
- [ ] Historical incident data collection completed
- [ ] Content change tracking completed

### Specialized Search Engine Usage:
- [ ] Shodan device discovery completed
- [ ] Censys service enumeration completed
- [ ] ZoomEye web service mapping completed
- [ ] GitHub code searching completed
- [ ] Paste site monitoring completed
- [ ] IoT device discovery completed
- [ ] Network service identification completed
- [ ] Public dataset analysis completed

### Impact Assessment:
- [ ] Information sensitivity classification completed
- [ ] Exposure risk assessment completed
- [ ] Business impact analysis completed
- [ ] Compliance violation assessment completed
- [ ] Remediation priority assignment completed
- [ ] Security control gap analysis completed
- [ ] Monitoring recommendation development completed
- [ ] Policy enhancement identification completed
```

### 20 Executive Reporting Template
```markdown
# Search Engine Discovery & Information Leakage Assessment Report

## Executive Summary
- Total information exposure findings: [Number]
- Critical data leakage incidents: [Number]
- High-risk information exposures: [Number]
- Employee information disclosures: [Number]
- Technical configuration exposures: [Number]
- Overall information security score: [A-F Grade]

## Critical Findings
### [Critical Finding Title]
- **Exposure Type:** [Data Leakage/Configuration Exposure/Credential Disclosure]
- **Source:** [Search Engine/Social Media/Code Repository]
- **Sensitivity Level:** [Public/Internal/Confidential/Restricted]
- **Impact:** [Data Breach/System Compromise/Reputation Damage]
- **Exposure Duration:** [Time Period]
- **Remediation Priority:** [Critical/High/Medium/Low]

## Technical Analysis
### Information Exposure Chain
1. **Discovery Method**
   - Search technique: [Google Dorking/GitHub Search/Shodan Query]
   - Exposure vector: [Public Repository/Unsecured Storage/Misconfiguration]
   - Access level: [Public/Authenticated/Internal]

2. **Exposed Information**
   - Data category: [Credentials/Configuration/Business Data/Personal Data]
   - Sensitivity classification: [Public/Internal/Confidential/Restricted]
   - Data volume: [Number of records/Files/Entries]
   - Exposure scope: [Partial/Complete/Targeted]

3. **Impact Assessment**
   - Data confidentiality: [Complete Exposure/Limited Exposure/No Exposure]
   - System security: [Direct Compromise/Indirect Risk/No Impact]
   - Business impact: [Financial Loss/Reputation Damage/Operational Impact]
   - Compliance impact: [Regulatory Violations/Contract Breaches/Legal Liability]

## Proof of Concept
### Exposure Demonstration
```http
[Example of discovered exposed information]
```

### Impact Verification
- [ ] Data accessibility confirmed
- [ ] Sensitivity validation completed
- [ ] Exposure scope verified
- [ ] Business impact assessed
- [ ] Compliance violation confirmed
- [ ] Remediation requirements identified
- [ ] Monitoring gaps documented
- [ ] Policy violations recorded

## Remediation Recommendations
### Immediate Actions
- [ ] Remove exposed data from public access
- [ ] Revoke compromised credentials
- [ ] Secure misconfigured services
- [ ] Implement access controls
- [ ] Conduct employee awareness training

### Medium-term Improvements
- [ ] Implement automated monitoring
- [ ] Establish data classification policies
- [ ] Enhance security controls
- [ ] Conduct regular security assessments
- [ ] Implement developer security training

### Long-term Strategies
- [ ] Develop comprehensive information governance
- [ ] Implement data loss prevention (DLP)
- [ ] Establish security culture
- [ ] Continuous security monitoring
- [ ] Regular policy review and updates

## Risk Assessment Summary
- **Overall Risk Level:** [Critical/High/Medium/Low]
- **Business Impact:** [Severe/Moderate/Minor]
- **Exposure Likelihood:** [Certain/Likely/Possible/Unlikely]
- **Remediation Timeline:** [Immediate/1-2 weeks/1+ month]
- **Compliance Impact:** [Regulatory violations/Standards non-compliance]
- **Reputation Impact:** [Significant/Moderate/Minimal]
- **Financial Impact:** [Major/Moderate/Minor]
```

This comprehensive Search Engine Discovery Reconnaissance checklist provides security professionals with a complete methodology for identifying, assessing, and mitigating information leakage through search engines and public sources. The framework covers technical reconnaissance, corporate intelligence gathering, social media analysis, and continuous monitoring strategies to protect organizations from accidental information exposure and targeted intelligence gathering.