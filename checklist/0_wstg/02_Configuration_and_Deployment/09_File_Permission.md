
# 🔐 CONFIGURATION AND DEPLOYMENT MANAGEMENT | TEST FILE PERMISSIONS

## Comprehensive File Permission Security Assessment

### 1 File System Permission Discovery
- **File Permission Enumeration:**
  - File ownership mapping and analysis (`ls -la`, `getfacl`)
  - Permission bit analysis (read, write, execute)
  - Special permission flag testing (setuid, setgid, sticky bit)
  - Access Control List (ACL) enumeration and analysis
  - Extended attribute discovery and analysis
  - File capability analysis (Linux capabilities)
  - SELinux/AppArmor context analysis
  - File system mount option analysis

- **Permission Pattern Recognition:**
  - World-writable file and directory discovery
  - Setuid/setgid executable identification
  - Configuration file permission analysis
  - Log file permission assessment
  - Temporary file permission testing
  - Backup file permission analysis
  - Development file permission testing
  - Hidden file permission assessment

### 2 Critical File Permission Testing
- **System File Permissions:**
  - System binary permission testing (`/bin`, `/sbin`, `/usr/bin`)
  - Configuration file permission analysis (`/etc`, `/etc/passwd`, `/etc/shadow`)
  - Boot file permission testing (`/boot`, initramfs, kernel)
  - Library file permission assessment (`/lib`, `/usr/lib`, `/lib64`)
  - Log file permission analysis (`/var/log`)
  - Temporary file permission testing (`/tmp`, `/var/tmp`)
  - Home directory permission assessment (`/home`, `/root`)
  - Device file permission testing (`/dev`)

- **Application File Permissions:**
  - Web application file permission analysis
  - Database file permission testing
  - Application configuration file assessment
  - Application log file permission analysis
  - Application temporary file testing
  - Application backup file assessment
  - Application source code permission testing
  - Application data file permission analysis

### 3 Privilege Escalation Vector Testing
- **Setuid/Setgid Analysis:**
  - Setuid root binary discovery and analysis
  - Setgid binary identification and assessment
  - Custom setuid/setgid executable testing
  - Setuid shell script analysis
  - Setuid programming errors testing
  - Setuid symlink vulnerability testing
  - Setuid environment variable testing
  - Setuid path manipulation testing

- **Capability Analysis:**
  - Linux capability-enabled binary discovery
  - Dangerous capability testing (CAP_SYS_ADMIN, CAP_DAC_OVERRIDE)
  - Capability escalation vector analysis
  - Container capability assessment
  - Service capability analysis
  - User namespace capability testing
  - File capability inheritance testing
  - Capability bounding set analysis

### 4 File Permission Vulnerability Testing
- **World-Writable File Risks:**
  - World-writable system file testing
  - World-writable configuration file analysis
  - World-writable executable testing
  - World-writable directory assessment
  - World-writable cron job testing
  - World-writable service file analysis
  - World-writable socket testing
  - World-writable device file assessment

- **Insecure Permission Patterns:**
  - Configuration file readable by non-privileged users
  - Log file writable by unauthorized users
  - Executable files with excessive permissions
  - Data files accessible by incorrect users/groups
  - Backup files with weak permissions
  - Temporary files with insecure permissions
  - Symbolic link permission testing
  - Hard link permission analysis

### 5 Access Control List (ACL) Testing
- **ACL Configuration Analysis:**
  - Extended ACL discovery and enumeration
  - ACL permission inheritance testing
  - ACL mask value analysis
  - Default ACL assessment
  - ACL permission escalation testing
  - ACL backup and restore testing
  - ACL consistency validation
  - ACL security control effectiveness

- **ACL Security Assessment:**
  - Overly permissive ACL identification
  - ACL conflict detection and analysis
  - ACL inheritance vulnerability testing
  - ACL modification security testing
  - ACL removal impact assessment
  - ACL backup security testing
  - ACL restore vulnerability testing
  - ACL monitoring capability assessment

### 6 Special Permission Flag Testing
- **Sticky Bit Analysis:**
  - Sticky bit directory discovery (`/tmp`, `/var/tmp`)
  - Sticky bit effectiveness testing
  - Sticky bit bypass techniques testing
  - Sticky bit inheritance testing
  - Sticky bit removal impact assessment
  - Sticky bit configuration testing
  - Sticky bit security control validation
  - Sticky bit monitoring testing

- **Immutable Flag Testing:**
  - Immutable file attribute discovery (`chattr +i`)
  - Immutable flag effectiveness testing
  - Immutable flag bypass techniques
  - Immutable flag inheritance testing
  - Immutable flag security assessment
  - Immutable flag configuration testing
  - Immutable flag monitoring validation
  - Immutable flag removal testing

### 7 Container File Permission Testing
- **Container Filesystem Analysis:**
  - Container image layer permission analysis
  - Container volume permission testing
  - Container bind mount permission assessment
  - Container tmpfs mount permission testing
  - Container configuration file permission analysis
  - Container secret file permission testing
  - Container environment file permission assessment
  - Container runtime file permission testing

- **Container Security Context:**
  - User namespace mapping analysis
  - Container root permission assessment
  - Container capability analysis
  - Container SELinux/AppArmor context testing
  - Container seccomp profile analysis
  - Container security context inheritance
  - Container privilege escalation testing
  - Container breakout vulnerability assessment

### 8 Cloud Storage Permission Testing
- **Cloud File Storage Analysis:**
  - AWS S3 bucket permission testing
  - Azure Blob Storage permission assessment
  - Google Cloud Storage permission testing
  - Cloud file share permission analysis
  - Cloud backup permission testing
  - Cloud snapshot permission assessment
  - Cloud object storage permission testing
  - Cloud file sync permission analysis

- **Cloud IAM Integration:**
  - IAM role file access testing
  - Service account file permission assessment
  - Resource-based policy analysis
  - Identity-based policy testing
  - Cross-account access assessment
  - Public access configuration testing
  - Encryption context permission analysis
  - Conditional permission testing

### 9 Automated File Permission Testing Framework
```yaml
File Permission Security Assessment Pipeline:
  Discovery Phase:
    - File system permission enumeration and mapping
    - Special permission flag discovery (setuid, setgid, sticky)
    - Access Control List (ACL) discovery and analysis
    - Extended attribute enumeration
    - Linux capability discovery
    - SELinux/AppArmor context analysis
    - Container filesystem permission mapping
    - Cloud storage permission discovery

  Analysis Phase:
    - Permission risk classification and scoring
    - Privilege escalation vector identification
    - Security control effectiveness evaluation
    - Compliance requirement validation
    - Business impact assessment
    - Risk exposure analysis
    - Vulnerability prioritization
    - Security gap analysis

  Testing Phase:
    - Permission escalation testing
    - Access bypass testing
    - Security control evasion testing
    - Container breakout testing
    - Cloud storage access testing
    - Backup file access testing
    - Configuration file manipulation testing
    - Log file tampering testing

  Validation Phase:
    - Security control effectiveness verification
    - Remediation implementation validation
    - Permission hardening validation
    - Monitoring system validation
    - Documentation accuracy verification
    - Management approval and sign-off
    - Continuous monitoring setup
    - Automated alerting configuration
```

### 10 File Permission Testing Tools & Commands
```bash
# Basic File Permission Analysis
find / -type f -perm -o+w 2>/dev/null                    # World-writable files
find / -type f -perm -4000 2>/dev/null                   # setuid files
find / -type f -perm -2000 2>/dev/null                   # setgid files
find / -type d -perm -1000 2>/dev/null                   # Sticky bit directories
getfacl /path/to/file                                    # ACL analysis
lsattr /path/to/file                                     # Extended attributes
getcap -r / 2>/dev/null                                  # Linux capabilities

# Comprehensive Permission Scanning
linpeas.sh --permissions                                 # Linux privilege escalation
linux-exploit-suggester.sh -k                            # Kernel and permission issues
lynis audit system                                       # System hardening audit
lynis audit file-permissions                             # File permission audit

# Advanced Permission Analysis
python3 permission_analyzer.py --path / --recursive --output permissions.json
ruby file_security_scanner.rb --directory / --scan-permissions --verbose
perl file_audit.pl --root / --check setuid,setgid,world_writable

# Container Permission Testing
docker run --rm -v /:/host alpine find /host -perm -o+w   # Container host file access
docker image history <image>                             # Image layer permissions
docker run --rm -it <image> find / -perm -4000          # Container setuid files

# Cloud Storage Permission Testing
aws s3api get-bucket-acl --bucket my-bucket             # S3 bucket ACL
aws s3api get-bucket-policy --bucket my-bucket          # S3 bucket policy
az storage container list --account-name mystorage      # Azure container list
gcloud storage buckets list --format="json"             # GCP bucket list

# Continuous Monitoring
watch_permissions --config permissions.conf --interval 300 --alert
file_integrity_monitor --paths /etc,/bin,/sbin --database file_perms.db
tripwire --check --interactive                          # File integrity check
```

### 11 Advanced File Permission Testing Implementation
```python
# Comprehensive File Permission Security Testing Tool
import os
import stat
import pwd
import grp
import subprocess
import json
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import hashlib

class FilePermissionTester:
    def __init__(self, target_paths=None):
        self.target_paths = target_paths or ['/', '/etc', '/bin', '/sbin', '/usr', '/var', '/home']
        self.test_results = {
            'permission_analysis': {},
            'vulnerability_assessment': {},
            'risk_analysis': {},
            'security_recommendations': {}
        }

    def comprehensive_permission_testing(self):
        """Perform comprehensive file permission security testing"""
        print("[+] Starting comprehensive file permission security testing")
        
        # Execute all permission testing methods
        self.analyze_file_permissions()
        self.identify_special_permissions()
        self.analyze_access_control_lists()
        self.test_linux_capabilities()
        self.perform_vulnerability_assessment()
        
        return {
            'test_results': self.test_results,
            'security_assessment': self.perform_security_assessment(),
            'risk_analysis': self.perform_risk_analysis(),
            'remediation_recommendations': self.generate_recommendations()
        }

    def analyze_file_permissions(self):
        """Analyze file permissions across target paths"""
        print("[+] Analyzing file permissions...")
        
        permission_analysis = {}
        
        for target_path in self.target_paths:
            if os.path.exists(target_path):
                analysis = self.analyze_directory_permissions(target_path)
                permission_analysis[target_path] = analysis
        
        self.test_results['permission_analysis'] = permission_analysis

    def analyze_directory_permissions(self, directory_path):
        """Analyze permissions for a directory and its contents"""
        analysis = {
            'directory_info': {},
            'file_permissions': {},
            'risk_files': {},
            'statistics': {}
        }
        
        try:
            dir_stat = os.stat(directory_path)
            analysis['directory_info'] = {
                'path': directory_path,
                'permissions': oct(stat.S_IMODE(dir_stat.st_mode)),
                'owner': pwd.getpwuid(dir_stat.st_uid).pw_name,
                'group': grp.getgrgid(dir_stat.st_gid).gr_name,
                'size': dir_stat.st_size
            }
            
            # Analyze files in directory
            risk_files = self.identify_risky_files(directory_path)
            analysis['risk_files'] = risk_files
            
            # Generate statistics
            analysis['statistics'] = self.generate_permission_statistics(directory_path)
            
        except (PermissionError, OSError) as e:
            analysis['directory_info']['error'] = str(e)
        
        return analysis

    def identify_risky_files(self, directory_path):
        """Identify files with risky permissions"""
        risky_files = {
            'world_writable': [],
            'setuid_setgid': [],
            'unowned_files': [],
            'insecure_configs': [],
            'insecure_logs': [],
            'insecure_tmp': []
        }
        
        try:
            for root, dirs, files in os.walk(directory_path):
                # Check directories
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    try:
                        dir_stat = os.stat(dir_path)
                        permissions = stat.S_IMODE(dir_stat.st_mode)
                        
                        # World-writable directories
                        if permissions & stat.S_IWOTH:
                            risky_files['world_writable'].append({
                                'path': dir_path,
                                'permissions': oct(permissions),
                                'owner': pwd.getpwuid(dir_stat.st_uid).pw_name
                            })
                        
                        # Sticky bit directories
                        if permissions & stat.S_ISVTX:
                            # Check if it's a known risky sticky directory
                            if dir_path not in ['/tmp', '/var/tmp']:
                                risky_files['insecure_tmp'].append({
                                    'path': dir_path,
                                    'permissions': oct(permissions),
                                    'owner': pwd.getpwuid(dir_stat.st_uid).pw_name
                                })
                    
                    except (OSError, PermissionError):
                        continue
                
                # Check files
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    try:
                        file_stat = os.stat(file_path)
                        permissions = stat.S_IMODE(file_stat.st_mode)
                        
                        # World-writable files
                        if permissions & stat.S_IWOTH:
                            risky_files['world_writable'].append({
                                'path': file_path,
                                'permissions': oct(permissions),
                                'owner': pwd.getpwuid(file_stat.st_uid).pw_name
                            })
                        
                        # setuid/setgid files
                        if permissions & stat.S_ISUID:
                            risky_files['setuid_setgid'].append({
                                'path': file_path,
                                'type': 'setuid',
                                'permissions': oct(permissions),
                                'owner': pwd.getpwuid(file_stat.st_uid).pw_name
                            })
                        
                        if permissions & stat.S_ISGID:
                            risky_files['setuid_setgid'].append({
                                'path': file_path,
                                'type': 'setgid',
                                'permissions': oct(permissions),
                                'owner': pwd.getpwuid(file_stat.st_uid).pw_name
                            })
                        
                        # Configuration files with insecure permissions
                        if self.is_configuration_file(file_path):
                            if self.has_insecure_config_permissions(file_path, file_stat):
                                risky_files['insecure_configs'].append({
                                    'path': file_path,
                                    'permissions': oct(permissions),
                                    'owner': pwd.getpwuid(file_stat.st_uid).pw_name
                                })
                        
                        # Log files with insecure permissions
                        if self.is_log_file(file_path):
                            if self.has_insecure_log_permissions(file_path, file_stat):
                                risky_files['insecure_logs'].append({
                                    'path': file_path,
                                    'permissions': oct(permissions),
                                    'owner': pwd.getpwuid(file_stat.st_uid).pw_name
                                })
                    
                    except (OSError, PermissionError):
                        continue
        
        except (OSError, PermissionError) as e:
            print(f"[-] Error walking directory {directory_path}: {e}")
        
        return risky_files

    def is_configuration_file(self, file_path):
        """Check if file is a configuration file"""
        config_patterns = ['.conf', '.cfg', '.ini', '.config', '.yml', '.yaml', '.xml']
        config_dirs = ['/etc', '/config', '/conf']
        
        return (any(file_path.endswith(pattern) for pattern in config_patterns) or
                any(file_path.startswith(dir_path) for dir_path in config_dirs))

    def has_insecure_config_permissions(self, file_path, file_stat):
        """Check if configuration file has insecure permissions"""
        permissions = stat.S_IMODE(file_stat.st_mode)
        
        # Config files should not be world-readable if they contain secrets
        if permissions & stat.S_IROTH:
            return True
        
        # Config files should not be world-writable
        if permissions & stat.S_IWOTH:
            return True
        
        # Config files should not be group-writable unless necessary
        if permissions & stat.S_IWGRP:
            # Check if this is expected for this specific file
            if file_path not in ['/etc/shadow', '/etc/gshadow']:
                return True
        
        return False

    def is_log_file(self, file_path):
        """Check if file is a log file"""
        log_patterns = ['.log', '.audit', '.trace']
        log_dirs = ['/var/log', '/var/audit', '/opt/logs']
        
        return (any(file_path.endswith(pattern) for pattern in log_patterns) or
                any(file_path.startswith(dir_path) for dir_path in log_dirs))

    def has_insecure_log_permissions(self, file_path, file_stat):
        """Check if log file has insecure permissions"""
        permissions = stat.S_IMODE(file_stat.st_mode)
        
        # Log files should not be world-writable
        if permissions & stat.S_IWOTH:
            return True
        
        # Log files should not be world-readable if they contain sensitive data
        if permissions & stat.S_IROTH:
            # Some log files can be world-readable, but check specific cases
            sensitive_logs = ['secure', 'auth', 'sudo', 'private']
            if any(sensitive in file_path for sensitive in sensitive_logs):
                return True
        
        return False

    def identify_special_permissions(self):
        """Identify files with special permissions (setuid, setgid, sticky)"""
        print("[+] Identifying special permissions...")
        
        special_perms = {
            'setuid_files': [],
            'setgid_files': [],
            'sticky_directories': [],
            'immutable_files': []
        }
        
        # Find setuid files
        try:
            result = subprocess.run(['find', '/', '-type', 'f', '-perm', '-4000', '-ls', '2>/dev/null'], 
                                  capture_output=True, text=True, shell=True)
            for line in result.stdout.split('\n'):
                if line.strip():
                    special_perms['setuid_files'].append(line.strip())
        except Exception as e:
            print(f"[-] Error finding setuid files: {e}")
        
        # Find setgid files
        try:
            result = subprocess.run(['find', '/', '-type', 'f', '-perm', '-2000', '-ls', '2>/dev/null'], 
                                  capture_output=True, text=True, shell=True)
            for line in result.stdout.split('\n'):
                if line.strip():
                    special_perms['setgid_files'].append(line.strip())
        except Exception as e:
            print(f"[-] Error finding setgid files: {e}")
        
        # Find sticky bit directories (excluding known safe ones)
        try:
            result = subprocess.run(['find', '/', '-type', 'd', '-perm', '-1000', '-ls', '2>/dev/null'], 
                                  capture_output=True, text=True, shell=True)
            for line in result.stdout.split('\n'):
                if line.strip():
                    path = line.split()[-1] if line.split() else ''
                    if path not in ['/tmp', '/var/tmp']:
                        special_perms['sticky_directories'].append(line.strip())
        except Exception as e:
            print(f"[-] Error finding sticky directories: {e}")
        
        # Find immutable files
        try:
            result = subprocess.run(['lsattr', '-R', '/', '2>/dev/null'], 
                                  capture_output=True, text=True, shell=True)
            for line in result.stdout.split('\n'):
                if line.strip() and 'i' in line.split()[0]:
                    special_perms['immutable_files'].append(line.strip())
        except Exception as e:
            print(f"[-] Error finding immutable files: {e}")
        
        self.test_results['special_permissions'] = special_perms

    def analyze_access_control_lists(self):
        """Analyze Access Control Lists (ACLs)"""
        print("[+] Analyzing Access Control Lists...")
        
        acl_analysis = {
            'files_with_acls': [],
            'overly_permissive_acls': [],
            'inconsistent_acls': []
        }
        
        # Find files with ACLs
        try:
            result = subprocess.run(['getfacl', '-R', '/', '2>/dev/null'], 
                                  capture_output=True, text=True, shell=True)
            
            current_file = None
            acl_entries = []
            
            for line in result.stdout.split('\n'):
                if line.startswith('# file:'):
                    if current_file and acl_entries:
                        acl_analysis = self.analyze_single_acl(current_file, acl_entries, acl_analysis)
                    current_file = line.split('# file: ')[1].strip()
                    acl_entries = []
                elif line.strip() and not line.startswith('#'):
                    acl_entries.append(line.strip())
            
            # Process last file
            if current_file and acl_entries:
                acl_analysis = self.analyze_single_acl(current_file, acl_entries, acl_analysis)
                
        except Exception as e:
            print(f"[-] Error analyzing ACLs: {e}")
        
        self.test_results['acl_analysis'] = acl_analysis

    def analyze_single_acl(self, file_path, acl_entries, acl_analysis):
        """Analyze ACL for a single file"""
        acl_analysis['files_with_acls'].append(file_path)
        
        for entry in acl_entries:
            # Check for overly permissive entries
            if 'other::rwx' in entry or 'mask::rwx' in entry:
                acl_analysis['overly_permissive_acls'].append({
                    'file': file_path,
                    'entry': entry
                })
            
            # Check for inconsistent permissions
            if 'default:' in entry and file_path not in ['/tmp', '/var/tmp']:
                acl_analysis['inconsistent_acls'].append({
                    'file': file_path,
                    'entry': entry,
                    'issue': 'Default ACL on non-directory'
                })
        
        return acl_analysis

    def test_linux_capabilities(self):
        """Test Linux capabilities on executable files"""
        print("[+] Testing Linux capabilities...")
        
        capabilities_analysis = {
            'capable_binaries': [],
            'dangerous_capabilities': [],
            'capability_vulnerabilities': []
        }
        
        # Find files with capabilities
        try:
            result = subprocess.run(['getcap', '-r', '/', '2>/dev/null'], 
                                  capture_output=True, text=True, shell=True)
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        file_path = parts[0]
                        caps = parts[1]
                        
                        capabilities_analysis['capable_binaries'].append({
                            'file': file_path,
                            'capabilities': caps
                        })
                        
                        # Check for dangerous capabilities
                        dangerous_caps = ['cap_sys_admin', 'cap_dac_override', 'cap_dac_read_search']
                        if any(danger_cap in caps for danger_cap in dangerous_caps):
                            capabilities_analysis['dangerous_capabilities'].append({
                                'file': file_path,
                                'capabilities': caps,
                                'risk': 'high'
                            })
        
        except Exception as e:
            print(f"[-] Error testing capabilities: {e}")
        
        self.test_results['capabilities_analysis'] = capabilities_analysis

    def perform_vulnerability_assessment(self):
        """Perform comprehensive vulnerability assessment"""
        print("[+] Performing vulnerability assessment...")
        
        vulnerabilities = {
            'privilege_escalation_vectors': [],
            'information_disclosure_risks': [],
            'data_tampering_risks': [],
            'service_disruption_risks': []
        }
        
        # Analyze permission analysis results
        for path, analysis in self.test_results['permission_analysis'].items():
            risk_files = analysis.get('risk_files', {})
            
            # World-writable files
            for file_info in risk_files.get('world_writable', []):
                vulnerabilities['privilege_escalation_vectors'].append({
                    'type': 'WORLD_WRITABLE_FILE',
                    'file': file_info['path'],
                    'risk': 'high',
                    'description': f"World-writable file: {file_info['path']}"
                })
            
            # setuid/setgid files
            for file_info in risk_files.get('setuid_setgid', []):
                vulnerabilities['privilege_escalation_vectors'].append({
                    'type': 'SETUID_SETGID_FILE',
                    'file': file_info['path'],
                    'risk': 'high',
                    'description': f"{file_info['type']} file: {file_info['path']}"
                })
            
            # Insecure configuration files
            for file_info in risk_files.get('insecure_configs', []):
                vulnerabilities['data_tampering_risks'].append({
                    'type': 'INSECURE_CONFIG_FILE',
                    'file': file_info['path'],
                    'risk': 'medium',
                    'description': f"Insecure configuration file: {file_info['path']}"
                })
        
        # Analyze special permissions
        special_perms = self.test_results.get('special_permissions', {})
        for file_info in special_perms.get('setuid_files', []):
            vulnerabilities['privilege_escalation_vectors'].append({
                'type': 'SETUID_ROOT_BINARY',
                'file': file_info,
                'risk': 'high',
                'description': f"Setuid root binary: {file_info}"
            })
        
        # Analyze capabilities
        capabilities = self.test_results.get('capabilities_analysis', {})
        for cap_info in capabilities.get('dangerous_capabilities', []):
            vulnerabilities['privilege_escalation_vectors'].append({
                'type': 'DANGEROUS_CAPABILITY',
                'file': cap_info['file'],
                'risk': 'high',
                'description': f"File with dangerous capabilities: {cap_info['file']}"
            })
        
        self.test_results['vulnerability_assessment'] = vulnerabilities

    def perform_security_assessment(self):
        """Perform comprehensive security assessment"""
        print("[+] Performing security assessment...")
        
        assessment = {
            'overall_risk_level': self.calculate_overall_risk(),
            'permission_hardening_score': self.calculate_hardening_score(),
            'compliance_status': self.assess_compliance_status(),
            'security_recommendations': self.generate_security_recommendations()
        }
        
        return assessment

    def calculate_overall_risk(self):
        """Calculate overall risk level based on findings"""
        risk_scores = []
        
        vulnerabilities = self.test_results.get('vulnerability_assessment', {})
        
        for category, vulns in vulnerabilities.items():
            for vuln in vulns:
                risk_score = self.risk_level_to_score(vuln.get('risk', 'low'))
                risk_scores.append(risk_score)
        
        if not risk_scores:
            return 'low'
        
        avg_score = sum(risk_scores) / len(risk_scores)
        
        if avg_score >= 4:
            return 'critical'
        elif avg_score >= 3:
            return 'high'
        elif avg_score >= 2:
            return 'medium'
        else:
            return 'low'

    def risk_level_to_score(self, risk_level):
        """Convert risk level to numerical score"""
        risk_scores = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
        return risk_scores.get(risk_level, 1)

    def calculate_hardening_score(self):
        """Calculate file permission hardening score (0-100)"""
        score = 100
        penalty = 0
        
        vulnerabilities = self.test_results.get('vulnerability_assessment', {})
        
        # Penalize based on vulnerability count and severity
        for category, vulns in vulnerabilities.items():
            for vuln in vulns:
                risk = vuln.get('risk', 'low')
                if risk == 'critical':
                    penalty += 10
                elif risk == 'high':
                    penalty += 5
                elif risk == 'medium':
                    penalty += 2
                else:
                    penalty += 1
        
        return max(0, score - penalty)

    def perform_risk_analysis(self):
        """Perform comprehensive risk analysis"""
        risk_analysis = {
            'critical_risks': [],
            'high_risks': [],
            'medium_risks': [],
            'low_risks': []
        }
        
        vulnerabilities = self.test_results.get('vulnerability_assessment', {})
        
        for category, vulns in vulnerabilities.items():
            for vuln in vulns:
                risk_entry = {
                    'vulnerability': vuln['type'],
                    'description': vuln['description'],
                    'file': vuln.get('file', ''),
                    'remediation': self.get_vulnerability_remediation(vuln['type'])
                }
                
                risk_analysis[f"{vuln['risk']}_risks"].append(risk_entry)
        
        return risk_analysis

    def get_vulnerability_remediation(self, vulnerability_type):
        """Get remediation for specific vulnerability type"""
        remediations = {
            'WORLD_WRITABLE_FILE': 'Remove world-writable permissions: chmod o-w <file>',
            'SETUID_SETGID_FILE': 'Remove setuid/setgid permissions if not required: chmod u-s,g-s <file>',
            'SETUID_ROOT_BINARY': 'Review and remove setuid root if not absolutely necessary',
            'INSECURE_CONFIG_FILE': 'Restrict config file permissions: chmod 600 <file>',
            'DANGEROUS_CAPABILITY': 'Remove dangerous capabilities: setcap -r <file>'
        }
        return remediations.get(vulnerability_type, 'Review and secure file permissions')

    def generate_recommendations(self):
        """Generate comprehensive security recommendations"""
        recommendations = {
            'immediate_actions': [],
            'short_term_improvements': [],
            'long_term_strategies': []
        }
        
        # Immediate actions for critical risks
        risk_analysis = self.perform_risk_analysis()
        for risk in risk_analysis['critical_risks']:
            recommendations['immediate_actions'].append({
                'action': f"Fix {risk['vulnerability']}",
                'description': risk['description'],
                'remediation': risk['remediation']
            })
        
        # Short-term improvements
        recommendations['short_term_improvements'].extend([
            "Implement regular file permission audits",
            "Set up file integrity monitoring",
            "Create file permission baselines",
            "Implement automated permission hardening"
        ])
        
        # Long-term strategies
        recommendations['long_term_strategies'].extend([
            "Establish file permission security standards",
            "Implement DevSecOps for permission management",
            "Create file permission governance framework",
            "Implement continuous security monitoring"
        ])
        
        return recommendations

# Advanced File Permission Monitoring System
class FilePermissionMonitor:
    def __init__(self, critical_paths, monitoring_interval=3600):
        self.critical_paths = critical_paths
        self.monitoring_interval = monitoring_interval
        self.permission_baseline = {}

    def setup_continuous_monitoring(self):
        """Set up continuous file permission monitoring"""
        print("[+] Setting up continuous file permission monitoring...")
        
        # Establish baseline
        for path in self.critical_paths:
            tester = FilePermissionTester([path])
            baseline = tester.comprehensive_permission_testing()
            self.permission_baseline[path] = baseline
        
        self.start_monitoring_loop()

    def detect_permission_changes(self):
        """Detect changes in file permissions"""
        changes_detected = {}
        
        for path, baseline in self.permission_baseline.items():
            current_tester = FilePermissionTester([path])
            current_results = current_tester.comprehensive_permission_testing()
            
            changes = self.compare_permission_results(baseline, current_results)
            
            if changes:
                changes_detected[path] = {
                    'changes': changes,
                    'security_impact': self.assess_change_impact(changes),
                    'timestamp': datetime.now().isoformat()
                }
            
            self.permission_baseline[path] = current_results
        
        return changes_detected

    def compare_permission_results(self, baseline, current):
        """Compare permission results and detect changes"""
        changes = []
        
        # Compare world-writable files
        baseline_ww = self.extract_world_writable_files(baseline)
        current_ww = self.extract_world_writable_files(current)
        
        new_ww = current_ww - baseline_ww
        removed_ww = baseline_ww - current_ww
        
        for file in new_ww:
            changes.append({
                'type': 'NEW_WORLD_WRITABLE_FILE',
                'file': file,
                'impact': 'HIGH'
            })
        
        for file in removed_ww:
            changes.append({
                'type': 'REMOVED_WORLD_WRITABLE_FILE',
                'file': file,
                'impact': 'MEDIUM'
            })
        
        return changes

    def extract_world_writable_files(self, results):
        """Extract world-writable files from test results"""
        world_writable = set()
        
        permission_analysis = results['test_results'].get('permission_analysis', {})
        for path, analysis in permission_analysis.items():
            risk_files = analysis.get('risk_files', {})
            for file_info in risk_files.get('world_writable', []):
                world_writable.add(file_info['path'])
        
        return world_writable
```

### 12 File Permission Risk Assessment Matrix
```yaml
File Permission Risk Assessment:
  Critical Risks:
    - World-writable system binaries or configuration files
    - setuid root binaries with known vulnerabilities
    - World-writable directories in system paths
    - Configuration files containing secrets with weak permissions
    - Log files containing sensitive data with world-readable permissions
    - Backup files with original file permissions intact
    - Temporary files with execution permissions
    - Device files with inappropriate permissions

  High Risks:
    - setuid/setgid binaries from untrusted sources
    - World-writable user home directories
    - Configuration files writable by non-privileged users
    - Application binaries with excessive permissions
    - Log files writable by unauthorized users
    - Database files with weak permissions
    - Cloud storage objects with public write access
    - Container images with root execution

  Medium Risks:
    - Files with unnecessary group write permissions
    - Directories with excessive search permissions
    - Application files with incorrect ownership
    - Backup files without proper access controls
    - Temporary files with weak permissions
    - Development files in production environments
    - Hidden files with sensitive information
    - Symbolic links with security implications

  Low Risks:
    - Files with appropriate permission settings
    - Properly configured setuid/setgid binaries
    - Secure temporary file handling
    - Correct file ownership and group assignments
    - Regular permission audits and monitoring
    - Automated permission hardening
    - Comprehensive logging and alerting
    - Regular security assessments
```

### 13 File Permission Protection Testing
```python
# File Permission Protection Effectiveness Tester
class FilePermissionProtectionTester:
    def __init__(self, target_systems):
        self.target_systems = target_systems

    def test_protection_effectiveness(self):
        """Test file permission protection effectiveness"""
        protection_tests = {}
        
        for system in self.target_systems:
            tester = FilePermissionTester(system['paths'])
            results = tester.comprehensive_permission_testing()
            
            protection_tests[system['name']] = {
                'access_control_effectiveness': self.test_access_controls(results),
                'permission_enforcement': self.test_permission_enforcement(results),
                'integrity_protection': self.test_integrity_protection(results),
                'monitoring_effectiveness': self.test_monitoring_capabilities(results),
                'overall_protection_score': self.calculate_protection_score(results)
            }
        
        return protection_tests

    def generate_protection_report(self):
        """Generate comprehensive protection report"""
        protection_tests = self.test_protection_effectiveness()
        
        report = {
            'protection_analysis': protection_tests,
            'security_gaps': self.identify_protection_gaps(protection_tests),
            'compliance_status': self.assess_protection_compliance(),
            'improvement_recommendations': self.generate_protection_recommendations()
        }
        
        return report
```

### 14 File Permission Remediation Checklist
```markdown
## ✅ FILE PERMISSION SECURITY REMEDIATION CHECKLIST

### System File Permissions:
- [ ] Remove world-writable permissions from system binaries
- [ ] Review and secure setuid/setgid binaries
- [ ] Restrict configuration file permissions (600 or 640)
- [ ] Secure log file permissions (640 or 600 for sensitive logs)
- [ ] Implement proper temporary file permissions (1777 for /tmp)
- [ ] Restrict device file permissions to appropriate users
- [ ] Secure boot file permissions (600 for sensitive boot files)
- [ ] Review and secure library file permissions

### Application File Permissions:
- [ ] Remove world-writable permissions from application files
- [ ] Restrict application configuration file permissions
- [ ] Secure application log file permissions
- [ ] Implement proper application temporary file handling
- [ ] Restrict application data file permissions
- [ ] Secure application backup file permissions
- [ ] Review application binary permissions
- [ ] Implement application file ownership correctly

### Special Permission Management:
- [ ] Remove unnecessary setuid/setgid permissions
- [ ] Implement sticky bit only on required directories
- [ ] Remove dangerous Linux capabilities
- [ ] Secure Access Control Lists (ACLs)
- [ ] Implement immutable flags on critical files
- [ ] Remove extended attributes unless required
- [ ] Review and secure symbolic link permissions
- [ ] Implement proper hard link management

### User and Group Permissions:
- [ ] Review and correct file ownership
- [ ] Implement proper group membership
- [ ] Restrict user home directory permissions (700)
- [ ] Secure user configuration files (600)
- [ ] Implement proper umask settings (0027 or 0077)
- [ ] Review and secure shared directory permissions
- [ ] Implement proper sudoers file permissions (440)
- [ ] Secure user temporary file permissions

### Container File Permissions:
- [ ] Implement non-root container execution
- [ ] Remove unnecessary container capabilities
- [ ] Secure container volume permissions
- [ ] Implement read-only container filesystems where possible
- [ ] Restrict container bind mount permissions
- [ ] Secure container configuration files
- [ ] Implement container security contexts
- [ ] Regular container image permission audits

### Cloud Storage Permissions:
- [ ] Remove public write access from cloud storage
- [ ] Implement proper IAM roles for file access
- [ ] Restrict cross-account access to necessary only
- [ ] Implement encryption for sensitive cloud files
- [ ] Regular cloud storage permission audits
- [ ] Implement proper resource-based policies
- [ ] Secure cloud backup permissions
- [ ] Monitor cloud file access patterns

### Monitoring and Auditing:
- [ ] Implement file integrity monitoring
- [ ] Set up permission change alerts
- [ ] Regular file permission audits
- [ ] Implement automated permission hardening
- [ ] Monitor setuid/setgid file changes
- [ ] Track world-writable file creation
- [ ] Implement file permission baselines
- [ ] Regular security compliance reporting

### Organizational Controls:
- [ ] Establish file permission security standards
- [ ] Implement change management for permission changes
- [ ] Conduct regular permission security training
- [ ] Establish incident response for permission issues
- [ ] Implement file permission governance
- [ ] Regular third-party security assessments
- [ ] Maintain comprehensive permission documentation
- [ ] Implement continuous improvement processes
```

### 15 File Permission Testing Completion Checklist
```markdown
## ✅ FILE PERMISSION SECURITY TESTING COMPLETION CHECKLIST

### File System Permission Discovery:
- [ ] File ownership mapping and analysis completed
- [ ] Permission bit analysis done
- [ ] Special permission flag testing completed
- [ ] Access Control List (ACL) enumeration done
- [ ] Extended attribute discovery completed
- [ ] File capability analysis done
- [ ] SELinux/AppArmor context analysis completed
- [ ] File system mount option analysis done

### Critical File Permission Testing:
- [ ] System binary permission testing completed
- [ ] Configuration file permission analysis done
- [ ] Boot file permission testing completed
- [ ] Library file permission assessment done
- [ ] Log file permission analysis completed
- [ ] Temporary file permission testing done
- [ ] Home directory permission assessment completed
- [ ] Device file permission testing done

### Privilege Escalation Vector Testing:
- [ ] Setuid root binary discovery and analysis completed
- [ ] Setgid binary identification and assessment done
- [ ] Custom setuid/setgid executable testing completed
- [ ] Setuid shell script analysis done
- [ ] Linux capability-enabled binary discovery completed
- [ ] Dangerous capability testing done
- [ ] Capability escalation vector analysis completed
- [ ] Container capability assessment done

### File Permission Vulnerability Testing:
- [ ] World-writable file and directory testing completed
- [ ] Configuration file permission vulnerability testing done
- [ ] Log file permission vulnerability testing completed
- [ ] Executable file permission testing done
- [ ] Backup file permission vulnerability testing completed
- [ ] Temporary file permission vulnerability testing done
- [ ] Symbolic link permission testing completed
- [ ] Hard link permission analysis done

### Container and Cloud Permission Testing:
- [ ] Container filesystem permission analysis completed
- [ ] Container volume permission testing done
- [ ] Container security context analysis completed
- [ ] Cloud storage permission testing done
- [ ] Cloud IAM integration testing completed
- [ ] Container breakout vulnerability assessment done
- [ ] Cloud cross-account access testing completed
- [ ] Container image layer permission analysis done

### Compliance and Reporting:
- [ ] Regulatory compliance assessment completed
- [ ] Industry standard compliance validation done
- [ ] Risk assessment and analysis completed
- [ ] Security effectiveness evaluation done
- [ ] Remediation recommendations developed
- [ ] Executive security report generated
- [ ] Management presentation prepared
- [ ] Continuous monitoring plan established
```

### 16 File Permission Executive Reporting Template
```markdown
# File Permission Security Assessment Report

## Executive Summary
- **Assessment Scope:** [Systems and directories assessed]
- **Assessment Period:** [Date range]
- **Files Analyzed:** [Total file count]
- **Critical Vulnerabilities:** [Critical findings count]
- **Overall Risk Level:** [High/Medium/Low]
- **Key Recommendations:** [Priority actions]

## Critical Findings
### [Critical Finding Title]
- **File Type:** [System binary/Configuration/Log/etc.]
- **Location:** [File path]
- **Risk Level:** Critical
- **Description:** [Detailed vulnerability description]
- **Impact:** [Potential security impact analysis]
- **Remediation Priority:** Immediate

## Technical Analysis
### Permission Analysis Summary
- **World-Writable Files:** [Count and risk summary]
- **Setuid/Setgid Binaries:** [Count and risk summary]
- **Insecure Configuration Files:** [Count and risk summary]
- **Dangerous Capabilities:** [Count and risk summary]
- **ACL Security Issues:** [Count and risk summary]

### Security Control Assessment
- **Access Control Effectiveness:** [Effectiveness rating]
- **Permission Enforcement:** [Control effectiveness rating]
- **Integrity Protection:** [Protection capability assessment]
- **Monitoring Capabilities:** [Monitoring effectiveness rating]

## Risk Assessment
### High Priority Risks
1. **[Risk Title]**
   - **Description:** [Detailed risk explanation]
   - **Impact:** [Security impact analysis]
   - **Likelihood:** [Probability assessment]
   - **Remediation:** [Specific mitigation steps]

### Medium Priority Risks
1. **[Risk Title]**
   - **Description:** [Detailed risk explanation]
   - **Impact:** [Security impact analysis]
   - **Likelihood:** [Probability assessment]
   - **Remediation:** [Specific mitigation steps]

## Recommendations
### Immediate Actions (1-7 days)
- [ ] [Remove critical world-writable permissions]
- [ ] [Secure dangerous setuid/setgid binaries]
- [ ] [Fix insecure configuration file permissions]

### Short-term Improvements (1-4 weeks)
- [ ] [Implement file integrity monitoring]
- [ ] [Establish permission security baselines]
- [ ] [Conduct comprehensive permission audit]

### Long-term Strategies (1-6 months)
- [ ] [Implement automated permission hardening]
- [ ] [Establish file permission governance framework]
- [ ] [Develop continuous security monitoring program]

## Compliance Status
- **Regulatory Compliance:** [PCI DSS, HIPAA, etc. compliance level]
- **Industry Standards:** [Security standards alignment]
- **Internal Policies:** [Policy compliance evaluation]

## Appendices
### Detailed Permission Analysis
- File permission configurations and findings
- Security control settings and gaps
- Vulnerability details and locations
- Risk classification details

### Risk Classification Matrix
- Risk scoring methodology
- Impact assessment criteria
- Remediation priority framework
- Compliance mapping

### Testing Methodology
- Tools and techniques used
- Scope and limitations
- Validation procedures
- Quality assurance measures
```

This comprehensive File Permission Security Testing checklist provides complete methodology for assessing, securing, and monitoring file permissions across systems, containers, and cloud environments. The framework covers permission discovery, vulnerability assessment, risk analysis, and comprehensive protection strategies to prevent unauthorized access, privilege escalation, and data breaches through insecure file permissions.