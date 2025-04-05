# Bug Bounty Checklist

## Reconnaissance Techniques

### Information Gathering

    - Google Dorking: Use advanced search operators to find sensitive information.
    - WHOIS Lookup: Gather domain registration details.
    - Reverse WHOIS Lookup: Find domains associated with a specific registrant.
    - DNS Enumeration: Identify DNS records like A, MX, NS, TXT, SOA.
    - IP Geolocation: Find the geographical location of IP addresses.
    - Public Records Search: Access public records related to the target.
    - Search Engine Queries: Use search engines to gather information.
    - Breach Data Search: Check for data breaches.
    - Social Engineering Techniques: Use social tactics to gather information.
    - Publicly Available APIs: Analyze APIs for exposed information.
    - Certificate Transparency Logs: Monitor public logs for SSL certificates.
    - Domain History Analysis: Analyze historical domain data.
    - Dark Web Scraping: Search dark web forums and marketplaces for leaked data.
    - Paste Site Monitoring: Scan paste sites for credentials or sensitive info.
    - Typosquatting Analysis: Identify typo-squatted domains mimicking the target.
    - DNS Cache Snooping: Probe DNS servers for cached queries about the target.
    - BGP Route Analysis: Map routing data to uncover network relationships.
    - Email Header Forensics: Analyze email headers for metadata and infra clues.
    - Tor Hidden Service Enumeration: Discover target-related .onion sites.
    - Favicon Hash Pivoting: Correlate favicon hashes across domains for ownership.
    - WHOIS Change Monitoring: Track real-time WHOIS updates for new assets.
    - Passive DNS Replay: Reconstruct historical DNS traffic from public datasets.
    - IoC Correlation: Cross-reference Indicators of Compromise with target infra.
    - Quantum-Resistant TLS Inspection: Analyze post-quantum crypto implementations.
    - Homomorphic Encryption Leakage: Probe encrypted data for unintended leaks.
    - Side-Channel Acoustic Analysis: Extract keys via server noise emissions.
    - Satellite Signal Interception: Capture satellite comms for target data.
    - Quantum Key Distribution Flaws: Exploit QKD protocol weaknesses.
    - Neural Network OSINT Prediction: Use AI to predict target infra from sparse data.
    - Zero-Knowledge Proof Harvesting: Extract metadata from ZKP implementations.

### Subdomain and Domain Discovery

    - Subdomain Enumeration: Discover subdomains.
    - Reverse IP Lookup: Identify other domains hosted on the same IP.
    - DNS Dumpster Diving: Extract information about DNS records.
    - Zone Transfers: Attempt DNS zone transfers to gather records.
    - Subdomain Permutation: Generate and test subdomain variations (e.g., dev-, test-).
    - Wildcard DNS Exploitation: Leverage wildcard DNS responses for enumeration.
    - DNSSEC Misconfig Analysis: Check DNSSEC records for validation flaws.
    - ASN Enumeration: Identify domains within the same Autonomous System Number.
    - Cloud Bucket Enumeration: Probe cloud storage (S3, GCP, Azure) for misconfigs.
    - Certificate SAN Harvesting: Extract subdomains from SSL certificate Subject Alternative Names.
    - DNS Response Timing Attacks: Infer subdomain existence via response delays.
    - CAA Record Analysis: Check Certificate Authority Authorization misconfigs.
    - IPv6 Subdomain Brute-Forcing: Enumerate subdomains over IPv6 networks.
    - AXFR Amplification Harvesting: Exploit misconfigured recursive resolvers.
    - Subdomain Takeover via CNAME: Detect dangling CNAME records for takeover.
    - Blockchain DNS Resolution: Resolve domains via decentralized DNS (e.g., ENS).
    - Quantum DNS Spoofing: Manipulate DNS via quantum entanglement effects.
    - DNS Anomaly Detection: Identify subdomains via statistical traffic anomalies.
    - Namecoin Domain Mining: Extract legacy blockchain-based domain records.
    - Subdomain Quantum Oracle Attacks: Use quantum computing for brute-force prediction.
    - DANE TLSA Misconfig: Exploit DNS-based Authentication of Named Entities flaws.

### Technology and Service Identification

    - Website Footprinting: Identify technologies, server details, and software versions.
    - Shodan Search: Find internet-connected devices and their details.
    - Censys Search: Identify and analyze devices and systems.
    - SSL/TLS Certificate Analysis: Review certificates for associated domains.
    - Web Application Framework Identification: Determine the frameworks used on a website.
    - Netcraft Site Reports: Analyze site reports for server details and technologies.
    - HTTP/2 and HTTP/3 Probing: Detect support for modern HTTP protocols.
    - WAF Fingerprinting: Identify Web Application Firewall presence and type.
    - CDN Mapping: Trace Content Delivery Network usage and origin servers.
    - Server-Side Tech Leakage: Extract tech stack from error pages or headers.
    - IoT Device Profiling: Identify IoT devices linked to the target infrastructure.
    - Protocol Banner Analysis: Capture banners from non-standard protocols (e.g., SIP, MQTT).
    - QUIC Fingerprinting: Identify QUIC implementations and versions.
    - GraphQL Introspection: Detect and map GraphQL endpoints.
    - WebSocket Protocol Analysis: Inspect WebSocket implementations for tech clues.
    - Serverless Function Detection: Identify Lambda or equivalent serverless usage.
    - eBPF Tracing Exposure: Check for exposed eBPF-based monitoring tools.
    - Hardware-Level Fingerprinting: Infer hardware via timing or side-channel leaks.
    - RISC-V Architecture Detection: Identify RISC-V chips in target infra.
    - TEE Exposure Analysis: Probe Trusted Execution Environments (e.g., SGX) for leaks.
    - Post-Quantum Crypto Detection: Identify quantum-resistant algorithm usage.
    - Neuromorphic Chip Profiling: Detect AI-driven hardware via response patterns.
    - Photonic Network Identification: Trace optical computing implementations.

### Metadata and Historical Data

    - FOCA: Extract metadata from documents and images.
    - ExifTool: Extract metadata from files and images.
    - Wayback Machine: Retrieve historical versions of web pages.
    - Github Repository Search: Look for sensitive information in code repositories.
    - Metadata Analysis: Analyze file and document metadata.
    - Historical DNS Pivoting: Cross-reference old DNS records with current ones.
    - Code Commit Diffing: Analyze repository commit diffs for secrets or changes.
    - PDF Redaction Fails: Check PDFs for unredacted sensitive data.
    - Image Steganography: Investigate images for hidden data or payloads.
    - Archive Scraping: Extract metadata from archived file formats (e.g., .tar, .zip).
    - Audio Watermark Extraction: Detect hidden data in audio files.
    - Git Rebase Leakage: Recover deleted commits from git reflogs.
    - Office Macro Reverse Engineering: Extract metadata from macro-enabled docs.
    - Blockchain Metadata Harvesting: Pull domain data from blockchain transactions.
    - Container Image Layer Analysis: Inspect Docker layers for embedded secrets.
    - Holographic Storage Scraping: Extract data from experimental storage tech.
    - Quantum State Metadata: Hypothesize metadata leaks in quantum storage.
    - DNA Data Storage Analysis: Decode target info from synthetic DNA archives.
    - Neuromorphic Memory Profiling: Extract data from AI-driven memory systems.
    - Time-Series Anomaly Mining: Detect historical secrets via temporal patterns.

### Network and Traffic Analysis

    - Network Mapping: Map out network topology.
    - Network Traffic Analysis: Analyze network traffic for service and system information.
    - IP Range Scanning: Identify IP ranges associated with the target.
    - Network Enumeration: Use traceroute to identify network paths.
    - Packet Fragmentation Analysis: Detect anomalies in fragmented packets.
    - ARP Spoofing Recon: Gather MAC addresses and devices in local networks.
    - VPN Leak Detection: Identify VPN misconfigs leaking real IPs.
    - QUIC Protocol Inspection: Analyze QUIC traffic for service details.
    - Passive DNS Monitoring: Collect DNS query data over time.
    - Network Latency Profiling: Infer infrastructure locations via latency patterns.
    - MPLS Label Inspection: Map MPLS paths for network segmentation.
    - SRv6 Traffic Analysis: Analyze Segment Routing over IPv6 for routing details.
    - DPDK Packet Capture: Use Data Plane Development Kit for high-speed analysis.
    - Zero Trust Misconfig Detection: Identify flaws in zero trust implementations.
    - Quantum Network Probing: Test for quantum key distribution exposures.
    - Photonic Signal Interception: Capture optical network traffic for intel.
    - Neuromorphic Traffic Analysis: Use AI to detect anomalies in traffic flows.
    - Gravitational Wave Correlation: Hypothesize infra locations via GW interference.
    - Molecular Communication Sniffing: Analyze nanoscale network signals.

## Enumeration Techniques

### Service and Port Enumeration

    - Service Enumeration: Identify active services and their versions.
    - Port Scanning: Identify open ports and services running on the target.
    - Banner Grabbing: Obtain service banners to determine versions.
    - FTP Enumeration: List files and directories on FTP servers.
    - HTTP Methods Testing: Check for supported HTTP methods.
    - WebDAV Enumeration: Explore WebDAV services for vulnerabilities.
    - NFS Enumeration: Identify Network File System shares and permissions.
    - UDP Service Probing: Enumerate UDP-based services (e.g., SNMP, TFTP).
    - gRPC Enumeration: Identify and interact with gRPC endpoints.
    - ZeroMQ Discovery: Detect ZeroMQ messaging services.
    - SSDP Enumeration: Probe for UPnP devices via Simple Service Discovery Protocol.
    - Multicast DNS Querying: Enumerate services via mDNS (e.g., Bonjour).
    - CoAP Enumeration: Probe Constrained Application Protocol for IoT devices.
    - AMQP Queue Listing: Enumerate Advanced Message Queuing Protocol queues.
    - BACnet Discovery: Identify Building Automation and Control network devices.
    - DNP3 Enumeration: Probe Distributed Network Protocol for SCADA systems.
    - Modbus Register Mapping: Extract data from Modbus industrial devices.
    - KNX Enumeration: Probe KNX protocol for smart building systems.
    - LONWorks Analysis: Enumerate Local Operating Network devices.
    - Profibus Mapping: Extract data from Profibus industrial networks.
    - EtherCAT Discovery: Identify EtherCAT automation protocol services.
    - Quantum Service Probing: Enumerate quantum computing service endpoints.

### User and Resource Enumeration

    - User Enumeration: Find valid usernames.
    - SMB Enumeration: Extract information from SMB shares.
    - NetBIOS Enumeration: Gather NetBIOS information.
    - SNMP Enumeration: Extract SNMP data.
    - LDAP Enumeration: Query LDAP servers for user and group details.
    - SMTP Enumeration: Discover email configurations.
    - Kerberos Enumeration: Enumerate Kerberos tickets and services.
    - RPC Enumeration: Identify RPC services and versions.
    - LDAP Injection Testing: Test for LDAP injection vulnerabilities.
    - Kerberoasting: Extract and crack service tickets from Kerberos.
    - VNC Enumeration: Probe for VNC servers and authentication weaknesses.
    - Redis Enumeration: Check Redis instances for exposed data or misconfigs.
    - Memcached Probing: Enumerate Memcached servers for key extraction.
    - MSSQL Enumeration: Query MSSQL databases for schema and users.
    - Oracle TNS Enumeration: Extract Oracle database info via TNS listener.
    - CouchDB Enum: Enumerate CouchDB instances for exposed databases.
    - Cassandra Keyspace Listing: Probe Cassandra clusters for data exposure.
    - Elasticsearch Index Harvesting: Extract indices from Elasticsearch nodes.
    - SAP Enumeration: Identify SAP systems and extract user data.
    - Mainframe TN3270 Probing: Enumerate IBM mainframe services.
    - HBase Table Listing: Enumerate HBase NoSQL database tables.
    - Neo4j Graph Extraction: Pull data from Neo4j graph databases.
    - Quantum Database Enumeration: Probe quantum-native databases for leaks.
    - Neuromorphic User Mapping: Use AI to infer users from system behavior.

## Scanning Techniques

## Network and Service Scanning

    - Network Scanning: Discover live hosts and network services.
    - Port Scanning: Identify open ports with detailed options.
    - Service Scanning: Determine services running on open ports.
    - Operating System Fingerprinting: Identify the operating system.
    - Web Application Scanning: Detect vulnerabilities in web applications.
    - DNS Scanning: Scan DNS records and identify potential misconfigurations.
    - SSL/TLS Scanning: Check SSL/TLS configurations and vulnerabilities.
    - IPv6 Scanning: Scan IPv6 address spaces for additional services.
    - GRE Tunnel Detection: Identify GRE tunnels for network pivoting.
    - VLAN Hopping Recon: Detect VLAN misconfigs for network access.
    - SCTP Scanning: Probe Stream Control Transmission Protocol services.
    - Passive OS Fingerprinting: Infer OS from traffic without active probes.
    - TIPC Scanning: Scan Transparent Inter-Process Communication services.
    - RDMA Enumeration: Probe Remote Direct Memory Access for HPC systems.
    - VXLAN Mapping: Identify Virtual Extensible LAN overlays.
    - Geneve Protocol Analysis: Scan Geneve tunneling for virtualized networks.
    - NVMe-oF Discovery: Enumerate NVMe over Fabrics storage services.
    - Quantum Network Scanning: Probe quantum entanglement-based networks.
    - Photonic Bus Scanning: Scan optical interconnects for service leaks.
    - Molecular Network Probing: Analyze nanoscale comms for service detection.

## Vulnerability and Protocol Scanning

    - Vulnerability Scanning: Identify known vulnerabilities.
    - Port Sweeping: Scan a range of ports to identify open services.
    - Application Scanning: Identify vulnerabilities in applications and services.
    - Network Protocol Analysis: Analyze network protocols for weaknesses.
    - Wireless Scanning: Identify and analyze wireless networks and their security settings.
    - Bluetooth Enumeration: Scan for Bluetooth devices and pairing flaws.
    - Zigbee Analysis: Probe Zigbee networks for IoT vulnerabilities.
    - SMBv1 Exploitation: Target SMBv1 for known exploits (e.g., EternalBlue).
    - RDP Scanning: Identify Remote Desktop Protocol weaknesses.
    - Custom Protocol Fuzzing: Test proprietary protocols for input handling flaws.
    - LoRaWAN Sniffing: Analyze LoRaWAN IoT networks for weaknesses.
    - CAN Bus Probing: Scan Controller Area Network for automotive flaws.
    - OPC UA Enumeration: Probe OPC Unified Architecture for industrial vulns.
    - MQTT Topic Harvesting: Extract MQTT topics for IoT data leaks.
    - Side-Channel Timing Scans: Detect vulns via timing discrepancies.
    - Quantum Protocol Fuzzing: Test quantum comms for implementation flaws.
    - Neuromorphic Vuln Detection: Use AI to predict vulns in exotic protocols.
    - Photonic Signal Injection: Exploit optical networks for vuln discovery.

## OSINT Techniques

    - Social Media Analysis: Collect information from social media platforms.
    - Public Records Search: Access public records and databases.
    - Domain and IP Lookup: Investigate domain and IP address information.
    - Historical Data Search: Access historical data on websites and domains.
    - Code Repository Search: Look for sensitive information in public code repositories.
    - Online People Search: Find personal details and professional backgrounds.
    - Technical Analysis: Analyze publicly available technical data.
    - Job Posting Mining: Extract tech stack and infra details from job listings.
    - Forum Scraping: Gather intel from niche forums or communities.
    - Geofencing Analysis: Correlate physical locations with online activity.
    - Blockchain Tracing: Track domain-related crypto transactions.
    - Leaked API Key Hunting: Search for exposed API keys across platforms.
    - Satellite Imagery Review: Use public imagery for physical asset recon.
    - RF Signal Mapping: Analyze radio frequency emissions for device intel.
    - Crowdsourced Data Mining: Pull target data from platforms like Reddit or Wikis.
    - Supply Chain Recon: Map vendor relationships for indirect attack vectors.
    - Firmware Dump Analysis: Extract secrets from public firmware images.
    - Quantum Entanglement Metadata: Hypothesize quantum comms metadata leaks.
    - Neuromorphic Behavior Profiling: Use AI to model target org behavior.
    - Gravitational Anomaly Mapping: Correlate GW data with physical infra.
    - Synthetic Biology Tracing: Track bio-engineered tech linked to targets.

## Active Directory Enumeration

    - Domain Enumeration: Gather information about the domain structure.
    - User Enumeration: Identify domain users.
    - Group Enumeration: Discover groups and their memberships.
    - Domain Trust Enumeration: Identify domain trusts and relationships.
    - ACL Enumeration: Review Access Control Lists for misconfigurations.
    - Kerberoasting: Extract service tickets to crack passwords.
    - SPN Enumeration: Discover Service Principal Names.
    - Kerberos Ticket Extraction: Obtain Kerberos tickets for analysis.
    - Golden Ticket Forging: Craft Kerberos golden tickets for persistence.
    - Silver Ticket Creation: Forge service-specific Kerberos tickets.
    - DCSync Attack: Extract AD credentials via replication abuse.
    - NTLM Relay Harvesting: Capture and relay NTLM hashes for auth.
    - GPO Misconfig Analysis: Identify exploitable Group Policy Objects.
    - SID History Injection: Enumerate legacy SIDs for privilege escalation.
    - ADCS Escalation: Exploit Active Directory Certificate Services flaws.
    - Pass-the-Certificate: Use certs for lateral movement in AD.
    - Constrained Delegation Abuse: Exploit delegation for privilege gain.
    - Resource-Based Constrained Delegation: Hijack RBCD for escalation.
    - AD Recycle Bin Harvesting: Recover deleted objects for intel.
    - AD Quantum Ticket Forging: Hypothesize quantum Kerberos ticket attacks.
    - AD Neuromorphic Enumeration: Use AI to predict AD structures.

## Privilege Escalation Techniques

### Linux Privilege Escalation

    - SUID/SGID Files: Identify files with SUID or SGID permissions.
    - Kernel Exploits: Check for vulnerabilities in the Linux kernel.
    - Cron Jobs: Identify misconfigured cron jobs.
    - Writable Directories: Check for directories where files can be written.
    - Environment Variables: Inspect environment variables for sensitive data.
    - SetUID Binaries: Check for binaries with SetUID permissions.
    - Sudo Permissions: Inspect sudo permissions and configurations.
    - LXC/LXD Exploitation: Escalate via container misconfigs.
    - AppArmor/SELinux Bypass: Exploit weak security policy enforcement.
    - NFS Root Squashing: Abuse NFS exports with no_root_squash.
    - Kernel Module Injection: Load malicious kernel modules for root.
    - Systemd Service Hijack: Modify systemd services for escalation.
    - eBPF Program Injection: Exploit eBPF hooks for kernel-level access.
    - KSM Merging Abuse: Manipulate Kernel Same-page Merging for data leaks.
    - cgroups Escape: Break out of control groups for system access.
    - Seccomp Filter Bypass: Evade seccomp sandbox restrictions.
    - OverlayFS Misuse: Exploit OverlayFS mounts for privilege gain.
    - Quantum Kernel Exploit: Hypothesize quantum computing kernel attacks.
    - Neuromorphic Process Hijack: Use AI to manipulate process execution.
    - Photonic Memory Escalation: Exploit optical memory for root access.

### Windows Privilege Escalation

    - Unquoted Service Paths: Identify unquoted service paths that can be exploited.
    - Insecure File Permissions: Check for files with insecure permissions.
    - Local Privilege Escalation Vulnerabilities: Look for known local privilege escalation vulnerabilities.
    - Scheduled Tasks: Check for tasks that can be exploited for privilege escalation.
    - Kerberos Ticket Extraction: Obtain Kerberos tickets to elevate privileges.
    - Service Account Misconfigurations: Identify misconfigured service accounts.
    - DLL Hijacking: Exploit DLL hijacking vulnerabilities for privilege escalation.
    - Kernel Exploits: Check for vulnerabilities in the Windows kernel.
    - Token Impersonation: Steal or forge tokens for higher privileges.
    - UAC Bypass: Exploit User Account Control misconfigs.
    - Alternate Data Streams: Hide executables in NTFS ADS for execution.
    - Registry Key Abuse: Modify registry for persistence or escalation.
    - WSL Exploitation: Escalate via Windows Subsystem for Linux flaws.
    - Print Spooler Abuse: Leverage Spooler service for SYSTEM access.
    - COM Object Hijacking: Exploit COM registry for privilege gain.
    - DCOM Lateral Movement: Use Distributed COM for escalation.
    - SeDebugPrivilege Abuse: Exploit debug privileges for process control.
    - Hyper-V Escape: Break out of Hyper-V VMs for host access.
    - CLFS Driver Exploits: Target Common Log File System drivers for kernel access.
    - Quantum Token Forging: Hypothesize quantum-based token manipulation.
    - Neuromorphic Driver Injection: Use AI to craft kernel driver exploits.
    - Photonic Bus Hijacking: Exploit optical interconnects for SYSTEM access.
