
---
#### **51. Question: What is the key difference between credential dumping techniques like using `sekurlsa::logonpasswords` in Mimikatz and extracting credentials from the SAM hive?**
-  `sekurlsa::logonpasswords` extracts credentials from the **LSASS process memory**, which contains hashes and sometimes plaintext passwords of *currently logged-on* users. Dumping the **SAM hive** (from the filesystem or registry) gives you the local user account password hashes, but these are static and only for local accounts, not domain accounts. LSASS memory is far richer for an attacker as it contains domain credentials and tickets.

---
#### **52. Question: Explain the "DLL Search Order Hijacking" attack and how it differs from "DLL Proxying".**
-  Both exploit Windows DLL load order. **Search Order Hijacking** places a malicious DLL with the same name as a required one in a directory searched earlier (e.g., the application's folder instead of `System32`). **DLL Proxying** is more stealthy; the malicious DLL is given the exact same name and placed in the vulnerable location, but it exports all the same functions as the legitimate DLL. It forwards all legitimate calls to the real DLL while executing malicious code in specific functions.

---
#### **53. Question: What is a "JWT" (JSON Web Token) and what is the most common critical vulnerability associated with its implementation?**
-  A JWT is a compact, URL-safe means of representing claims between two parties, often used for authentication. The most common critical vulnerability is **algorithm confusion** (or "key confusion"). This occurs when a server expects a token signed with an asymmetric algorithm (like RS256) but an attacker provides a token signed with a symmetric algorithm (HS256). If the server uses the public key (which is known) as the HMAC secret, the attacker can forge valid tokens.

---
#### **54. Question: Describe the technique of "ACL (Access Control List) Abuse" in Active Directory for privilege escalation.**
-  AD objects (users, groups, computers) have ACLs that define permissions. Many of these are overly permissive. For example, if a standard user has the "ForceChangePassword" permission on a Domain Admin's account, they can reset the DA's password. If a user has "GenericAll" on a computer object, they can perform a resource-based constrained delegation attack to gain code execution on that computer with SYSTEM privileges.

---
#### **55. Question: What is the purpose of a "Webshell" and what are some common indicators of its presence on a server?**
-  A webshell is a malicious script that provides a web-based interface for remote command execution and file management on a compromised server. Indicators include: unexpected files in web roots (e.g., `.asp`, `.php`, `.jsp` files with names like `cmd.aspx` or `b374k.php`), anomalous network traffic (consistent POST requests to a specific, unusual page), and spikes in CPU/Memory usage from the web server process.

---
#### **56. Question: How does the "ETERNALBLUE" exploit work and what specific vulnerability does it target?**
-  ETERNALBLUE exploits a vulnerability in the SMBv1 protocol (CVE-2017-0144) on Windows systems. The flaw is in the handling of crafted "Transaction" requests. It involves a buffer overflow and a "DoublePulsar" backdoor that allows unauthenticated remote code execution by sending specially crafted packets, which was famously used by the WannaCry ransomware to propagate.

---
#### **57. Question: In the context of cloud security, what is "Instance Metadata Service (IMDS)" and what is the risk associated with its v1?**
-  The IMDS (like AWS's `169.254.169.254`) provides temporary credentials and other data to a cloud instance. **IMDSv1** is risky because it is a simple HTTP request with no required headers, making it vulnerable to **Server-Side Request Forgery (SSRF)**. If a web app on the instance is vulnerable to SSRF, an attacker can force it to retrieve IAM role credentials from the IMDS and use them to access other cloud resources. **IMDSv2** mitigates this by requiring a session token via the `PUT` method first.

---
#### **58. Question: What is "Format String Bug" and how can it lead to arbitrary memory read or write?**
-  A Format String Bug occurs when user input is passed directly as the format string argument to a function like `printf()` (e.g., `printf(user_input)` instead of `printf("%s", user_input)`). An attacker can supply format specifiers like `%x` to read from the stack, or `%n` to *write* the number of characters printed so far to a specified memory address, leading to arbitrary memory writes and potential code execution.

---
#### **59. Question: Explain the concept of "Container Escape" and describe one method to achieve it.**
-  A container escape is when an attacker breaks out of the container's isolation and gains access to the host operating system. One method is by abusing a privileged container. If a container is run with `--privileged` or specific capabilities like `SYS_ADMIN`, an attacker can mount the host's filesystem inside the container (e.g., `mount /dev/sda1 /mnt`) and then modify host files like `/mnt/etc/crontab` to execute code on the host.

---
#### **60. Question: What is "OSINT" (Open-Source Intelligence) and name three critical tools used during the reconnaissance phase of a penetration test.**
-  OSINT is the collection and analysis of publicly available information to support an assessment.
**Tools:**
1.  **theHarvester:** For gathering emails, subdomains, and hosts.
2.  **Shodan:** For finding specific devices and services exposed to the internet.
3.  **Maltego:** For visualizing relationships between data points (domains, IPs, people).

---
#### **61. Question: What is the strategic purpose of "Pivoting" after initial compromise?**
-  Pivoting uses a compromised machine (the "foothold") as a relay to attack other systems on networks that are not directly accessible from the internet. It extends the attacker's reach into the internal network, allowing them to target critical systems that are hidden behind firewalls.

---
#### **62. Question: How does the "NoPAC" (CVE-2021-42278/CVE-2021-42287) vulnerability allow for domain privilege escalation?**
-  This is a two-part vulnerability:
1.  **CVE-2021-42287:** A flaw allows a machine account name to be impersonated because the Domain Controller doesn't correctly handle the machine account's `sAMAccountName` attribute when it lacks a trailing `$`.
2.  **CVE-2021-42278:** A DC fails to find the computer account (because the attacker removed the `$`) and confuses it with a Domain Controller account, allowing the attacker to request a Ticket Granting Ticket (TGT) for the DC. By then modifying the ticket, the attacker can gain Domain Admin privileges.

---
#### **63. Question: What is "SQL Truncation Attack" and under what conditions is it exploitable?**
-  A SQL Truncation Attack exploits how databases handle long strings. If a database column has a fixed length (e.g., `username VARCHAR(20)`) and the application automatically truncates input without other checks, an attacker can register a user with a name like `"admin[many_spaces]x"`. The database truncates this to `"admin[spaces]"`, which might be identical to the actual `"admin"` account's stored username if the database ignores trailing spaces in comparisons. The attacker can then set a password for this "new" account, effectively taking over the original admin account.

---
#### **64. Question: Describe the "Buffer Overflow" mitigation technique "Stack Canaries" and how it works.**
-  A stack canary is a random value placed on the stack between the local variables and the return address. Before a function returns, it checks this value. If a buffer overflow occurs and overwrites the return address, it will also overwrite the canary. The function detects the changed canary and terminates the program, preventing exploitation. The name comes from the "canary in a coal mine" concept.

---
#### **65. Question: What is "WMI (Windows Management Instrumentation)" and how is it abused by attackers for execution and persistence?**
-  WMI is a core Windows administration feature. Attackers abuse it via:
*   **Execution:** Using `wmic.exe` or the `Win32_Process` class to create remote processes.
*   **Persistence:** Creating a WMI Event Subscription (e.g., `__EventFilter`, `__EventConsumer`) that triggers a malicious payload in response to a system event (like a user logon). This is very stealthy as it leaves no file on disk for traditional AV to scan.

---
#### **66. Question: In cryptography, what is a "Nonce" and why is it crucial in preventing replay attacks?**
-  A nonce ("number used once") is a random or pseudo-random number that is used only once in a cryptographic communication. It ensures that old communications cannot be reused in replay attacks. By including a unique nonce in each session or transaction, even if an attacker captures the data, they cannot simply resend it, as the nonce will be invalid or detected as a duplicate.

---
#### **67. Question: What is the "Orange Tsai" attack against URL parsers?**
-  This is a class of vulnerabilities discovered by researcher Orange Tsai that exploits inconsistencies in how different components of a web application (the web server, the application framework, and the application itself) parse URLs. By crafting a URL with special characters (like `@`, `#`, `?`, `\`), an attacker can trick one component into seeing one part of the URL while another component sees a different part, potentially leading to authentication bypass, SSRF, or path traversal.

---
#### **68. Question: How does "Resource-Based Constrained Delegation" (RBCD) work in Kerberos and how can it be exploited?**
-  In traditional constrained delegation, a service can impersonate users to *specific* other services. In RBCD, the *resource service* (e.g., a file server) defines which other services (delegates) are allowed to send forwardable tickets to it. An attacker who has the permission to modify a computer object's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute (e.g., via `GenericWrite`) can configure it to allow a service they control to impersonate any user to that computer, leading to privilege escalation.

---
#### **69. Question: What is a "Heap Spray" and why is it used in browser exploitation?**
-  A heap spray is a technique used to make memory exploitation more reliable. The attacker fills (sprays) a large portion of the browser's heap memory with their shellcode, often padded with NOP sleds. The goal is to place the shellcode at a predictable memory address. Then, when a memory corruption vulnerability (like a use-after-free) is triggered, the instruction pointer is highly likely to jump into the NOP sled and slide into the shellcode.

---
#### **70. Question: Explain the concept of "Domain Fronting" and what is its primary use case for attackers?**
-  Domain Fronting is a technique to evade censorship and hide C2 traffic by routing it through a large, trusted Content Delivery Network (CDN) like Google or Cloudflare. The attacker makes an HTTPS request to a benign, front-end domain hosted on the CDN (e.g., `google.com`), but in the HTTP `Host` header, they specify their actual, malicious back-end domain (e.g., `evil.com`). The CDN, based on the `Host` header, routes the request to the malicious server, while network inspection only sees a connection to `google.com`.

---
#### **71. Question: What is the "STRIDE" model and what is it used for?**
-  STRIDE is a threat modeling framework used to categorize security threats.
*   **S**poofing: Impersonating someone or something else.
*   **T**ampering: Modifying data or code.
*   **R**epudiation: Claiming you didn't perform an action.
*   **I**nformation Disclosure: Exposing information to unauthorized parties.
*   **D**enial of Service: Denying or degrading service to users.
*   **E**levation of Privilege: Gaining capabilities without authorization.

---
#### **72. Question: How does a "NOP Sled" (or NOP Slide) assist in buffer overflow exploitation?**
-  A NOP sled is a long sequence of No-Operation (NOP) instructions (or other one-byte instructions that have no material effect) placed before the shellcode. It increases the attack's reliability by widening the "target" in memory. The attacker only needs to overwrite the return address with an address that lands *anywhere* in the NOP sled. The CPU will then "slide" through the NOPs until it hits the shellcode and executes it.

---
#### **73. Question: What is "Spectre" and what is the fundamental hardware vulnerability it exploits?**
-  Spectre is a side-channel attack that exploits **speculative execution**, a performance feature in modern CPUs. The CPU speculatively executes instructions ahead of time, "guessing" which path a program will take. Spectre tricks the CPU into speculatively executing instructions that access privileged memory, and then uses a timing side-channel (e.g., via the cache) to infer the values of that privileged data.

---
#### **74. Question: In a phishing engagement, how would you bypass a secure email gateway (SEG) that scans all links?**
-  Techniques include:
*   **Time-based URL Activation:** Using a link that only redirects to the phishing page after a certain time, bypassing the SEG's initial scan.
*   **User Interaction:** Requiring the user to click a button or complete a CAPTCHA on a benign-looking intermediary page before redirecting to the malicious site.
*   **Domain Rotation:** Using a new, clean domain for each target or small batch of targets.
*   **Link Obfuscation:** Using URL shorteners or embedding links in attached documents (PDFs, DOCs) that the SEG might not scan deeply.

---
#### **75. Question: What is the critical difference between the "Pass the Hash" and "Overpass the Hash" attacks?**
-  
*   **Pass the Hash (PtH):** Uses the raw NTLM hash to authenticate directly via the NTLM protocol. It does not involve Kerberos.
*   **Overpass the Hash:** Uses the NTLM hash to *request a Kerberos Ticket-Granting Ticket (TGT)*. It essentially converts an NTLM hash into a Kerberos ticket, allowing the attacker to operate within the more prevalent and potentially less monitored Kerberos ecosystem.

---
#### **76. Question: What is a "Polyglot" file and how is it used in offensive security?**
-  A polyglot file is a file that is valid and executable in multiple formats simultaneously (e.g., a file that is both a valid GIF image and a valid JavaScript file). It's used to bypass file upload filters and AV scanners. The security tool might see it as a benign image, but when interpreted by a browser or other application, it executes as malicious code.

---
#### **77. Question: Explain the "CCM / CCR" method for retrieving Azure AD credentials from a hybrid-joined device.**
-  This involves the Primary Refresh Token (PRT) in Azure AD. On a hybrid Azure AD-joined machine, the PRT is backed by a key stored in the TPM. However, the `CloudAP` plugin handles PRT requests. By using tools like `ROADtoken` or `AADInternals`, an attacker can request a Primary Refresh Token for the current user and then use it to request access tokens for other services (like Microsoft Graph), effectively compromising the Azure AD user's identity.

---
#### **78. Question: What is "SQL Injection" and how do "Prepared Statements" (Parameterized Queries) prevent it?**
-  SQL Injection occurs when untrusted user input is concatenated directly into a SQL query, allowing an attacker to alter the query's structure. **Prepared Statements** separate the SQL logic from the data. The query structure (with placeholders, e.g., `SELECT * FROM users WHERE id = ?`) is sent to the database first. The user input is then sent later as pure data. The database knows the input is data, not code, so it cannot change the query's meaning, thus preventing SQLi.

---
#### **79. Question: What is "VBA Stomping" and why is it effective against static analysis?**
-  VBA Stomping is a technique where a malicious Microsoft Office document is crafted with a discrepancy between the "p-code" (a semi-compiled intermediate language) and the source VBA code. The source VBA code visible in the VBA editor (the VBA project stream) is benign, but the p-code, which is what the VBA interpreter *actually executes*, is malicious. Many static analysis tools and manual reviewers only look at the source VBA code, allowing the malware to evade detection.

---
#### **80. Question: Describe the "ICS/SCADA" attack vector that involves "Ladder Logic".**
-  Ladder Logic is a programming language used for Programmable Logic Controllers (PLCs) in industrial environments. An attacker who gains access to the engineering workstation or network can upload malicious Ladder Logic to a PLC. This logic could cause physical damage—for example, by ignoring safety limits, overriding sensor inputs, or commanding actuators to operate in an unsafe manner, potentially destroying equipment or creating dangerous conditions.

---
#### **81. Question: What is the purpose of the "skeleton key" malware in an Active Directory context?**
-  Skeleton Key is a malware that runs on a Domain Controller (DC) and patches the LSASS process in memory. Once installed, it allows an attacker to authenticate to the domain as *any* user (including Domain Admins) using a single, universal "master" password, in addition to the user's real password. It provides persistent backdoor access without changing user account attributes.

---
#### **82. Question: How does the "NetNTLMv2" relay attack work and what is a primary mitigation?**
-  This attack involves capturing a NetNTLMv2 challenge-response hash (e.g., via Responder) and then "relaying" it to another service (like a web server's authentication endpoint) in real-time. If the relay is successful, the attacker authenticates as the victim. A primary mitigation is enabling **SMB Signing** on all hosts, which ensures the integrity of the SMB communication and prevents the relayed session from being established.

---
#### **83. Question: What is "Process Hollowing" and how does it differ from "Process Injection"?**
-  Both are code injection techniques. **Process Hollowing** creates a new, suspended instance of a legitimate process (e.g., `svchost.exe`). It then "hollows out" its memory, unmapping the legitimate code and replacing it with malicious code before resuming the thread. **Process Injection** typically targets an *already running* process and injects code into its existing memory space. Hollowing is often used for launching malware, while injection is used for runtime manipulation.

---
#### **84. Question: In a bug bounty program, what is the typical finding that would be classified as "Improper Asset Management"?**
-  This occurs when an organization fails to decommission old, forgotten assets (subdomains, IPs, cloud instances) that are still part of their attack surface. A classic finding is a **subdomain takeover**, where a subdomain points to a service (e.g., Heroku, S3) that no longer exists, allowing an attacker to claim it.

---
#### **85. Question: What is "SeBackupPrivilege" and how can it be abused for privilege escalation?**
-  It's a Windows privilege (`SeBackupPrivilege`) that allows a user to read any file on the system, ignoring standard DACLs (Discretionary Access Control Lists). An attacker with this privilege can use tools like `diskshadow` and `robocopy` to create a shadow copy of the `C:` drive and then extract sensitive files like the `NTDS.dit` (Active Directory database) and `SYSTEM` hive, which can be used to dump all domain user hashes.

---
#### **86. Question: Explain the "BlueKeep" vulnerability (CVE-2019-0708).**
-  BlueKeep is a critical remote code execution vulnerability in the Remote Desktop Protocol (RDP) service on older Windows systems (like Windows 7, XP, Server 2008). It is "wormable," meaning it can self-propagate without user interaction. The flaw is in how RDP handles certain connection requests, allowing an unauthenticated attacker to run arbitrary code with system privileges.

---
#### **87. Question: What is "Mimikatz" and what is the single most important defensive control to mitigate its primary function?**
-  Mimikatz is a legendary post-exploitation tool that can extract plaintext passwords, hashes, and Kerberos tickets from LSASS memory. The single most important defensive control is **Credential Guard** on Windows 10/11 and Server 2016+. It uses virtualization-based security to isolate LSASS and prevent unauthorized access to these credentials, rendering standard Mimikatz commands ineffective.

---
#### **88. Question: What is a "CAN Bus" and what is a security concern in automotive hacking?**
-  The Controller Area Network (CAN Bus) is a robust vehicle bus standard that allows microcontrollers and devices to communicate with each other without a host computer. A security concern is its **lack of authentication**. Any device on the CAN Bus can send commands, meaning if an attacker gains access (e.g., via the OBD-II port or an infected infotainment system), they can send messages to critical Electronic Control Units (ECUs) to disable brakes, alter steering, or control the engine.

---
#### **89. Question: How does the "LSA Protection" (RunAsPPL) setting in Windows help protect against credential theft?**
-  LSA Protection configures the LSASS process to run as a **Protected Process Light (PPL)**. This prevents non-admin and non-protected processes from accessing the LSASS process memory, which blocks many credential dumping tools, including the standard version of Mimikatz. To bypass it, an attacker would need to load a driver, which requires `SeLoadDriverPrivilege` or kernel-level access.

---
#### **90. Question: What is "Shodan" and how would you use it to find vulnerable industrial control systems?**
-  Shodan is a search engine for Internet-connected devices. To find vulnerable ICS, I would use specific search filters and queries for:
*   **Protocols:** `port:502` (Modbus), `port:102` (Siemens S7), `port:44818` (Allen-Bradley EtherNet/IP).
*   **Banners:** `"Schneider Electric"` or `"SIMATIC"`.
*   **Vulnerabilities:** `"heartbleed"` or `product:"VxWorks"`.
This would reveal exposed PLCs and SCADA systems that should not be accessible from the internet.

---
#### **91. Question: Describe the "DCSync" attack and what permissions are required to perform it.**
-  The DCSync attack impersonates a Domain Controller and uses the Directory Replication Service (DRS) protocol to request password data from a legitimate DC. To perform this, an account needs replication rights over the domain, which is typically granted to Domain Admins, Enterprise Admins, and the Domain Controller computer accounts. However, these rights can be delegated to other users, making it a powerful persistence technique.

---
#### **92. Question: What is "Code Signing" and how can attackers bypass it using "Stolen Certificates"?**
-  Code Signing uses digital certificates to verify that software comes from a trusted publisher and hasn't been altered. Attackers bypass this by stealing the private key of a legitimate software company (e.g., through a breach or by purchasing it on darknet markets). They then sign their malware with this stolen certificate, making it appear trusted by the operating system and many security products.

---
#### **93. Question: What is the "OWASP Top 10" and what was the most significant change in the 2021 version compared to 2017?**
-  The OWASP Top 10 is a standard awareness document representing the most critical security risks to web applications. The most significant change in 2021 was the consolidation of **A4:2017-XML External Entities (XXE)** into other categories and the introduction of three new categories: **A08:2021-Software and Data Integrity Failures** (covering supply chain attacks) and moving **Insecure Deserialization** up to **A08:2017** and now part of **A08:2021**.

---
#### **94. Question: Explain the "Zero-Trust" security model in one sentence.**
-  Zero-Trust is a security framework that mandates "never trust, always verify," requiring strict identity verification for every person and device trying to access resources on a private network, regardless of whether they are sitting within or outside of the network perimeter.

---
#### **95. Question: What is "Vulnerability Chaining" and why is it a critical concept in penetration testing?**
-  Vulnerability Chaining is the process of combining multiple lower-severity vulnerabilities to achieve a greater impact, such as full system compromise. For example, chaining a low-privilege SQL Injection with a local file inclusion to read the `/etc/passwd` file. It's critical because real-world attacks rarely rely on a single "critical" flaw; they exploit a series of misconfigurations and bugs.

---
#### **96. Question: How does the "ICMP Tunnel" covert channel work?**
-  An ICMP Tunnel encapsulates data within ICMP Echo Request (ping) and Echo Reply packets. A client on the internal network sends pings containing command output to an external server controlled by the attacker. The server sends back pings containing new commands. Because many networks allow ICMP outbound, this can be used to establish a stealthy C2 channel that bypasses firewall rules blocking traditional protocols.

---
#### **97. Question: What is the "Sysmon" tool and what is its primary value in a SOC?**
-  Sysmon (System Monitor) is a Windows system service and device driver that, once installed, logs detailed information about system activity to the Windows Event Log. Its primary value is providing high-fidelity, granular logs for **process creation, network connections, and file creation**, which are essential for threat hunting, detection engineering, and incident investigation.

---
#### **98. Question: What is a "Rainbow Table" and why are they less effective against modern password hashes?**
-  A Rainbow Table is a precomputed table for reversing cryptographic hash functions, used to crack password hashes. They are less effective today because of the widespread use of **salting**. A salt is a random value unique to each password that is hashed alongside it. This means a precomputed rainbow table is useless, as an attacker would need to generate a new table for every single salt, which is computationally infeasible.

---
#### **99. Question: In a physical penetration test, what is a "tailgating" attack?**
-  Tailgating (or "piggybacking") is a social engineering physical security attack where an unauthorized person follows an authorized person into a restricted area without their consent (e.g., by walking closely behind them as they use their access card on a door).

---
#### **100. Question: What is the fundamental purpose of the "MITRE ATT&CK" framework?**
-  The MITRE ATT&CK framework is a globally accessible knowledge base of adversary **Tactics, Techniques, and Procedures (TTPs)** based on real-world observations. Its purpose is to provide a common language and taxonomy for describing post-compromise attacker behavior, which is used for threat intelligence, detection and analytics, red teaming, and adversary emulation.
