
---
#### **151. Question: What is "Process Doppelgänging" and how does it differ from Process Hollowing?**
-  Process Doppelgänging is a fileless code execution technique that abuses Windows Transactional NTFS (TxF). It involves creating a transaction, modifying a legitimate executable within that transaction, creating a section from the transacted file, then rolling back the transaction before creating a process from the section. Unlike Process Hollowing, it never writes the malicious content to disk and leaves minimal forensic traces since the transaction is rolled back.

---
#### **152. Question: Explain the "Kerberoasting" attack and what makes it particularly effective.**
-  Kerberoasting is an attack where an attacker requests service tickets (TGS) for services that use SPN (Service Principal Names) and then attempts to crack the service account password offline. It's effective because:
1. Any domain user can request these tickets
2. Service accounts often have weak, easily crackable passwords
3. The tickets are encrypted with the service account's password hash
4. It's a low-and-slow attack that's difficult to detect in normal traffic

---
#### **153. Question: What is "AMSI Bypass" and why is it a cat-and-mouse game between attackers and defenders?**
-  AMSI (Antimalware Scan Interface) scans scripts and payloads in memory before execution. AMSI bypasses are techniques to evade this scanning. It's a cat-and-mouse game because Microsoft continuously patches AMSI detection mechanisms, while attackers continuously find new ways to obfuscate, encrypt, or modify their payloads to avoid detection signatures and behavioral analysis.

---
#### **154. Question: Describe the "DNS Cache Poisoning" attack and how DNSSEC helps prevent it.**
-  DNS Cache Poisoning involves corrupting a DNS resolver's cache with false information, redirecting users to malicious sites. DNSSEC (Domain Name System Security Extensions) prevents this by adding cryptographic signatures to DNS records, allowing resolvers to verify the authenticity and integrity of DNS responses, ensuring they haven't been tampered with.

---
#### **155. Question: What is "Virtualization-Based Security" (VBS) in Windows and what are its core components?**
-  VBS uses hardware virtualization features to create isolated, secure regions of memory from the normal operating system. Core components include:
- **Credential Guard:** Isolates and protects credentials
- **Hypervisor-Protected Code Integrity (HVCI):** Ensures only signed, trusted code runs in kernel mode
- **Application Guard:** Isolates Microsoft Edge in a container

---
#### **156. Question: How does the "PrintSpoofer" (CVE-2021-1675) exploit work for privilege escalation?**
-  PrintSpoofer exploits the Print Spooler service by leveraging named pipe impersonation. It creates a named pipe that the Print Spooler (running as SYSTEM) connects to, then impersonates the SYSTEM token. This allows a low-privileged user with SeImpersonatePrivilege to gain SYSTEM-level access by tricking the spooler service into authenticating to their controlled pipe.

---
#### **157. Question: What is "API Monitoring" in EDR solutions and how do attackers evade it?**
-  API Monitoring involves hooking critical Windows APIs to monitor for suspicious behavior. Attackers evade it through:
- **Direct System Calls:** Making system calls directly instead of through monitored APIs
- **API Unhooking:** Removing the EDR's hooks from API functions
- **Custom Loaders:** Using reflective DLL injection or manual mapping
- **ROP-based execution:** Using return-oriented programming to avoid direct API calls

---
#### **158. Question: Explain the "Golden GMSA" attack in Active Directory.**
-  Group Managed Service Accounts (gMSAs) have automatically managed passwords. The "Golden GMSA" attack occurs when an attacker with appropriate permissions dumps the gMSA password, which is stored in the AD attribute `msDS-ManagedPassword`. Since these passwords are long and complex but change automatically, obtaining one provides long-term persistence without the need for password rotation.

---
#### **159. Question: What is "Network Segmentation" and why is it considered a fundamental security control?**
-  Network Segmentation involves dividing a network into smaller, isolated segments to limit the spread of attacks. It's fundamental because it:
- Contains breaches to a single segment
- Prevents lateral movement
- Allows for more granular security policies
- Reduces the attack surface by isolating critical systems

---
#### **160. Question: How does "SIM Jacking" work and what makes it particularly dangerous for MFA?**
-  SIM Jacking involves social engineering a mobile carrier to transfer a victim's phone number to a SIM card controlled by the attacker. This is particularly dangerous for MFA because it allows the attacker to receive SMS-based two-factor authentication codes, effectively bypassing this security layer and taking over accounts protected by SMS 2FA.

---
#### **161. Question: What is "SeAssignPrimaryTokenPrivilege" and how can it be abused?**
-  This privilege allows a process to assign a primary token to a new process, enabling it to create processes under different user contexts. An attacker with this privilege can create processes with stolen tokens from higher-privileged users, effectively escalating their privileges by impersonating those users in new processes.

---
#### **162. Question: Describe the "AD CS ESC8" vulnerability and its impact.**
-  AD CS ESC8 is a vulnerability in Active Directory Certificate Services where the web enrollment endpoint is vulnerable to NTLM relay attacks. An attacker can coerce authentication from a machine account and relay it to the AD CS web interface to obtain a certificate for that machine, which can then be used for authentication and privilege escalation within the domain.

---
#### **163. Question: What is "Memory Corruption" and why is it such a pervasive class of vulnerabilities?**
-  Memory corruption occurs when a program accesses memory in ways it shouldn't, leading to crashes, unexpected behavior, or code execution. It's pervasive because:
- C/C++ languages don't have built-in memory safety
- Complex software has many edge cases
- Memory management is error-prone
- Many legacy codebases weren't written with security in mind

---
#### **164. Question: How does "Control Flow Guard" (CFG) work as a mitigation against memory corruption attacks?**
-  CFG is a compiler-based security feature that protects against memory corruption exploits. It creates a "valid call target" bitmap for each process and inserts checks before indirect function calls to ensure the target address is valid. This prevents attackers from redirecting execution to arbitrary locations in memory via ROP or jump-oriented programming.

---
#### **165. Question: What is "SeCreateTokenPrivilege" and why is it extremely dangerous?**
-  This privilege allows a process to create primary tokens, which can be used to create new logon sessions. With this privilege, an attacker can create tokens with any set of privileges, including SYSTEM-level tokens, effectively granting themselves unlimited administrative access to the system.

---
#### **166. Question: Explain the "DFSCoerce" attack vector in Active Directory.**
-  DFSCoerce is an authentication coercion attack that tricks a target machine into authenticating to an attacker-controlled server by abusing the Distributed File System (DFS) referral process. Similar to PetitPotam, it can be used to force a machine (including Domain Controllers) to reveal their computer account hash via NTLM, which can then be relayed or cracked.

---
#### **167. Question: What is "Code Cave" and how is it used in malware development?**
-  A Code Cave is an unused area within a legitimate executable file where malicious code can be inserted without affecting the original program's functionality. Malware authors use code caves to hide their payloads within trusted, signed binaries, making detection more difficult as the file maintains its valid digital signature.

---
#### **168. Question: How does "JEA (Just Enough Administration)" differ from traditional administrative access?**
-  Traditional administrative access grants broad, unrestricted access to systems. JEA provides constrained, role-based administration where users can only perform specific, pre-defined tasks using limited PowerShell commands and parameters. It follows the principle of least privilege by restricting what actions can be performed, even for administrative tasks.

---
#### **169. Question: What is "SeRestorePrivilege" and how can it lead to privilege escalation?**
-  This privilege allows a user to restore files and directories, overriding any existing permissions. An attacker with this privilege can replace critical system files (like executables or libraries) with malicious versions, or restore a backup of the SAM hive to extract password hashes, leading to full system compromise.

---
#### **170. Question: Describe the "NOP Generator" technique in shellcode obfuscation.**
-  A NOP Generator creates a sequence of instructions that have no operational effect but serve as a sled for the execution flow. Advanced NOP generators use complex, multi-byte instructions that effectively behave as NOPs but don't use the traditional 0x90 byte, helping to evade signature-based detection that looks for simple NOP sleds.

---
#### **171. Question: What is "Token Privilege Escalation" and name three commonly abused privileges.**
-  Token Privilege Escalation involves leveraging Windows privileges assigned to a user token to gain higher levels of access. Three commonly abused privileges are:
1. **SeDebugPrivilege:** Allows debugging other processes, enabling memory dumping
2. **SeImpersonatePrivilege:** Allows impersonating other users
3. **SeLoadDriverPrivilege:** Allows loading device drivers, enabling kernel access

---
#### **172. Question: How does "Control Flow Integrity" (CFI) protect against code reuse attacks?**
-  CFI is a security mechanism that ensures program execution follows a predetermined, valid control-flow graph. It validates indirect branch targets (calls and jumps) at runtime to ensure they point to legitimate locations, making it much harder for attackers to redirect execution to ROP gadgets or other unauthorized code locations.

---
#### **173. Question: What is "SeTcbPrivilege" and why is it considered one of the most powerful privileges?**
-  SeTcbPrivilege (Act as part of the operating system) allows a process to authenticate as any user and impersonate SYSTEM. It's extremely powerful because it essentially grants the ability to bypass all security checks and act as the operating system itself, enabling complete control over the system.

---
#### **174. Question: Explain the "Shadow Credentials" attack in Active Directory.**
-  The Shadow Credentials attack involves adding an alternate, attacker-controlled certificate to a target user or computer object's `msDS-KeyCredentialLink` attribute. This allows the attacker to authenticate as that principal using the certificate instead of a password, effectively taking over the account without needing to know or reset the password.

---
#### **175. Question: What is "SeManageVolumePrivilege" and how can it be abused?**
-  This privilege allows a user to perform maintenance operations on storage volumes. An attacker with this privilege can use tools to read and write directly to disk sectors, potentially accessing or modifying files outside of normal file system permissions, including system files and the page file which may contain sensitive data.

---
#### **176. Question: How does "Address Space Layout Randomization" (ASLR) make exploitation more difficult?**
-  ASLR randomizes the memory locations of key data areas, including the base of the executable and positions of the stack, heap, and libraries. This makes it difficult for attackers to predict memory addresses needed for successful exploitation, as the addresses change with each execution, requiring information leaks or other techniques to bypass.

---
#### **177. Question: What is "SeLockMemoryPrivilege" and what are its security implications?**
-  This privilege allows a process to lock pages in physical memory, preventing them from being paged to disk. While normally used for performance, an attacker could use this to:
- Prevent sensitive data from being written to the page file
- Cause memory exhaustion leading to denial of service
- Interfere with forensic analysis that relies on page file examination

---
#### **178. Question: Describe the "RPC Endpoint Mapper" attack vector.**
-  The RPC Endpoint Mapper (port 135) can be queried to discover other RPC services running on a system. Attackers use this to enumerate available services and identify potentially vulnerable interfaces. While the mapper itself isn't typically exploited directly, it serves as a valuable reconnaissance tool for identifying additional attack surfaces.

---
#### **179. Question: What is "SeSecurityPrivilege" and how can it be used in security operations?**
-  This privilege allows a user to manage auditing and security logs. While important for legitimate security monitoring, an attacker with this privilege could:
- Clear security logs to cover their tracks
- Modify audit policies to avoid detection
- Access security log information to understand monitoring capabilities

---
#### **180. Question: How does "Data Execution Prevention" (DEP) protect against common exploitation techniques?**
-  DEP marks certain memory regions (typically stack and heap) as non-executable, preventing code from being run in those areas. This protects against common shellcode injection techniques where attackers would place malicious code in data areas and jump to it, forcing them to use more complex techniques like ROP.

---
#### **181. Question: What is "SeSystemEnvironmentPrivilege" and what are its potential abuses?**
-  This privilege allows a user to modify firmware environment values stored in non-volatile RAM. An attacker with this privilege could potentially modify boot settings, alter hardware configurations, or persist malware across reboots by modifying firmware settings.

---
#### **182. Question: Explain the "GPO Abuse" technique for lateral movement.**
-  GPO Abuse involves modifying Group Policy Objects to push malicious settings or executables to target computers. An attacker with sufficient permissions can:
- Add a malicious script to the startup/shutdown or logon/logoff scripts
- Modify security settings to weaken defenses
- Deploy malicious software through software installation policies
This provides a powerful mechanism for lateral movement and persistence across multiple systems.

---
#### **183. Question: What is "SeTrustedCredManAccessPrivilege" and how does it relate to credential theft?**
-  This privilege allows access to Credential Manager as a trusted caller. An attacker with this privilege can dump stored credentials from Windows Credential Manager, which may contain saved passwords for websites, network resources, or other systems, potentially providing access to additional systems and services.

---
#### **184. Question: How does "Stack Canary" protection work and what are its limitations?**
-  Stack Canaries place a random value before the return address on the stack and check it before function return. If the value is modified (as in a buffer overflow), the program terminates. Limitations include:
- Can be leaked if there's an information disclosure vulnerability
- Some implementations use predictable values
- Doesn't protect against non-stack-based overflows or other memory corruption types

---
#### **185. Question: What is "SeTakeOwnershipPrivilege" and how does it enable privilege escalation?**
-  This privilege allows a user to take ownership of any securable object. With this privilege, an attacker can take ownership of critical files, registry keys, or other objects, grant themselves full permissions, and then modify them. For example, they could take ownership of a service binary and replace it with a malicious version.

---
#### **186. Question: Describe the "WSUS Man-in-the-Middle" attack.**
-  This attack targets Windows Server Update Services (WSUS) by performing a man-in-the-middle attack between clients and the update server. If WSUS uses HTTP instead of HTTPS (or if certificate validation is weak), an attacker can intercept and replace legitimate updates with malicious ones, which clients will automatically install with system privileges.

---
#### **187. Question: What is "SeBackupPrivilege" and how can it lead to credential dumping?**
-  As covered previously, this privilege allows reading any file on the system. It can be used to dump credentials by:
- Reading the SAM hive to get local account hashes
- Reading the NTDS.dit file on Domain Controllers for domain hashes
- Accessing memory dumps or page files that may contain credentials
- Copying protected files for offline analysis

---
#### **188. Question: How does "Control Flow Guard" (CFG) differ from "Arbitrary Code Guard" (ACG)?**
-  CFG protects against control-flow hijacking by validating indirect calls, while ACG prevents the allocation of executable memory that isn't part of the original image. CFG ensures execution stays within valid code paths, while ACG ensures no new executable code can be created at runtime, providing complementary protections against code execution attacks.

---
#### **189. Question: What is "SeCreatePermanentPrivilege" and what are its potential risks?**
-  This privilege allows a user to create permanent objects in the object manager. While somewhat obscure, it could potentially be abused to create permanent kernel objects that persist beyond process termination, potentially enabling rootkit-like functionality or other low-level system manipulation.

---
#### **190. Question: Explain the "DCOM Lateral Movement" technique.**
-  DCOM (Distributed Component Object Model) Lateral Movement involves using DCOM interfaces to execute code on remote systems. An attacker can instantiate DCOM objects remotely and invoke methods that allow command execution, such as the MMC20.Application object's ExecuteShellCommand method, providing a way to move laterally without traditional remote execution services.

---
#### **191. Question: What is "SeSyncAgentPrivilege" and how is it relevant in Active Directory environments?**
-  This privilege allows a user to synchronize Active Directory data. While intended for directory replication, an attacker with this privilege could potentially abuse it to:
- Read sensitive directory information
- Monitor for changes in the directory
- Interfere with replication processes
- Gain intelligence about the AD environment

---
#### **192. Question: How does "Return-oriented Programming" (ROP) bypass DEP protection?**
-  ROP bypasses DEP by reusing existing code snippets (gadgets) in executable memory regions rather than injecting new shellcode. By chaining together these gadgets that end with return instructions, attackers can build complex operations that execute malicious logic without violating DEP, as all executed code already exists in legitimate, executable memory pages.

---
#### **193. Question: What is "SeEnableDelegationPrivilege" and why is it dangerous in domain environments?**
-  This privilege allows enabling delegation settings on user and computer accounts. In domain environments, this is dangerous because an attacker with this privilege could configure unconstrained delegation on compromised accounts, allowing them to capture and reuse authentication tickets from any users who authenticate to those systems, including privileged accounts.

---
#### **194. Question: Describe the "XSS to RCE" attack chain in web applications.**
-  This attack chain starts with a Cross-Site Scripting vulnerability that allows an attacker to execute JavaScript in a user's browser. If the web application has additional functionality (like a admin panel that allows command execution), the attacker can use the XSS to make authenticated requests to that functionality, potentially achieving remote code execution on the underlying server.

---
#### **195. Question: What is "SeAuditPrivilege" and how can it be used to evade detection?**
-  This privilege allows a process to generate security audit log entries. While typically used legitimately, an attacker with this privilege could potentially:
- Generate fake audit events to create noise and hide real attacks
- Manipulate audit policies through other means if combined with additional privileges
- Gain insight into what events are being audited

---
#### **196. Question: How does "Jump-oriented Programming" (JOP) differ from traditional ROP?**
-  While ROP uses gadgets ending with return instructions, JOP uses gadgets ending with indirect jump instructions. JOP chains are controlled through a dispatcher gadget that manages execution flow, making them more complex to construct but potentially more stealthy and resistant to some ROP detection techniques.

---
#### **197. Question: What is "SeRelabelPrivilege" and what are its potential security implications?**
-  This privilege allows a user to modify the integrity level of objects. In Mandatory Integrity Control systems, this could allow an attacker to:
- Raise the integrity level of malicious processes
- Lower the integrity level of protected objects
- Bypass integrity protection mechanisms
- Potentially elevate privileges through integrity level manipulation

---
#### **198. Question: Explain the "WSH Injection" technique for persistence.**
-  WSH (Windows Script Host) Injection involves modifying or creating WSH script files (.vbs, .js) that execute malicious code. This can be used for persistence by:
- Modifying existing legitimate scripts
- Creating new scripts in startup folders
- Modifying file associations to use malicious scripts
- Abusing WSH components through other persistence mechanisms

---
#### **199. Question: What is "SeSystemtimePrivilege" and how could it be abused?**
-  This privilege allows a user to modify the system time. While seemingly benign, it could be abused to:
- Disrupt time-sensitive applications and services
- Interfere with Kerberos authentication (which relies on time synchronization)
- Cause issues with logging and audit trail accuracy
- Potentially affect scheduled tasks and cron jobs

---
#### **200. Question: How does "Code Integrity Guard" (CIG) protect against malicious code execution?**
-  CIG is a Windows security feature that restricts which DLLs can be loaded into a process. It ensures that only DLLs signed by Microsoft or with specific certificates can be loaded, preventing the injection of unauthorized or malicious libraries into protected processes, thereby maintaining the integrity of the application's code.
