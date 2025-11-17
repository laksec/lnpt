
---
#### **1. Question: How would you differentiate between a stateful and a stateless firewall, and in what scenario would you recommend one over the other?**
-  A stateful firewall tracks the state of active connections (e.g., TCP handshakes), making decisions based on the context of the traffic. A stateless firewall uses static rules (e.g., IP/port) without context. I'd recommend a stateful firewall for a corporate network perimeter for better security against spoofing and complex protocols. A stateless firewall might be used for high-speed, internal network segmentation where raw speed is critical and traffic is predictable.

---
#### **2. Question: Explain the process of exploiting a Blind SQL Injection vulnerability where you cannot see the direct output.**
-  I would use inference techniques. For time-based blind SQLi, I'd inject a query with a `SLEEP()` or `WAITFOR DELAY` command, observing the response time to confirm the vulnerability and extract data character by character. For boolean-based blind SQLi, I'd craft queries that return a true or false response (e.g., different HTTP status codes or page content) based on a condition, like `' AND (SELECT SUBSTRING(password,1,1) FROM users)='a'--`.

---
#### **3. Question: What is the key security improvement in Kerberos that mitigates Pass-the-Hash attacks, and how does it work?**
-  The key improvement is the use of **Kerberos authentication** itself, which relies on ticket-granting tickets (TGTs) and service tickets rather than NTLM hashes. Specifically, **Kerberos Resource-Based Constrained Delegation** and the move away from NTLM make PtH less effective. However, the most direct mitigation is using **Protected Process Light (PPL)** for LSASS and credential guard in Windows 10/11, which isolates and protects hashes in memory.

---
#### **4. Question: Describe a scenario where you might use DNS exfiltration and how you would detect it.**
-  I'd use DNS exfiltration when outbound HTTP/HTTPS traffic is heavily monitored and blocked. Data is encoded into subdomains of a domain I control (e.g., `[encoded-data].evil.com`). The DNS queries for these subdomains are sent to my malicious DNS server, which logs the encoded data. To detect this, monitor DNS logs for unusual patterns: high volume of DNS queries to a single domain, long and random subdomain names, queries for TXT or NULL records, and traffic outside of business hours.

---
#### **5. Question: What is the fundamental difference between ASLR (Address Space Layout Randomization) and DEP (Data Execution Prevention)?**
-  ASLR is a memory *randomization* technique. It randomizes the base addresses of key memory regions (stack, heap, libraries) for each process, making it harder for an attacker to predict memory addresses for exploits. DEP is a memory *protection* technique. It marks certain areas of memory (like the stack and heap) as non-executable, preventing code from being run in those regions and stopping shellcode injection attacks.

---
#### **6. Question: During a post-exploitation phase, you find a system that is air-gapped. How would you attempt to exfiltrate data?**
-  This is a highly complex scenario. I would look for a "sneakernet" vector, such as infecting a USB drive used for data transfer (using tools like BadUSB). Alternatively, I could attempt a covert channel using:
*   **Acoustics:** Modulating data into sound waves using the system's speaker/microphone.
*   **Thermals:** Manipulating CPU load to create thermal signatures.
*   **Electromagnetic:** Using EM emissions from the monitor or cables to transmit data.
*   **Optical:** Blinking the keyboard LEDs or screen pixels in a pattern to be read by a camera.

---
#### **7. Question: Explain the concept of a "Time-of-Check to Time-of-Use" (TOCTOU) race condition vulnerability.**
-  It's a software flaw where the state of a resource (e.g., a file) is checked ("time-of-check") but then used ("time-of-use") after that check. An attacker can alter the resource in the tiny window between the check and the use. For example, a privileged program might check if a file is owned by the user, but before it opens it, the attacker swaps it with a symbolic link to a sensitive system file like `/etc/passwd`.

---
#### **8. Question: How does the "Pass the Ticket" attack work in a Kerberos environment?**
-  In a Kerberos environment, after a user authenticates, they receive a Ticket-Granting Ticket (TGT). A "Pass the Ticket" attack involves stealing this Kerberos TGT from memory (using tools like Mimikatz) and then reusing it on another machine to request access to resources as that user, without needing their password or hash. This is different from "Pass the Hash," which targets NTLM authentication.

---
#### **9. Question: What are the key differences between Threat Hunting and traditional Incident Response?**
-  **Incident Response** is reactive; it's the process of managing and mitigating a security incident *after* it has been detected. **Threat Hunting** is proactive; it's the hypothesis-driven search for malicious activity that has evaded existing automated detection tools. It assumes adversaries are already in the network and seeks to find them based on TTPs (Tactics, Techniques, and Procedures) rather than alerts.

---
#### **10. Question: Explain how a CSRF (Cross-Site Request Forgery) attack works and how a SameSite cookie attribute can prevent it.**
-  CSRF tricks a logged-in user's browser into making an unintended request to a web application where they are authenticated. The browser automatically includes the user's session cookie. The `SameSite` cookie attribute (`Strict` or `Lax`) tells the browser not to send the cookie with cross-site requests. `Strict` never sends it on cross-site requests, while `Lax` allows it for safe top-level navigations (like clicking a link) but not for cross-site POST requests, which effectively blocks most CSRF attacks.

---
#### **11. Question: What is DLL Side-Loading and how is it used for persistence and evasion?**
-  DLL Side-Loading exploits the Windows DLL search order. A legitimate application is tricked into loading a malicious DLL placed in a directory that is searched *before* the legitimate system directory (like the application's own folder). By replacing a legitimate but vulnerable DLL with a malicious one, an attacker can achieve code execution whenever the application runs, which is excellent for persistence and evading application whitelisting if the main application is trusted.

---
#### **12. Question: Describe the process of exploiting a vulnerable SAML implementation.**
-  A common flaw is improper validation of the SAML response. I would look for:
*   **Signature Bypass:** Removing the signature entirely, using key confusion attacks (e.g., using the public key as a certificate), or exploiting weak algorithms.
*   **XML External Entity (XXE) Injection:** To read local files from the Identity Provider (IdP) server.
*   **SAML Comment Injection:** Injecting comments into the `NameID` field to manipulate the parsed data, potentially impersonating another user (e.g., `userA<!-- -->@domain.com` becomes `userA@domain.com` after comment removal, but a flawed parser might see it as `userA`).

---
#### **13. Question: In cloud environments, what is the "Confused Deputy Problem" and how do IAM Roles help mitigate it?**
-  The Confused Deputy problem occurs when a privileged service (the deputy) is tricked by a less-privileged attacker into using its privileges in an unintended way. In AWS, this could be a user convincing a EC2 instance with a powerful role to perform actions on their behalf. IAM Roles with precise resource-based policies (e.g., an S3 bucket policy with a `aws:SourceArn` condition) mitigate this by explicitly defining *which* resources can be accessed by *which* roles, preventing cross-account abuse.

---
#### **14. Question: What is the strategic purpose of a "Canary" or "Honeytoken" in defensive security?**
-  A canary (like a Canarytoken) is a digital bait placed in a network (e.g., a fake API key in code, a dummy file on a share). It has no legitimate use. When an attacker interacts with it, it triggers an alert, providing a high-fidelity signal of a breach. Its purpose is early detection, indicating that an attacker has moved beyond initial access into data discovery and exfiltration stages.

---
#### **15. Question: How does the "Golden Ticket" attack in Active Directory fundamentally compromise the entire forest?**
-  A Golden Ticket attack requires the KRBTGT account's password hash, which is used to encrypt/sign all Kerberos TGTs. With this hash, an attacker can forge a TGT for *any* user to *any* service in the forest, with any group membership (including Domain Admins) and an arbitrary expiration date. This provides unlimited, persistent access because it's not tied to any user's password and is virtually undetectable by traditional means, as the forged TGT is cryptographically valid.

---
#### **16. Question: Explain the principle behind a ROP (Return-Oriented Programming) chain and why it's used to bypass DEP.**
-  DEP marks the stack as non-executable, preventing traditional shellcode execution. ROP bypasses this by reusing small, pre-existing code snippets ("gadgets") already in the program's memory (e.g., in `ntdll.dll`). Each gadget ends with a `ret` instruction. An attacker chains the addresses of these gadgets on the stack. The `ret` instruction pops an address off the stack and jumps to it, creating a chain of execution that performs a desired task (like calling `VirtualProtect` to make the stack executable) without injecting new code.

---
#### **17. Question: What is the key difference in exploitation between a Stack Buffer Overflow and a Heap Buffer Overflow?**
-  The key difference is predictability and exploitation technique. A **stack overflow** directly overwrites the return address on the stack, allowing for relatively straightforward control of the instruction pointer (EIP/RIP). A **heap overflow** is more complex; it typically corrupts heap metadata (like chunk headers in glibc's `malloc`) or overwrites function pointers or C++ vtables stored on the heap, leading to arbitrary write primitives that must be carefully leveraged to achieve code execution.

---
#### **18. Question: During a web app test, you find an endpoint that executes commands on the server. However, it filters all alphanumeric characters. How would you craft a payload?**
-  I would use a technique that leverages non-alphanumeric characters in Bash or PowerShell. In Bash, you can use wildcards (`/???/??` expands to `/bin/cat`) and string manipulation with `${_}` or `$@`. In PowerShell, you can invoke commands using call operators `&` and environment variables. The goal is to construct a payload that, when expanded by the shell, becomes a valid command without using letters or numbers directly.

---
#### **19. Question: What is the primary security risk associated with Docker containers running with the `--privileged` flag?**
-  The `--privileged` flag gives the container *all* capabilities and lifts the security restrictions of the cgroups/namespaces isolation. This allows a process inside the container to break out and gain full root access on the host machine. For example, an attacker can remount the host's root filesystem inside the container and modify it directly.

---
#### **20. Question: How does a "Shadow Attack" on PDF documents work?**
-  A Shadow Attack involves hiding malicious content within a PDF by exploiting its object stream structure. An attacker creates a PDF with multiple "versions" of a document object. The PDF reader renders one benign version to the user, but when the PDF is saved or forwarded, the hidden malicious version (containing, for example, a fake form or JavaScript) is revealed and executed. This evades static analysis and user inspection.

---
#### **21. Question: Explain the concept of "Living off the Land" (LotL) and why it's effective.**
-  LotL is an attack methodology where adversaries use legitimate, pre-installed tools and system features (like `powershell.exe`, `wmic.exe`, `bitsadmin.exe`, or `sc.exe`) to perform malicious actions. It's highly effective because it blends in with normal administrative activity, generates minimal new forensic artifacts, and easily bypasses traditional antivirus software that whitelists these trusted system binaries.

---
#### **22. Question: What is the purpose of the "AMSI" (Antimalware Scan Interface) and how can it be bypassed?**
-  AMSI is a Windows interface that allows applications (like PowerShell) to send content to an antivirus/EDR for scanning *before* execution. It aims to catch in-memory and script-based attacks. Bypasses have included:
*   **String Obfuscation:** Breaking up malicious strings.
*   **Forcing an AMSI Context Error:** Patching the `amsi.dll` functions in memory (e.g., setting `amsiInitFailed` to true).
*   **Reflection:** Using .NET reflection to manually load assemblies without triggering the standard scan.

---
#### **23. Question: Describe a method for escalating privileges in a Kubernetes cluster from a compromised pod.**
-  I would first check the pod's service account token (`/var/run/secrets/kubernetes.io/serviceaccount`). If the associated RBAC role has excessive permissions (like `cluster-admin`), I could use the Kubernetes API from within the pod to create new pods with host privileges, list secrets, or even run a privileged container on the host node itself, effectively breaking node isolation.

---
#### **24. Question: What is a "Subdomain Takeover" vulnerability and what is its impact?**
-  This occurs when a subdomain (e.g., `cdn.company.com`) points to a third-party service (e.g., a CloudFront distribution, S3 bucket, or GitHub Pages) that has been decommissioned or deleted. An attacker can claim the resource on the third-party service. The impact is full control over the subdomain, allowing them to host phishing sites, steal cookies via CORS, and even steal SSL/TLS certificates for that domain.

---
#### **25. Question: How does the "PrintNightmare" (CVE-2021-34527) vulnerability allow for remote code execution?**
-  It was a critical flaw in the Windows Print Spooler service. It allowed a low-privileged user to remotely trigger the installation of a malicious printer driver. Due to improper permission checks during this installation process, the attacker could specify a DLL payload that would be executed with SYSTEM privileges, leading to immediate local privilege escalation and full system compromise.

---
#### **26. Question: In a phishing campaign, how can you bypass Multi-Factor Authentication (MFA)?**
-  Common MFA bypass techniques include:
*   **Adversary-in-the-Middle (AiTM) Phishing:** Setting up a proxy server between the victim and the legitimate site, stealing the session cookie *after* the MFA challenge is completed.
*   **MFA Fatigue/Spamming:** Bombarding the user with MFA push notifications until they accidentally approve one.
*   **SIM Swapping:** Taking control of the victim's phone number to intercept SMS-based codes.
*   **Token Theft:** Using malware to steal session cookies or TGTs that have already passed MFA.

---
#### **27. Question: What is the significance of the `Unconstrained Delegation` setting in Active Directory and its associated attack**
-  A computer with Unconstrained Delegation can impersonate any user to *any* service on the network. An attacker can compromise such a computer and then coerce authentication from a Domain Admin (e.g., by triggering a network logon). The computer's Kerberos service will cache the DA's TGT, which the attacker can then extract from memory and use to impersonate the Domain Admin anywhere in the domain.

---
#### **28. Question: Explain the difference between White-box, Black-box, and Grey-box penetration testing.**
- 
*   **Black-box:** The tester has zero prior knowledge of the internal systems, simulating an external attacker.
*   **White-box:** The tester has full knowledge, including source code, architecture diagrams, and credentials, simulating a malicious insider or a thorough internal audit.
*   **Grey-box:** The tester has limited knowledge, such as low-privileged user credentials, simulating an attacker who has gained a foothold inside the network.

---
#### **29. Question: How does a "Deserialization" vulnerability in a .NET application lead to RCE?**
-  Insecure deserialization allows an attacker to control the data being deserialized. In .NET, this can be exploited by crafting a payload that uses "gadget chains" – a series of classes in the .NET framework that, when deserialized in a specific order, execute code. A common example is the `ObjectDataProvider` gadget in the `System.Windows.Data` namespace, which can be used to execute arbitrary commands during the deserialization process.

---
#### **30. Question: What is the primary goal of the "Discovery" phase in the MITRE ATT&CK framework?**
-  The goal is for an adversary to understand the environment they have compromised. This includes gathering information about the system, network, and other connected systems to orient themselves and plan their next moves. Techniques include network scanning, account discovery, and querying the system for security software.

---
#### **31. Question: You find a website with a strict WAF that blocks all requests containing the string "union". How would you perform a SQL Injection?**
-  I would use alternative SQL techniques that don't rely on the `UNION` keyword.
*   **Error-based:** Use `extractvalue()` or `updatexml()` in MySQL to force errors that leak data.
*   **Boolean-based Blind:** Use conditional statements with `SUBSTRING()` and observe true/false page differences.
*   **Out-of-Band (OAST):** Use `LOAD_FILE()` or `DNS` queries to exfiltrate data to an external server I control.
*   **Alternative Syntax:** Use case-sensitive tricks or encoding to bypass the filter (e.g., `UnIoN` if the filter is case-sensitive, or URL encoding).

---
#### **32. Question: What is "Template Injection" (SSTI) and how is it more dangerous than a simple XSS?**
-  Server-Side Template Injection occurs when user input is unsafely embedded into a server-side template (like Jinja2, Twig, or Freemarker). Unlike XSS, which executes JavaScript in the victim's browser, SSTI allows an attacker to execute arbitrary code *on the server* with the application's privileges, leading to full server compromise, file system access, and remote code execution.

---
#### **33. Question: Explain the concept of "VLAN Hopping" and how to prevent it.**
-  VLAN Hopping is an attack where an attacker on one VLAN gains unauthorized access to traffic on another VLAN. The primary method is **switch spoofing**, where the attacker configures their machine to emulate a switch and negotiate a trunk link with the actual switch, thus receiving traffic for all VLANs. Prevention involves explicitly disabling Dynamic Trunking Protocol (DTP) on all switch ports that do not require trunking and using dedicated VLAN IDs for trunk links.

---
#### **34. Question: What is the role of the "Key Distribution Center (KDC)" in Kerberos authentication?**
-  The KDC is the trusted third party in Kerberos, comprised of two services:
1.  **Authentication Service (AS):** Verifies a user's initial login and issues a Ticket-Granting Ticket (TGT).
2.  **Ticket-Granting Service (TGS):** Uses the TGT to issue service tickets for accessing specific network resources (like file shares or applications).
The KDC holds the secret keys for all users and services in the domain.

---
#### **35. Question: How does the "Responder" tool work to capture NTLMv2 hashes on a network?**
-  Responder poisons Link-Local Multicast Name Resolution (LLMNR), NetBIOS Name Service (NBT-NS), and mDNS requests. When a user mistypes a share name (e.g., `\\filseerver`), their computer broadcasts a name resolution query. Responder, listening on the network, answers falsely, claiming to be the requested machine. It then forces the victim's computer to authenticate to it, capturing the NTLMv2 challenge-response hash, which can be cracked or relayed.

---
#### **36. Question: What is the critical difference between Symmetric and Asymmetric cryptography in terms of key management?**
-  **Symmetric** cryptography uses a *single, shared* secret key for both encryption and decryption. The key management challenge is securely distributing this key to all parties. **Asymmetric** cryptography uses a *key pair*: a public key (shared openly) for encryption and a private key (kept secret) for decryption. This eliminates the secret distribution problem but is computationally slower.

---
#### **37. Question: Describe a scenario where you would use the "Scatter/Gather" technique in malware development.**
-  Scatter/Gather is an anti-forensic and evasion technique. "Scatter" involves splitting the malicious payload into small, encrypted/encoded chunks and hiding them across various seemingly benign locations on the filesystem or within the registry. "Gather" is a small, benign-looking loader that reassembles the chunks in memory and executes the final payload. This makes disk-based detection and analysis very difficult.

---
#### **38. Question: What is the purpose of a "C2 (Command and Control) Redirector"?**
-  A C2 redirector is a proxy server placed between compromised implants and the actual C2 server. Its purposes are:
*   **Obfuscation:** Hiding the true IP address of the C2 server.
*   **Resilience:** If the redirector is taken down, the attacker can spin up a new one without losing access to the implants.
*   **Traffic Filtering:** Blocking requests from security researchers or sandboxes based on IP or HTTP headers.
*   **Load Balancing:** Distributing C2 traffic across multiple servers.

---
#### **39. Question: How does the "BloodHound" tool identify attack paths in Active Directory?**
-  BloodHound uses graph theory. It collects data from AD (using the SharpHound ingestor) about objects (users, groups, computers) and their relationships (e.g., "MemberOf", "HasSession", "CanRDP", "GenericAll"). It then builds a directed graph and uses algorithms to find the shortest and most exploitable paths from a compromised starting point (like a low-privileged user) to a high-value target (like Domain Admin).

---
#### **40. Question: What is a "Nonce" and why is it crucial in cryptographic protocols like TLS?**
-  A nonce ("number used once") is a random or pseudo-random number issued in an authentication protocol. In TLS, it's used to prevent replay attacks. By including a unique nonce in each handshake, the protocol ensures that even if an attacker captures an entire encrypted session, they cannot simply replay the same messages to establish a new, valid session.

---
#### **41. Question: Explain the "Diffie-Hellman Key Exchange" and why it's secure even though the exchange is over a public channel.**
-  Diffie-Hellman allows two parties to jointly establish a shared secret over an insecure channel. It uses public-private key pairs derived from modular exponentiation. Each party combines their private key with the other's public key to generate the same shared secret. The security relies on the computational difficulty of the **Discrete Logarithm Problem** – it's infeasible to calculate the private keys from the intercepted public values, even for a powerful computer.

---
#### **42. Question: What is the main risk associated with exposed ".git" directories on a web server?**
-  An exposed `.git` directory can allow an attacker to download the entire source code repository of the website using tools like `git-dumper`. This exposes sensitive information like API keys, database credentials in the code history, application logic, and potentially other vulnerabilities that were fixed in previous commits but are now visible.

---
#### **43. Question: How does the "LLMNR/NBT-NS Poisoning" attack lead to credential compromise?**
-  As described in Q35 with Responder, it exploits misconfigured fallback protocols. When DNS fails, Windows falls back to LLMNR and NBT-NS for name resolution on the local network. An attacker who answers these broadcast requests can trick a victim's machine into authenticating to a rogue service, thus revealing the user's NTLMv2 hash, which can be cracked or relayed.

---
#### **44. Question: What is "Dynamic Analysis" in the context of malware, and what is a common evasion technique against it?**
-  Dynamic analysis involves executing malware in a controlled, isolated environment (a sandbox) to observe its behavior. A common evasion technique is **sandbox detection**. The malware checks for artifacts of a virtual machine (e.g., specific processes, MAC addresses, hardware IDs), a lack of user interaction (mouse movements, recent documents), or a short system uptime. If it detects a sandbox, it halts execution or behaves benignly.

---
#### **45. Question: Describe the "RC4" cryptographic vulnerability and why it's considered weak.**
-  RC4 has several flaws, but the most critical are biases in its keystream. The initial bytes of the output are non-random and correlate with the key, making it vulnerable to statistical attacks. Over time, these biases allow an attacker to recover the plaintext from a large number of encrypted messages. This led to the "Mantin's Attack" and others, resulting in RC4 being deprecated in standards like TLS.

---
#### **46. Question: In a CI/CD pipeline, what is a "Software Composition Analysis" (SCA) tool used for?**
-  An SCA tool (like Snyk, Black Duck) scans an application's dependencies (libraries, frameworks) to identify known vulnerabilities listed in databases like the NVD. It's crucial for DevSecOps to find and remediate vulnerable third-party components *before* the software is deployed, preventing entire classes of supply chain attacks.

---
#### **47. Question: What is the strategic purpose of a "Fully Undetectable (FUD)" payload?**
-  An FUD payload is one that is not detected by any antivirus or EDR solution at the time of delivery. Its purpose is to achieve initial access and establish a foothold without triggering alerts, giving the attacker time to perform reconnaissance and escalate privileges before the defense is aware of the intrusion. It's typically achieved through custom obfuscation, encryption, or code signing with stolen certificates.

---
#### **48. Question: How does the "Schannel" component in Windows relate to the "FREAK" attack?**
-  Schannel is Microsoft's implementation of SSL/TLS. The FREAK ("Factoring RSA Export Keys") attack exploited a 1990s U.S. policy that mandated the use of "export-grade" weak encryption (512-bit RSA) in software sold overseas. Vulnerable servers (including some Windows systems with Schannel) were found to still support these weak cipher suites, allowing an attacker to downgrade a connection, factor the weak RSA key, and decrypt the TLS traffic.

---
#### **49. Question: What is "ARP Spoofing/Poisoning" and what is a modern mitigation for it?**
-  ARP Spoofing is a technique where an attacker sends falsified ARP messages onto a local network. This links the attacker's MAC address with the IP address of a legitimate machine (like the default gateway), causing all traffic for that IP to be sent to the attacker instead. A modern mitigation is to use **Dynamic ARP Inspection (DAI)** on network switches, which validates ARP packets against a trusted database (like the DHCP snooping binding table) and blocks invalid ones.

---
#### **50. Question: Explain the concept of a "Logic Bug" in a bug bounty context, with an example.**
-  A logic bug is a flaw in the application's business workflow or access control, not a typical technical vulnerability like SQLi or XSS.
*   **Example:** An e-commerce site allows you to add items to a cart. At checkout, it calculates the total price on the client-side and sends it to the server. A logic bug would be if the server trusts this client-side total without re-verifying it, allowing an attacker to modify the price to $0.01 and purchase any item.
