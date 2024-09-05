# Web Application Penetration Testing Checklist

## 1. Testing Approach
- **Determine Testing Approach**: Select between black box, gray box, or white box testing based on the level of access and information available.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [Nessus](#), [Veracode](#), [SonarQube](#)

## 2. Passive Reconnaissance
- **Attack Surface Discovery**: Identify and catalog all potential attack surfaces.
  - ***Tools:*** [Shodan](#), [Censys](#), [Google Dorking](#), [Recon-ng](#), [BuiltWith](#)
- **Exposed Secrets**: Look for exposed credentials, API keys, and other sensitive data.
  - ***Tools:*** [GitHub Search](#), [GitLab Search](#), [TruffleHog](#), [LeakCanary](#), [DataLeaker](#)

## 3. Active Reconnaissance
- **Port and Service Scanning**: Identify open ports and running services to uncover potential vulnerabilities.
  - ***Tools:*** [Nmap](#), [Masscan](#), [ZMap](#), [Angry IP Scanner](#), [Netcat](#)
- **Web Application Interaction**: Engage with the application to understand its functionality and uncover potential issues.
  - ***Tools:*** [Browser DevTools](#), [Postman](#), [Burp Suite](#), [OWASP ZAP](#), [Insomnia](#)
- **Inspect with DevTools**: Use browser developer tools to analyze network traffic, cookies, and JavaScript.
  - ***Tools:*** [Chrome DevTools](#), [Firefox Developer Tools](#), [Edge DevTools](#), [Fiddler](#), [Burp Suite](#)
- **Directory and File Discovery**: Identify hidden directories and files that may reveal additional attack vectors.
  - ***Tools:*** [DirBuster](#), [Dirsearch](#), [Gobuster](#), [Wfuzz](#), [Nikto](#)
- **Discover API Endpoints**: Locate and test API endpoints for potential vulnerabilities.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [API Discovery Tools](#), [API Fortress](#)

## 4. Endpoint Analysis
- **Review Web Application Documentation**: Examine any available documentation for insights into the application’s functionality and potential weaknesses.
  - ***Tools:*** [Swagger UI](#), [Redoc](#), [Postman](#), [OpenAPI Specification](#), [Custom Documentation Review](#)
- **Reverse Engineering**: Analyze the application’s code and behavior to identify vulnerabilities.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [Fiddler](#), [Charles Proxy](#)
- **Use the Application as Intended**: Test the application’s functionality as a normal user to identify potential security issues.
  - ***Tools:*** [Postman](#), [Insomnia](#), [cURL](#), [HTTPie](#), [SoapUI](#)
- **Analyze Responses**: Review responses for information leaks, excessive data exposures, and potential business logic flaws.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [Fiddler](#), [Wireshark](#)

## 5. Authentication Testing
- **Basic Authentication Testing**: Test the strength and security of basic authentication mechanisms.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [Nessus](#), [Hydra](#)
- **Authentication Mechanism Testing**: Evaluate various authentication mechanisms (e.g., OAuth, JWT) for vulnerabilities.
  - ***Tools:*** [Burp Suite](#), [Postman](#), [JWT.io Debugger](#), [Auth0](#), [OAuth2 Proxy](#)

## 6. Fuzzing
- **Fuzz Input Fields**: Apply fuzzing techniques to all input fields to identify unexpected behaviors and vulnerabilities.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [AFL](#), [Peach Fuzzer](#), [Boofuzz](#)

## 7. Authorization Testing
- **Resource Identification**: Identify how resources are accessed and identified within the application.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [Access Control Tester](#), [API Testing Tools](#)
- **Test for Broken Access Control**: Verify that access control mechanisms are implemented correctly and are resistant to exploitation.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [API Security Testing Tools](#), [Manual Testing](#)

## 8. Mass Assignment Testing
- **Identify Standard Parameters**: Discover parameters used in requests that could be susceptible to mass assignment attacks.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [API Testing Tools](#), [Manual Testing](#)
- **Test for Mass Assignment Vulnerabilities**: Check if the application allows unauthorized modifications of parameters.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [API Security Testing Tools](#), [Manual Testing](#)

## 9. Injection Testing
- **Identify Injection Points**: Locate areas where user input could be processed and potentially vulnerable to injection attacks.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [SQLmap](#), [Commix](#), [Fuzzing Tools](#)
- **Test for Cross-Site Scripting (XSS)**: Assess the application for XSS vulnerabilities.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [XSSer](#), [XSStrike](#), [XSS Hunter](#)
- **Test for SQL Injection**: Evaluate input fields for SQL injection vulnerabilities.
  - ***Tools:*** [SQLmap](#), [Burp Suite](#), [OWASP ZAP](#), [SQLNinja](#), [SQLite Database Browser](#)
- **Test for Command Injection**: Identify vulnerabilities that allow for arbitrary command execution on the server.
  - ***Tools:*** [Commix](#), [Burp Suite](#), [OWASP ZAP](#), [Metasploit](#), [Netcat](#)

## 10. Rate Limit Testing
- **Check for Rate Limits**: Verify if the application enforces rate limits to mitigate abuse.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [Rate Limit Tester](#), [Wfuzz](#)
- **Test Rate Limit Bypass**: Explore techniques to bypass or evade rate limits.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [Rate Limit Bypass Tools](#), [Manual Testing](#)

## 11. Evasive Techniques
- **String Terminators**: Add terminators to payloads to test evasion.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [Fuzzing Tools](#), [Custom Scripts](#), [Manual Testing](#)
- **Case Switching**: Modify payload cases to bypass security filters.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [Fuzzing Tools](#), [Custom Scripts](#), [Manual Testing](#)
- **Payload Encoding**: Use encoding techniques to evade detection.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [Fuzzing Tools](#), [Custom Scripts](#), [Manual Testing](#)
- **Combine Evasion Techniques**: Apply a mix of evasion techniques for improved results.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [Fuzzing Tools](#), [Custom Scripts](#), [Manual Testing](#)
- **Apply Evasion to All Tests**: Ensure evasive techniques are used across all testing phases.
  - ***Tools:*** [Burp Suite](#), [OWASP ZAP](#), [Fuzzing Tools](#), [Custom Scripts](#), [Manual Testing](#)

