# API Testing Checklist

## 1. Testing Approach
- **Determine Testing Approach**: Choose between black box, gray box, or white box testing based on the level of access and information available.

## 2. Passive Reconnaissance
- **Attack Surface Discovery**: Identify all potential entry points and attack vectors.
  - ***Tools:*** &emsp; [Shodan](#), [Censys](#), [Google Dorking](#), [Recon-ng](#), [BuiltWith](#)
- **Exposed Secrets**: Check for sensitive information such as API keys, tokens, and credentials that might be inadvertently exposed.
  - ***Tools:*** &emsp; [GitHub Search](#), [GitLab Search](#), [TruffleHog](#), [LeakCanary](#), [DataLeaker](#)

## 3. Active Reconnaissance
- **Port and Service Scanning**: Use tools to scan for open ports and services that may reveal additional endpoints or vulnerabilities.
  - ***Tools:*** &emsp; [Nmap](#), [Masscan](#), [ZMap](#), [Angry IP Scanner](#), [Netcat](#)
- **Application Usage**: Interact with the application as an end-user to understand its behavior and API usage patterns.
  - ***Tools:*** &emsp; [Browser DevTools](#), [Postman](#), [Burp Suite](#), [OWASP ZAP](#), [Insomnia](#)
- **Inspect with DevTools**: Utilize browser developer tools to analyze network requests, responses, and JavaScript files.
  - ***Tools:*** &emsp; [Chrome DevTools](#), [Firefox Developer Tools](#), [Edge DevTools](#), [Fiddler](#), [Burp Suite](#)
- **API Directory Discovery**: Search for directories related to the API, such as `/api/`, `/v1/`, or `/endpoints/`.
  - ***Tools:*** &emsp; [DirBuster](#), [Dirsearch](#), [Gobuster](#), [Wfuzz](#), [Burp Suite](#)
- **Endpoint Discovery**: Identify all available API endpoints using tools.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [API Discovery Tools](#), [API Fortress](#)

## 4. Endpoint Analysis
- **API Documentation Review**: Locate and examine official API documentation or any available resources that describe the API’s functionality.
  - ***Tools:*** &emsp; [Swagger UI](#), [Redoc](#), [Postman](#), [API Blueprint](#), [OpenAPI Specification](#)
- **Reverse Engineering**: Analyze the API's underlying structure to understand its implementation.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [Fiddler](#), [Charles Proxy](#)
- **Use the API as Intended**: Interact with the API based on its documented functionality to identify potential issues.
  - ***Tools:*** &emsp; [Postman](#), [Insomnia](#), [cURL](#), [HTTPie](#), [SoapUI](#)
- **Analyze Responses**: Look for information disclosures, excessive data exposures, and business logic flaws.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [Fiddler](#), [Wireshark](#)

## 5. Authentication Testing
- **Basic Authentication Testing**: Test for flaws in basic authentication mechanisms.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [Nessus](#), [Hydra](#)
- **API Token Manipulation**: Attempt to exploit and manipulate API tokens.
  - ***Tools:*** &emsp; [Burp Suite](#), [Postman](#), [JWT.io Debugger](#), [Auth0](#), [Burp Suite Extensions](#)

## 6. Fuzzing
- **Fuzz All Inputs**: Use fuzzing techniques to test API inputs for unexpected behavior or vulnerabilities.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [AFL](#), [Peach Fuzzer](#), [Boofuzz](#)

## 7. Authorization Testing
- **Resource Identification Methods**: Discover how resources are identified and accessed.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [API Testing Tools](#), [Access Control Tester](#)
- **Broken Object Level Authorization (BOLA)**: Test for flaws in object-level access control.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [API Security Testing Tools](#), [Manual Testing](#)
- **Broken Function Level Authorization (BFLA)**: Test for flaws in function-level access control.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [API Security Testing Tools](#), [Manual Testing](#)

## 8. Mass Assignment Testing
- **Discover Standard Parameters**: Identify parameters used in requests that might be susceptible to mass assignment attacks.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [API Testing Tools](#), [Manual Testing](#)
- **Test for Mass Assignment**: Check if the API allows users to modify parameters that should be restricted.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [API Security Testing Tools](#), [Manual Testing](#)

## 9. Injection Testing
- **User Input Testing**: Discover and test requests that accept user input for injection vulnerabilities.
  - ***Tools:*** &emsp; [SQLmap](#), [Burp Suite](#), [OWASP ZAP](#), [Commix](#), [Fuzzing Tools](#)
- **Test for XSS/XAS**: Test for Cross-Site Scripting (XSS) and XML Injection vulnerabilities.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [XSSer](#), [XSStrike](#), [XML Injector](#)
- **Database-Specific Attacks**: Perform attacks tailored to specific database systems.
  - ***Tools:*** &emsp; [SQLmap](#), [MySQLi](#), [NoSQLMap](#), [PostgreSQL Tools](#), [SQLNinja](#)
- **Operating System Injection**: Test for operating system command injection vulnerabilities.
  - ***Tools:*** &emsp; [Commix](#), [Burp Suite](#), [OWASP ZAP](#), [Metasploit](#), [Netcat](#)

## 10. Rate Limit Testing
- **Check for Rate Limits**: Test if the API enforces rate limits to prevent abuse.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [Rate Limit Tester](#), [Wfuzz](#)
- **Test Rate Limit Bypass Methods**: Explore ways to bypass or evade rate limits.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [Postman](#), [Rate Limit Bypass Tools](#), [Manual Testing](#)

## 11. Evasive Techniques
- **String Terminators**: Add string terminators to payloads to test for evasion.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [Fuzzing Tools](#), [Custom Scripts](#), [Manual Testing](#)
- **Case Switching**: Modify the case of payloads to bypass filters.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [Fuzzing Tools](#), [Custom Scripts](#), [Manual Testing](#)
- **Payload Encoding**: Encode payloads to avoid detection.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [Fuzzing Tools](#), [Custom Scripts](#), [Manual Testing](#)
- **Combine Evasion Techniques**: Use a combination of evasive techniques to increase effectiveness.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [Fuzzing Tools](#), [Custom Scripts](#), [Manual Testing](#)
- **Apply Evasion to All Tests**: Ensure that evasive techniques are applied to all previous tests.
  - ***Tools:*** &emsp; [Burp Suite](#), [OWASP ZAP](#), [Fuzzing Tools](#), [Custom Scripts](#), [Manual Testing](#)

