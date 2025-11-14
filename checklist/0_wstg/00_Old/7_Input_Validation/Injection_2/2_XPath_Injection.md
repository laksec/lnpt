# 🔍 XPATH INJECTION TESTING CHECKLIST

 ## Comprehensive XPath Injection Testing

### 1 Basic XPath Injection Vectors
    - Simple Authentication Bypass:
      * Always true conditions: ' or '1'='1
      * Comment-based injection: ' or 1=1 or 'a'='a
      * Parenthesis manipulation: ') or ('1'='1
      * Boolean operator injection: ' or true() or '
      * String concatenation bypass

    - Common Injection Patterns:
      * Username field: ' or 1=1 or 'a'='a
      * Password field: ' or string-length(name())=4 or 'a'='b
      * Search functionality: '] | //* | //*['
      * Numeric field injection: 1 or 1=1
      * Date field manipulation

    - Basic Operator Testing:
      * Logical operators: and, or, not()
      * Comparison operators: =, !=, <, >, <=, >=
      * Arithmetic operators: +, -, *, div, mod
      * Node operators: | (union), /, //
      * Sequence operators: , (comma)

### 2 Advanced XPath Injection Techniques
    - Complex Conditional Injection:
      * Nested condition exploitation
      * Multiple predicate injection
      * Axis manipulation in conditions
      * Function-based condition bypass
      * Data type conversion attacks

    - XPath 2.0/3.0 Features:
      * if-then-else expressions
      * for-return expressions (FLWOR)
      * Quantified expressions: some, every
      * Type operators: instance of, cast as
      * Advanced sequence expressions

    - Context Manipulation:
      * Position() function exploitation
      * Last() function manipulation
      * Context size alteration
      * Current node modification
      * Document order manipulation

### 3 Blind XPath Injection Testing
    - Boolean-Based Blind Injection:
      * True/false condition testing
      * String length analysis: string-length(//user[1]/password)=8
      * Character extraction: substring(//user[1]/password,1,1)='a'
      * Node existence checking
      * Attribute value inference

    - Time-Based Blind Injection:
      * XPath 2.0: system-property('xsl:version')='2.0'
      * Extension function timing attacks
      * Recursive function calls for delays
      * Large dataset processing delays
      * External resource timing

    - Error-Based Blind Injection:
      * Type conversion errors
      * Function parameter errors
      * Division by zero attacks
      * Invalid node set operations
      * Namespace resolution errors

### 4 XPath Function Exploitation
    - String Function Testing:
      * substring(), string-length(), contains()
      * starts-with(), ends-with(), matches()
      * translate(), replace(), normalize-space()
      * concat(), string-join()
      * upper-case(), lower-case()

    - Numeric Function Testing:
      * number(), sum(), avg(), min(), max()
      * floor(), ceiling(), round()
      * abs(), random-number()
      * Arithmetic operation injection

    - Node Set Functions:
      * count(), position(), last()
      * local-name(), name(), namespace-uri()
      * root(), id(), element-with-id()
      * doc(), document() for external resources

    - Boolean and Sequence Functions:
      * not(), boolean(), exists(), empty()
      * distinct-values(), index-of()
      * insert-before(), remove(), reverse()
      * subsequence(), unordered()

### 5 Axis and Path Manipulation
    - Axis Specifier Testing:
      * child::, parent::, ancestor::
      * descendant::, following::, preceding::
      * attribute::, self::, namespace::
      * following-sibling::, preceding-sibling::
      * descendant-or-self::, ancestor-or-self::

    - Path Expression Injection:
      * Absolute path injection: /root/users/user
      * Relative path manipulation:  /sensitiveData
      * Wildcard path exploitation: //*
      * Conditional path injection: //user[position()=1]
      * Multiple path combination

    - Node Test Manipulation:
      * Element name testing
      * Attribute node selection: @password
      * Text node access: text()
      * Comment and processing instruction nodes
      * Node type testing

### 6 Predicate Injection Testing
    - Position-Based Predicates:
      * Position() function manipulation
      * Last() function exploitation
      * Range-based predicate injection
      * First/last node access
      * Reverse position manipulation

    - Value-Based Predicates:
      * Attribute value conditions
      * Element text content conditions
      * Multiple attribute conditions
      * Nested predicate injection
      * Complex condition stacking

    - Function-Based Predicates:
      * String function predicates
      * Numeric function conditions
      * Boolean function predicates
      * Custom function exploitation
      * External function injection

### 7 XML Document Structure Exploitation
    - Document Navigation:
      * Root element access
      * Sibling node manipulation
      * Ancestor/descendant traversal
      * Following/preceding node access
      * Cross-branch navigation

    - Namespace Exploitation:
      * Namespace URI manipulation
      * Prefix reassignment attacks
      * Default namespace bypass
      * Multiple namespace confusion
      * Namespace wildcard testing

    - Schema Awareness Testing:
      * Type-based node selection
      * Schema element/type manipulation
      * Validation bypass through XPath
      * Type conversion exploitation
      * Substitution group manipulation

### 8 Application-Specific Testing
    - Authentication Systems:
      * Login form XPath injection
      * Password reset functionality
      * Session management XPath
      * Role-based access control bypass
      * User enumeration attacks

    - Search and Filter Systems:
      * Product search XPath injection
      * Data filtering manipulation
      * Sort order XPath control
      * Pagination XPath exploitation
      * Category filtering bypass

    - Data Processing Applications:
      * XML document editors
      * Configuration file processors
      * Report generation systems
      * Data transformation pipelines
      * Content management systems

### 9 XQuery Injection Testing
    - FLWOR Expression Injection:
      * For clause manipulation
      * Let variable injection
      * Where condition exploitation
      * Order by clause tampering
      * Return expression injection

    - XQuery Function Injection:
      * Built-in function exploitation
      * User-defined function manipulation
      * External function invocation
      * Module import exploitation
      * Function overloading attacks

    - Advanced XQuery Features:
      * Type switch expressions
      * Validate expressions
      * Update expressions (XQuery Update)
      * Full text search manipulation
      * Scripting extension exploitation

### 10 Defense Bypass Testing
    - Input Filter Evasion:
      * Encoding variations: HTML, URL, Unicode
      * Case manipulation and mixing
      * Whitespace obfuscation techniques
      * Comment injection within XPath
      * Multiple encoding layers

    - WAF Bypass Techniques:
      * Alternative XPath syntax
      * Function name variations
      * Operator synonym usage
      * Namespace prefix manipulation
      * String literal variations

    - Parser Differential Exploitation:
      * Browser vs server XPath parsing
      * XPath 1.0 vs 2.0 vs 3.0 differences
      * Library-specific parsing behaviors
      * Configuration setting exploitation
      * Feature flag manipulation

### 11 Specialized Context Testing
    - Browser XPath Evaluation:
      * document.evaluate() injection
      * XPathResult manipulation
      * DOM XPath context exploitation
      * Browser extension XPath
      * Client-side XSLT transformation

    - Database XPath Integration:
      * SQL Server XML data type XPath
      * Oracle XMLDB XPath injection
      * PostgreSQL XML function XPath
      * MySQL XPath function exploitation
      * NoSQL XML document XPath

    - Programming Language Context:
      * Java JAXP XPath injection
      * NET XPathDocument/XPathNavigator
      * Python lxml XPath injection
      * PHP DOMXPath exploitation
      * JavaScript XPath evaluation

#### Testing Tools and Methodologies:
    Manual Testing Tools:
    - Burp Suite with XPath injection scanner
    - OWASP ZAP active scan rules
    - Browser developer tools for client-side XPath
    - Custom XPath payload generators
    - XML editors with XPath evaluation

    Automated Testing Tools:
    - XPath injection fuzzing scripts
    - Custom Python scripts with lxml
    - SQLMap with XPath detection
    - Web application scanner XPath plugins
    - Automated payload generation tools

    Specialized Testing Tools:
    - XPath Visualizer for expression testing
    - Oxygen XML Editor XPath builder
    - XMLSpy XPath evaluation tools
    - Online XPath testers for quick validation

    Test Case Examples:
    - Authentication: ' or 1=1 or 'a'='a
    - Data Extraction: //user[position()=1]/password
    - Structure Discovery: //*[position()=1]/name()
    - Blind Injection: string-length(//user[1]/password)=8
    - Union Attack: //user | //admin

    Testing Methodology:
    1. Identify XPath processing endpoints
    2. Test basic injection vectors
    3. Attempt authentication bypass
    4. Test data extraction capabilities
    5. Verify blind injection techniques
    6. Test advanced XPath features
    7. Attempt defense bypass methods
    8. Document exploitation paths and data access