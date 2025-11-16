# ULTIMATE SERVER-SIDE TEMPLATE INJECTION (SSTI) ATTACK METHODOLOGY

## PHASE 1: DETECTION TECHNIQUES

### Basic Identification Methods

    - Mathematical operation testing in template syntax
    - Boolean expression evaluation attempts
    - String concatenation experiments
    - Environment variable leakage probes

### Contextual Detection Approaches

    - Direct output context testing
    - Blind injection time-delay analysis
    - Out-of-band interaction observation
    - Error message fingerprinting

## PHASE 2: TEMPLATE ENGINE IDENTIFICATION

### Behavioral Analysis Techniques

    - Native function availability assessment
    - Built-in object accessibility checks
    - Special variable exposure testing
    - Filter/function enumeration

### Engine-Specific Fingerprinting

    - Control structure syntax analysis
    - Comment format recognition
    - Variable referencing pattern matching
    - Inheritance model examination

## PHASE 3: EXPLOITATION METHODOLOGIES

### Object Chain Exploration

    - Class hierarchy traversal techniques
    - Subclass enumeration procedures
    - Method accessibility testing
    - Attribute exposure strategies

### Sandbox Escape Approaches

    - Built-in function discovery methods
    - Import mechanism abuse
    - Reflection capability exploitation
    - Native interface utilization

## PHASE 4: ADVANCED ATTACK VECTORS

### File System Operations

    - File read/write capability testing
    - Directory listing techniques
    - Path traversal combination methods
    - File descriptor manipulation

### System Command Execution

    - Process creation pathways
    - Shell access escalation methods
    - Pipe/redirection abuse
    - Binary execution workflows

### Memory Exploitation

    - Address space probing
    - Pointer manipulation attempts
    - Buffer overflow triggering
    - Memory corruption testing

## PHASE 5: BLIND EXPLOITATION

### Time-Based Detection

    - Delayed execution verification
    - Conditional sleep triggering
    - Computational complexity analysis
    - Sequential operation timing

### Out-of-Band Techniques

    - DNS exfiltration pathways
    - HTTP callback mechanisms
    - Network socket testing
    - External service interaction

## PHASE 6: DEFENSE EVASION

### Obfuscation Methods

    - Encoding variation testing
    - Whitespace manipulation
    - Delimiter substitution
    - Case modification techniques

### WAF Bypass Strategies

    - Token splitting approaches
    - Context switching attempts
    - Boundary confusion methods
    - Parser inconsistency exploitation

## PHASE 7: PERSISTENCE TECHNIQUES

### Backdoor Installation

    - Template modification methods
    - Preprocessor abuse
    - Cache poisoning approaches
    - Persistent storage manipulation

### Environment Manipulation

    - Configuration alteration
    - Variable pollution techniques
    - Path modification strategies
    - Dependency hijacking

## PHASE 8: LATERAL MOVEMENT

### Credential Harvesting

    - Memory scraping techniques
    - Configuration file extraction
    - Environment variable collection
    - Log file analysis methods

### Trust Relationship Abuse

    - Service account exploitation
    - Token reuse approaches
    - Certificate manipulation
    - SSH key harvesting

## MITIGATION STRATEGIES

### Prevention Framework

    - Template sandboxing architecture
    - Input validation methodologies
    - Context-aware escaping implementation
    - Function whitelisting approach

### Detection Mechanisms

    - Anomaly detection signatures
    - Behavioral analysis rules
    - Template rendering monitoring
    - Execution sandboxing

### Response Protocols

    - Template engine hardening
    - Runtime protection activation
    - Forensic evidence collection
    - Compromise assessment workflow
