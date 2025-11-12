# 🔍 SQL INJECTION TESTING CHECKLIST

 ## Comprehensive SQL Injection Testing

### 1 Oracle Database Testing
    - Oracle-Specific Syntax Testing:
      * Single quote escape testing: ' OR '1'='1
      * Comment techniques: --, /* */, //
      * String concatenation: '||'1
      * Oracle functions: CHR(), CONCAT(), NVL()
      * Dual table usage: FROM DUAL
      * UNION SELECT with correct column numbers
      * Error-based payloads using utl_inaddr.get_host_name
      * Time-based delays using DBMS_LOCK.SLEEP()
      * Out-of-band techniques using UTL_HTTP

    - Oracle Privilege Escalation:
      * SYSTEM privileges testing
      * DBA role access attempts
      * Oracle dictionary views: ALL_TABLES, USER_TABLES
      * Package execution: DBMS_CRYPTO, DBMS_SQL
      * File system access: UTL_FILE
      * Network access: UTL_TCP, UTL_HTTP

    - Advanced Oracle Techniques:
      * PL/SQL injection in stored procedures
      * Oracle XML functions: EXTRACTVALUE, UPDATEXML
      * Oracle Java virtual machine access
      * Cross-site scripting via Oracle APEX
      * Oracle Text index manipulation

### 2 MySQL Database Testing
    - MySQL-Specific Syntax Testing:
      * Comment variations: #, -- , /*! */
      * Version-specific comments: /*!50000 */
      * String concatenation: CONCAT(), GROUP_CONCAT()
      * MySQL functions: VERSION(), DATABASE(), USER()
      * UNION SELECT with correct data types
      * Error-based using extractvalue(), updatexml()
      * Time-based delays: SLEEP(), BENCHMARK()
      * Stacked queries testing

    - MySQL System Exploitation:
      * Information schema exploitation
      * File system access: LOAD_FILE(), INTO OUTFILE
      * System variable reading: @@version, @@hostname
      * User-defined functions testing
      * MySQL configuration table access

    - MySQL Advanced Techniques:
      * Boolean-based blind injection
      * Bit-shifting techniques for data extraction
      * MySQL 8.0+ window functions exploitation
      * JSON function injection: JSON_EXTRACT()
      * Regular expression-based extraction

### 3 SQL Server Testing
    - SQL Server-Specific Syntax Testing:
      * Comment techniques: --, /* */
      * String concatenation: +, CONCAT()
      * System functions: @@VERSION, @@SERVERNAME
      * UNION queries with type matching
      * Error-based using convert(), cast()
      * Time-based delays: WAITFOR DELAY
      * Stacked queries with semicolon

    - SQL Server Privilege Testing:
      * xp_cmdshell execution testing
      * Linked server exploitation
      * CLR assembly injection
      * Service Broker activation
      * SQL Agent job creation

    - Advanced SQL Server Techniques:
      * OPENROWSET data exfiltration
      * BULK INSERT file reading
      * XML path injection for data concatenation
      * Dynamic SQL execution via sp_executesql
      * Certificate and encryption manipulation

### 4 PostgreSQL Testing
    - PostgreSQL-Specific Syntax Testing:
      * Comment styles: --, /* */
      * String concatenation: ||, CONCAT()
      * System functions: VERSION(), CURRENT_USER
      * CAST and :: operator exploitation
      * UNION queries with type casting
      * Error-based using cast(), geometric functions
      * Time-based delays: pg_sleep()

    - PostgreSQL System Access:
      * Large object manipulation
      * File system access: COPY, lo_import
      * System table access: pg_catalog
      * PL/pgSQL function injection
      * Foreign data wrapper exploitation

    - Advanced PostgreSQL Techniques:
      * JSON/JSONB function injection
      * Array manipulation for data extraction
      * Regular expression-based extraction
      * Table functions exploitation
      * Transaction block manipulation

### 5 MS Access Database Testing
    - MS Access-Specific Syntax:
      * Comment testing using NULL bytes
      * String concatenation: &, +
      * MS Access functions: IIF(), MID(), LEN()
      * UNION query limitations testing
      * Error-based inference techniques
      * MS Jet engine exploitation

    - MS Access System Testing:
      * System table access: MSysObjects
      * VBA function injection testing
      * Linked table manipulation
      * Password cracking techniques
      * Workgroup security file testing

### 6 NoSQL Injection Testing
    - MongoDB Injection Testing:
      * Operator injection: $ne, $gt, $where
      * JavaScript injection in map-reduce
      * NoSQL boolean-based injection
      * Schema pollution attacks
      * Aggregation framework injection

    - CouchDB Injection Testing:
      * View injection in _design documents
      * JavaScript execution in views
      * Show/list function manipulation
      * Update handler injection

    - Cassandra Injection Testing:
      * CQL injection techniques
      * User-defined function exploitation
      * Collection type manipulation
      * Batch statement injection

    - Redis Injection Testing:
      * Command injection via EVAL
      * Lua script injection
      * Protocol manipulation
      * Module loading exploitation

### 7 ORM Injection Testing
    - Hibernate (Java) Testing:
      * HQL injection techniques
      * Native SQL bypass testing
      * Criteria API manipulation
      * Named parameter exploitation
      * Second-level cache poisoning

    - Entity Framework (.NET) Testing:
      * LINQ injection testing
      * Raw SQL method exploitation
      * Database function injection
      * Connection string parameter pollution

    - Django ORM (Python) Testing:
      * QuerySet injection techniques
      * Raw SQL execution testing
      * Extra() method exploitation
      * Annotation/aggregation injection

    - ActiveRecord (Ruby) Testing:
      * Method chaining exploitation
      * Raw SQL fragment injection
      * Scope manipulation
      * Association injection

    - Sequelize (Node.js) Testing:
      * Literal injection testing
      * Raw query exploitation
      * Include/association manipulation
      * Transaction block injection

### 8 Client-Side SQL Injection Testing
    - WebSQL Database Testing:
      * Client-side SQL execution testing
      * IndexedDB SQL injection
      * Browser extension database access
      * Local storage SQL manipulation

    - Mobile Application Testing:
      * SQLite injection in mobile apps
      * Content provider injection (Android)
      * Core Data injection (iOS)
      * Realm database manipulation

    - Desktop Application Testing:
      * Local database file manipulation
      * Embedded database engine testing
      * Configuration file SQL injection
      * Memory database exploitation

#### Advanced Testing Techniques:
    - Polyglot Payload Testing:
      * Multi-database compatible payloads
      * WAF bypass using encoding variations
      * Context-aware payload switching
      * Database fingerprinting through error messages

    - Blind Injection Optimization:
      * Binary search for efficient extraction
      * Bit-level data extraction
      * Statistical timing analysis
      * Response differential analysis

    - Automated Tool Integration:
      * SQLMap tamper script customization
      * Burp Suite SQLi extension testing
      * Custom fuzzing payload development
      * Machine learning-based detection evasion

#### Defense Bypass Testing:
    - WAF Evasion Techniques:
      * Encoding variations (URL, HTML, Unicode)
      * Case randomization and mixing
      * Whitespace and comment obfuscation
      * Parameter fragmentation and splitting
      * HTTP method switching and pollution

    - Input Filter Bypass:
      * Keyword filtering evasion
      * Signature detection avoidance
      * Type conversion attacks
      * Boundary condition exploitation
      * Parser differential attacks

#### Testing Tools and Methodologies:
    Manual Testing Tools:
    - Burp Suite Scanner and Repeater
    - OWASP ZAP SQL Injection scanner
    - Custom SQLi cheat sheets per database
    - Browser developer tools for client-side testing

    Automated Testing Tools:
    - SQLMap with database-specific techniques
    - NoSQLMap for NoSQL databases
    - jSQL Injection for Java applications
    - BBQSQL for blind SQL injection

    Test Environment Requirements:
    - Isolated testing databases
    - Database-specific error logging
    - Network traffic monitoring
    - Query execution time measurement