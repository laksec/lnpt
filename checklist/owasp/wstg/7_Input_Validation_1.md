## 🔍 INPUT VALIDATION TESTING MASTER LIST

### 7.1 TESTING FOR REFLECTED XSS
    - URL parameter injection
    - Form field reflection
    - Header value reflection
    - Cookie value reflection
    - JSON/XML response injection
    - Different encoding techniques
    - WAF bypass methods
    - DOM-based reflection
    - AngularJS sandbox escape
    - SVG vector testing

### 7.2 TESTING FOR STORED XSS
    - Comment fields
    - User profiles
    - File uploads
    - Chat systems
    - Support tickets
    - CMS content
    - Database entries
    - Log entries
    - API responses
    - Email templates

### 7.3 TESTING FOR HTTP VERB TAMPERING
    - GET to POST switching
    - HEAD method abuse
    - PUT/DELETE testing
    - TRACE method risks
    - OPTIONS disclosure
    - PATCH method manipulation
    - Custom verb injection
    - Proxy verb tunneling
    - Authentication bypass
    - CSRF protection bypass

### 7.4 TESTING FOR HTTP PARAMETER POLLUTION
    - Duplicate parameters
    - Parameter overriding
    - Different separator testing
    - Array parameter injection
    - JSON parameter pollution
    - WAF evasion techniques
    - Server-specific parsing
    - Parameter priority testing
    - Client-side HPP
    - API parameter pollution

### 7.5 TESTING FOR SQL INJECTION
#### 7.5.1 ORACLE
    - DBMS_PIPE exploitation
    - UTL_HTTP abuse
    - ORA_HASH attacks
    - CTXSYS exploits
    - Time-based techniques
    - Out-of-band exfiltration
    - PL/SQL injection
    - Object privilege escalation
    - SYS_CONTEXT leaks
    - XML DB abuse

#### 7.5.2 MYSQL
    - SLEEP() timing attacks
    - INTO OUTFILE abuse
    - LOAD_FILE exploitation
    - Benchmark attacks
    - Information_schema
    - UNION-based techniques
    - Boolean-based blind
    - Nested query injection
    - Prepared statement bypass
    - Default function abuse

#### 7.5.3 SQL SERVER
    - xp_cmdshell abuse
    - OPENROWSET attacks
    - WAITFOR DELAY timing
    - Linked server abuse
    - CLR assembly injection
    - Error-based techniques
    - Agent job manipulation
    - Column truncation
    - Service broker abuse
    - Always Encrypted bypass

#### 7.5.4 POSTGRESQL
    - COPY TO exploitation
    - Large object abuse
    - PL/pgSQL injection
    - dblink attacks
    - File system access
    - pg_read_file abuse
    - CVE-specific exploits
    - FDW manipulation
    - JSON/JSONB injection
    - Array unnesting

#### 7.5.5 MS ACCESS
    - IIF blind injection
    - MSysObjects access
    - Cross-database queries
    - VBA function abuse
    - Data shaping attacks
    - Parameter pollution
    - Jet engine exploits
    - ODBC connection abuse
    - Password cracking
    - Linked table injection

#### 7.5.6 NOSQL INJECTION
    - MongoDB operator abuse
    - $where clause injection
    - MapReduce attacks
    - JSON injection
    - Array-based attacks
    - Schema pollution
    - CouchDB view abuse
    - GraphQL injection
    - Cassandra CQL injection
    - Redis command injection

#### 7.5.7 ORM INJECTION
    - HQL injection
    - JPQL manipulation
    - ActiveRecord abuse
    - Sequelize attacks
    - Doctrine flaws
    - Entity Framework
    - Django ORM bypass
    - TypeORM injection
    - Waterline abuse
    - Prisma manipulation

#### 7.5.8 CLIENT-SIDE SQL
    - WebSQL injection
    - IndexedDB abuse
    - localStorage SQL
    - SQL.js attacks
    - Browser extension DBs
    - PWA database risks
    - Cache poisoning
    - Service Worker DB
    - FileSystem API SQL
    - WASM SQL injection

### 7.6 TESTING FOR LDAP INJECTION
    - Filter bypass techniques
    - AND/OR manipulation
    - Wildcard attacks
    - Blind LDAP injection
    - Attribute disclosure
    - Access control bypass
    - ObjectSID extraction
    - Password policy discovery
    - Time-based enumeration
    - AD-specific attacks

### 7.7 TESTING FOR XML INJECTION
    - XXE attacks
    - XInclude exploitation
    - XPath injection
    - XSLT injection
    - XML bomb attacks
    - Schema poisoning
    - External DTD abuse
    - Parameter entity
    - DoS vectors
    - SOAP injection

### 7.8 TESTING FOR SSI INJECTION
    - Exec cmd injection
    - File inclusion
    - Echo directive
    - Config manipulation
    - Time formatting
    - Variable access
    - Conditional SSI
    - Apache-specific
    - Nginx SSI risks
    - WAF bypass

### 7.9 TESTING FOR XPATH INJECTION
    - Booleanization
    - Error-based
    - Union techniques
    - Blind enumeration
    - Namespace injection
    - Axis manipulation
    - Function abuse
    - Predicate injection
    - Context node
    - Document traversal

### 7.10 TESTING FOR IMAP/SMTP INJECTION
    - Command injection
    - Header manipulation
    - CRLF injection
    - Backend system access
    - Mail server DoS
    - Filter bypass
    - Authentication abuse
    - Mailbox enumeration
    - Attachment risks
    - MIME type abuse
