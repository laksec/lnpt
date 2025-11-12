# 🔍 WEB APPLICATION FRAMEWORK FINGERPRINTING CHECKLIST

 ## Comprehensive Web Application Framework Fingerprinting

### 1 HTTP Header Analysis
    - Framework-Specific Headers:
      * X-Powered-By: PHP, ASP.NET, Express
      * X-Generator: Drupal, WordPress, CMS indicators
      * X-Runtime: Ruby on Rails, Django
      * X-Drupal-Cache: Drupal framework
      * X-Varnish: Varnish cache with specific frameworks

    - Custom Framework Headers:
      * X-Symfony-Version: Symfony framework
      * X-Laravel-Version: Laravel framework
      * X-ASP.NETMVC-Version: ASP.NET MVC
      * X-CakePHP: CakePHP framework

    - Cache and Proxy Headers:
      * X-Cache: Framework-specific caching
      * X-Cache-Enabled: Framework cache status
      * X-Served-By: Load balancer with framework hints

### 2 Cookie Analysis
    - Session Cookie Patterns:
      * PHPSESSID: PHP applications
      * JSESSIONID: Java applications
      * ASP.NET_SessionId: ASP.NET applications
      * laravel_session: Laravel framework
      * django_session: Django framework

    - Framework-Specific Cookies:
      * csrftoken: Django CSRF protection
      * XSRF-TOKEN: Laravel, Angular
      * symfony: Symfony framework
      * cfduid: CloudFlare with framework hints

    - Security Cookie Patterns:
      * SameSite attributes framework-specific
      * HttpOnly flag implementation
      * Secure flag patterns
      * Custom security tokens

### 3 URL Structure and Routing
    - RESTful Route Patterns:
      * /api/v1/users: REST API conventions
      * /users/123/show: Framework routing
      * Query parameter patterns: ?_method=PUT

    - Framework-Specific URLs:
      * /wp-admin: WordPress
      * /administrator: Joomla
      * /admin: Generic admin patterns
      * /graphql: GraphQL endpoints

    - File Extension Patterns:
      * php: PHP frameworks
      * aspx: ASP.NET
      * jsp: Java frameworks
      * do: Struts framework

### 4 HTML Source Code Analysis
    - Meta Tags and Generator:
      * <meta name="generator" content="WordPress X.X">
      * <meta name="framework" content="Laravel">
      * CMS-specific meta tags
      * Framework version in comments

    - CSS and JavaScript Patterns:
      * Framework-specific class names
      * JavaScript library inclusion
      * Asset path patterns (/static/, /assets/)
      * Cache busting patterns

    - Form Element Patterns:
      * CSRF token field names
      * Form method spoofing fields
      * Validation attribute patterns
      * Framework-specific form helpers

### 5 Error Message Analysis
    - Framework-Specific Error Pages:
      * Django debug page
      * Laravel Whoops page
      * Ruby on Rails error page
      * ASP.NET Yellow Screen of Death

    - Stack Trace Information:
      * File paths revealing framework structure
      * Method names in stack traces
      * Database driver information
      * Template engine errors

    - Custom Error Messages:
      * Framework-specific error formats
      * Validation error patterns
      * Authentication error messages
      * Database error handling

### 6 Default File and Directory Patterns
    - Framework Installation Files:
      * wp-config.php: WordPress
      * settings.php: Drupal
      * web.config: ASP.NET
      * package.json: Node.js applications

    - Asset Directory Structures:
      * /wp-content/: WordPress
      * /sites/default/: Drupal
      * /public/assets/: Ruby on Rails
      * /static/: Django, Flask

    - Configuration File Patterns:
      * env files: Laravel, Node.js
      * config/database.yml: Ruby on Rails
      * appsettings.json: ASP.NET Core
      * pom.xml: Java Maven projects

### 7 JavaScript Framework Detection
    - Frontend Framework Patterns:
      * React: __REACT_DEVTOOLS_GLOBAL_HOOK__
      * Angular: ng- attributes, angular.js
      * Vue.js: __VUE_DEVTOOLS_GLOBAL_HOOK__
      * jQuery: jQuery, $ patterns

    - SPA Framework Indicators:
      * Client-side routing patterns
      * API consumption patterns
      * State management libraries
      * Build tool indicators

### 8 API Response Patterns
    - JSON Structure Analysis:
      * Pagination format (page, limit, offset)
      * Error response formats
      * Data wrapping patterns
      * Metadata structure

    - Authentication Patterns:
      * JWT token usage
      * OAuth implementation
      * API key patterns
      * Rate limiting headers

### 9 Database and ORM Indicators
    - Query Parameter Patterns:
      * ActiveRecord patterns (Ruby on Rails)
      * Eloquent patterns (Laravel)
      * Django ORM patterns
      * Entity Framework (ASP.NET)

    - Database Error Messages:
      * PDO exceptions (PHP)
      * ActiveRecord errors (Ruby)
      * Django database errors
      * Entity Framework exceptions

### 10 Security Feature Analysis
    - CSRF Protection Implementation:
      * Token field names (_token, csrf_token)
      * Header-based CSRF protection
      * Double submit cookie patterns

    - Content Security Policy:
      * Framework-specific CSP headers
      * Nonce patterns in scripts
      * Hash patterns in CSP

    - Security Headers:
      * X-Frame-Options implementation
      * X-Content-Type-Options
      * HSTS implementation patterns
      * CORS configuration

### 11 Caching Implementation Patterns
    - Page Caching Headers:
      * Framework-specific cache control
      * ETag generation patterns
      * Last-Modified headers
      * Cache vary headers

    - Fragment Caching:
      * Edge Side Includes
      * Varnish cache patterns
      * Redis cache indicators
      * Memcached usage

### 12 File Upload and Handling
    - Upload Directory Patterns:
      * /uploads/ structure
      * File naming conventions
      * Thumbnail generation patterns
      * File permission patterns

    - MIME Type Handling:
      * File type validation
      * File size limits
      * Virus scanning integration
      * Storage backend indicators

### 13 Authentication System Patterns
    - Login Form Analysis:
      * Field names (username, email, login)
      * Password complexity indicators
      * Remember me functionality
      * CAPTCHA implementation

    - Social Authentication:
      * OAuth provider patterns
      * Social login button classes
      * OpenID Connect implementation
      * SAML integration

### 14 Template Engine Detection
    - Server-Side Template Patterns:
      * {{ }}: Handlebars, Mustache, Django
      * {% %}: Django, Twig, Liquid
      * ${ }: Thymeleaf, Freemarker
      * <?php : PHP templates

    - Template File Extensions:
      * twig: Twig templates
      * blade.php: Laravel Blade
      * erb: Ruby ERB templates
      * ejs: EJS templates

### 15 Build and Deployment Patterns
    - Build Tool Indicators:
      * webpack: Bundle patterns
      * gulp: Build file patterns
      * grunt: Task runner indicators
      * vite: Modern build tool

    - Deployment Artifacts:
      * Dockerfile patterns
      * github/workflows: GitHub Actions
      * gitlab-ci.yml: GitLab CI
      * Jenkinsfile: Jenkins pipelines

### 16 Third-Party Integration Patterns
    - Analytics and Tracking:
      * Google Analytics patterns
      * Hotjar integration
      * Facebook Pixel
      * Custom analytics implementation

    - CDN and Hosting Patterns:
      * CloudFlare headers
      * AWS CloudFront patterns
      * Azure CDN indicators
      * Google Cloud CDN

#### Framework-Specific Detection Techniques:
    WordPress:
    - /wp-admin/, /wp-includes/, /wp-content/
    - wp-json API endpoints
    - Generator meta tag
    - Specific cookie patterns

    Drupal:
    - /sites/default/files/
    - /core/assets/
    - Drupal.settings in JavaScript
    - X-Drupal-Cache header

    Laravel:
    - /storage/, /bootstrap/cache/
    - laravel_session cookie
    - XSRF-TOKEN cookie
    - Mix manifest patterns

    Ruby on Rails:
    - /assets/application-*.js
    - rails-ujs patterns
    - Turbolinks indicators
    - ActiveRecord patterns

    Django:
    - /static/admin/
    - csrftoken cookie
    - Django admin patterns
    - WSGI server headers

    ASP.NET:
    - Web.config file
    - ASP.NET_SessionId cookie
    - ViewState patterns
    - aspx file extensions

#### Automated Fingerprinting Tools:
    Command Line Tools:
    - WhatWeb: whatweb -a 3 target.com
    - Wappalyzer CLI: wappalyzer target.com
    - BuiltWith: builtwith.com target.com
    - WAFW00F: wafw00f target.com

    Browser Extensions:
    - Wappalyzer browser extension
    - BuiltWith browser extension
    - Library Sniffer
    - Application Fingerprint

    Custom Scripts:
    - Python with requests library
    - Curl with header analysis
    - Custom regex patterns
    - Machine learning classifiers

#### Manual Testing Methodology:
    Step 1: Initial Reconnaissance
    - Check HTTP headers
    - Analyze cookies
    - Review page source
    - Check for default files

    Step 2: Deep Analysis
    - Test error conditions
    - Analyze API responses
    - Check directory structures
    - Review JavaScript files

    Step 3: Framework-Specific Tests
    - Test known framework paths
    - Check for version-specific files
    - Analyze security implementations
    - Review build and deployment files

#### Documentation Template:
    Framework Fingerprint Report:
    - Target: target.com
    - Primary Framework: [Framework Name]
    - Version: [Detected Version]
    - Supporting Technologies: [List]
    - Detection Confidence: [High/Medium/Low]
    - Evidence: [Specific indicators found]
    - Security Implications: [Known vulnerabilities]

#### Common False Positives:
    - Custom frameworks mimicking popular ones
    - Modified default configurations
    - Security through obscurity techniques
    - CDN and proxy modifications

#### Protection and Obfuscation:
    - Header Removal:
      * Remove X-Powered-By headers
      * Custom server headers
      * Minimal error information

    - File Obfuscation:
      * Rename default directories
      * Modify default file names
      * Custom error pages

    - Security Through Obscurity:
      * Custom session cookie names
      * Modified URL patterns
      * Hidden administrative paths

This comprehensive web application framework fingerprinting checklist helps security professionals accurately identify the underlying technologies, versions, and configurations of web applications, enabling targeted security testing and vulnerability assessment.