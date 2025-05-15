# 🔐 WEAK CRYPTOGRAPHY TESTING MASTER CHECKLIST

## 9.1 Testing for Weak Transport Layer Security
### Protocol Testing
    - Verify TLS 1.2+ enforcement (disable SSLv3, TLS 1.0/1.1)
    - Test for POODLE attack (SSLv3 fallback)
    - Check for BEAST vulnerability (CBC cipher suites)
    - Verify FREAK/Logjam mitigation (disable export-grade ciphers)

### Cipher Suite Testing
    - Confirm weak ciphers disabled:
        - RC4
        - DES/3DES
        - CBC mode ciphers
        - NULL/anon ciphers
    - Verify ECDHE key exchange preference
    - Check forward secrecy implementation

### Certificate Testing
    - Validate certificate:
    - Not expired/self-signed
    - Strong signature (SHA-256+)
    - Proper SAN configuration
    - OCSP stapling enabled
    - Test for Heartbleed vulnerability

## 9.2 Testing for Padding Oracle
    - Check for error message differences:
    - Invalid padding vs. invalid MAC
    - Response timing variations
    - Test CBC-mode encryption endpoints:
    - Authentication tokens
    - Session cookies
    - API parameters
    - Verify AES-GCM usage where possible

## 9.3 Testing for Sensitive Information via Unencrypted Channels
### Protocol Analysis
    - Check for:
    - HTTP form submissions
    - Basic auth over HTTP
    - API keys in URLs
    - Mixed content warnings
    - Verify HSTS header implementation
    - Test for SSL stripping attacks

### Data Flow Testing
    - Trace sensitive data through:
    - Mobile app communications
    - Third-party integrations
    - WebSocket connections
    - Webhook callbacks

## 9.4 Testing for Weak Encryption
### Algorithm Testing
    - Identify usage of:
    - MD5/SHA-1 hashing
    - ECB mode encryption
    - RSA < 2048-bit
    - DSA < 2048-bit
    - ECDSA < 256-bit
    - Verify PBKDF2/scrypt/Argon2 for password storage

### Implementation Testing
    - Check for:
    - Hardcoded keys/secrets
    - IV reuse
    - Improper random number generation
    - Key derivation without salts
    - Test for CRIME/BREACH attacks

## 9.5 Additional Cryptographic Tests
### Key Management
    - Verify:
    - Key rotation policies
    - Secure key storage
    - Proper key destruction
    - HSMs for critical keys

### Configuration Review
    - Check:
    - Crypto libraries updated
    - FIPS 140-2 compliance if required
    - Disabled insecure protocols (SSHv1, Telnet)
    - Secure crypto configuration guides followed

### 🛡️ CRYPTO HARDENING RECOMMENDATIONS
    ✔ TLS 1.3 preferred where supported  
    ✔ AEAD ciphers (AES-GCM, ChaCha20-Poly1305)  
    ✔ Certificate transparency monitoring  
    ✔ Security headers (Expect-CT, Feature-Policy)  
    ✔ Automated scanning for crypto weaknesses  

### 🔧 TESTING TOOLS
    - testssl.sh (Comprehensive TLS testing)
    - SSL Labs Scanner (Qualys)
    - Wireshark (Traffic analysis)
    - Burp Suite (Manual crypto testing)
    - Hashcat (Password hash testing)
    - CryptCheck (Server configuration analysis)

### ⚠️ COMMON VULNERABILITIES
    - Outdated TLS configurations
    - Missing certificate validations
    - Predictable initialization vectors
    - Weak password hashing (unsalted MD5)
    - Cryptographic randomness issues

