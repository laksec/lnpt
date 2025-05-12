### 5.2 OAuth Testing
    # (Manual testing with Burp Suite is common. Tools can assist.)
    # For conceptual command, imagine a tool:    
    
    # Test for common misconfigs
    oauth_scanner -u https://auth.target.com/authorize -c client_id_val -r http://localhost/callback --test misconfigs 
    
    # Test specific flow
    oauth_scanner -u https://auth.target.com/token -g client_credentials --test open_redirect 
    -----
    oauth2test -u https://target.com/oauth -c client_id -r redirect_uri
    burp-oauth -c config.json -p 8080
    ------
    oauth2test -u https://target.com/oauth/authorize -c client_id -r http://evil.com/callback -s invalid_scope
    oauth2test -u https://target.com/oauth/token -g authorization_code -d "client_id=...&client_secret=...&grant_type=authorization_code&code=..." -m POST
    burp-oauth -c config_full.json -p 8080 -v
    burp-oauth -c implicit_grant.json -p 8081
    ------
    oauth2test -u https://target.com/oauth/authorize -c client_id -r http://evil.com/callback -s openid profile email address -response_type code id_token
    oauth2test -u https://target.com/oauth/token -g authorization_code -d "client_id=...&client_secret=...&grant_type=authorization_code&code=...&redirect_uri=http://evil.com/callback" -m POST -H "Content-Type: application/x-www-form-urlencoded"
    burp-oauth -c config_extensive.json -p 8080 -v -debug
    burp-oauth -c implicit_grant_full.json -p 8081 -intercept