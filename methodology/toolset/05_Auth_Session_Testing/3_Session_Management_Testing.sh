### 5.3 Session Management Testing
    # (Often manual or with Burp Sequencer. For a command line concept:)    
    
    # Analyze session ID entropy
    session_analyzer --url https://target.com/login --cookies "PHPSESSID=abc" --check-entropy 
    
    # Test for session fixation
    session_fixation_tester -u https://target.com/login --new-session-url https://target.com/afterlogin 

    # Use Burp API for brute force
    burp-rest-api --config burp_config.json --intruder-payloads user_pass.txt --intruder-attack https://target.com/login 
    ------
    session-fuzz -u https://target.com/login -c cookies.txt -p params.txt
    session-bruteforcer -u https://target.com -t tokens.txt
    ------
    session-fuzz -u https://target.com/login -c cookies.txt -p /usr/share/seclists/Fuzzing/HTTP-Methods-and-More/HTTP-Methods.txt -m PUT,DELETE
    session-fuzz -u https://target.com/change_password -c session_cookie -d "old_password=test&new_password=FUZZ&confirm_password=FUZZ" -w /usr/share/seclists/Passwords/Common-Credentials/top-passwords.txt
    session-bruteforcer -u https://target.com/api/session -H "X-Session-Token: FUZZ" -t valid_tokens.txt -r "valid"
    ------
    session-fuzz -u https://target.com/login -c cookies.txt -p /usr/share/seclists/Fuzzing/HTTP-Methods-and-More/all.txt -m GET,POST,PUT,DELETE,OPTIONS,TRACE
    session-fuzz -u https://target.com/change_password -c session_cookie -d "current_password=FUZZ&new_password=newpass&confirm_password=newpass" -w /usr/share/seclists/Passwords/Common-Credentials/top-passwords.txt -rate 50
    session-bruteforcer -u https://target.com/api/session -H "Authorization: Bearer FUZZ" -t long_token_list.txt -r "valid" -threads 20