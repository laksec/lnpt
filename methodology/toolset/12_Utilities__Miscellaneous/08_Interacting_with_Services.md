### 12.8 Interacting with Services
    :- GET request with Auth header, pipe to jq
    curl -s -X GET "http://target.com/api/users" -H "Authorization: Bearer TOKEN" | jq . 
    
    :- Netcat listen for incoming connections
    ncat -lvnp 4444
    
    :- Send raw HTTP request from file
    ncat target.com 80 < http_request.txt

