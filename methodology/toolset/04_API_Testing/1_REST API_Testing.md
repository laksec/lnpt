### 4.1 REST API Testing
    :- API endpoint brute force, 10 extensions deep
    kiterunner -w api_routes.txt -u https://target.com/api -A discovery -x 10 -o kiterunner_scan.txt 
    
    :- Scan using Kiterunner's format
    kiterunner scan -U https://api.target.com -w routes-large.kite --max-api-depth 5 -o kite_depth5.txt 
    
    :- Recon mode on a list of hosts
    kiterunner recon -A assetnote_wordlist/kiterunner/routes-large.kite -s hosts.txt -o kite_recon.txt 

    :- (arjun used previously for general param discovery, also applicable here)    
    :- API GET parameter discovery
    arjun -u https://api.target.com/v1/users --include='application/json' -m GET -o arjun_api_get.json 
    
    :- API POST w/ Auth
    arjun -u https://api.target.com/v1/items -m POST -H "Authorization: Bearer XYZ" -o arjun_api_post_auth.json 
    ------
    kiterunner -w api_wordlist.txt -u https://target.com/api
    kiterunner -w api_wordlist.txt -u https://target.com/api -A discovery
    arjun -u https://target.com/api --include='application/json'
    postman-smuggler -r request.txt
    postman-smuggler -r request.txt -o smuggled_requests
    crAPI -u https://target.com/api -t 20 -o crapi_report.html
    restler fuzz --grammar_file api_spec.json --dictionary words.txt
    ------
    kiterunner -w api_endpoints.txt -u https://target.com/api -A discovery,security -o kiterunner_full.txt -threads 30
    kiterunner -w swagger.json -u https://target.com/api -A all -o kiterunner_swagger.txt
    arjun -u https://target.com/api --include='application/json','application/xml' -o arjun_api_all.json -m all -t 20
    arjun -u https://target.com/api/users/{id} --method PUT --params '{"username":"test","email":"test@example.com"}' -o arjun_put.txt
    postman-smuggler -r request.txt -o smuggled_requests_all -v
    postman-smuggler -r malicious_request.txt -o smuggled_malicious
    crAPI -u https://target.com/api -t 30 -o crapi_report_full.html -deep
    crAPI -u https://target.com/api -auth-type basic -username user -password pass -o crapi_auth.html
    restler fuzz --grammar_file api_spec.json --dictionary words.txt --host target.com --port 443 --ssl
    restler fuzz --grammar_file openapi.yaml --api_key $API_KEY
    swagger-cli validate swagger.json
    swagger-cli bundle swagger.json -o bundled_swagger.json
    ------
    kiterunner -w api_endpoints_extensive.txt -u https://target.com/api -A discovery,security,fuzz -o kiterunner_extensive.txt -threads 40 -v
    kiterunner -w openapi.json -u https://target.com/api -A all -o kiterunner_openapi_full.txt -report-format json
    arjun -u https://target.com/api --include='application/json','application/xml','text/plain' -o arjun_api_all_types.json -m all -t 35 -H "X-Custom-Header: value"
    arjun -u https://target.com/api/users/{id} --method PATCH --params '{"is_admin":true}' -o arjun_patch_admin.txt -b "401,403"
    postman-smuggler -r complex_request.txt -o smuggled_complex -vv
    postman-smuggler -r auth_bypass_request.txt -o smuggled_auth_bypass
    crAPI -u https://target.com/api -t 40 -o crapi_report_very_full.html -deep -rate-limit 200
    crAPI -u https://target.com/api -auth-type bearer -token $BEARER_TOKEN -o crapi_bearer.html
    restler fuzz --grammar_file api_spec.json --dictionary words.txt --host target.com --port 443 --ssl --request_timeout 60
    restler fuzz --grammar_file graphql.json --api_key $GRAPHQL_KEY --method POST --data '{"query": "{ __schema { queryType { name } } }"}'
    swagger-cli bundle swagger.yaml -o bundled_swagger.json --type yaml
    swagger-cli validate bundled_swagger.json --schemaType yaml