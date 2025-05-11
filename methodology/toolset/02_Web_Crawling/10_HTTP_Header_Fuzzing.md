### 2.10 HTTP Header Fuzzing
     :- (Used to test for cache poisoning, header injection vulnerabilities, finding hidden headers)
     
     :- Fuzz X-Forwarded-Host
     -w header_payloads.txt -u https://target.com -H "X-Forwarded-Host: FUZZ" -fs <baseline_size> 
    
    :- Fuzz header names
    ffuf -w common_headers.txt:HEADER -u https://target.com -H "HEADER: testvalue" --mc 200,302 
    
    :- Fuzz HTTP methods
    ffuf -w methods.txt:METHOD -u https://target.com -X METHOD --hc 405,404 
