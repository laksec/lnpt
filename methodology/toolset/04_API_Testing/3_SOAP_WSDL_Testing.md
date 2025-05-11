### 4.3 SOAP/WSDL Testing
    wsdlfuzz -u https://target.com/wsdl -o wsdl_results.xml
    soapui -s https://target.com/service?wsdl -t test_case
    ------
    wsdlfuzz -u https://target.com/service?wsdl -o wsdl_results_full.xml -d 3
    wsdlfuzz -u https://target.com/api.asmx?wsdl -o asmx_fuzz.xml -w /usr/share/seclists/Fuzzing/SOAP-WSDL/Common-SOAP-Requests.txt
    soapui -s https://target.com/service?wsdl -t security_test_suite -j
    soapui -s https://target.com/old_service?wsdl -p admin -w password
    ------
    wsdlfuzz -u https://target.com/service?wsdl -o wsdl_results_deep.xml -d 5 -w /usr/share/seclists/Fuzzing/SOAP-WSDL/SOAP-Parameter-Fuzzing.txt
    wsdlfuzz -u https://target.com/api.asmx?wsdl -o asmx_fuzz_extended.xml -w custom_soap_payloads.txt -headers "Content-Type: text/xml"
    soapui -s https://target.com/service?wsdl -t security_test_suite_full -j -Dprop1=value1 -Dprop2=value2
    soapui -s https://target.com/old_service?wsdl -p admin -w password -s "Negative Tests"