### 4.2 GraphQL Testing
    # Dump schema with auth
    graphqlmap -u https://target.com/graphql --dump-schema --headers "Auth: Bearer TKN" 
    
    # Custom introspection query
    graphqlmap -u https://target.com/graphql --method query --query '{__schema{types{name}}}' 
    
    # Schema reconstruction if introspection is disabled
    clairvoyance -o schema_reconstructed.json https://target.com/graphql
    
    # Use wordlist and header
    clairvoyance -w wordlist_for_graphql.txt -H "X-API-KEY: mykey" https://target.com/graphql 

    
    # Burp extension, can be used command-line for schema analysis (conceptual)
    inql -t https://target.com/graphql -f schema.json
    
    # Fingerprint GraphQL engine and dump schema
    graphw00f -t https://target.com/graphql -f -d -o graphw00f_fingerprint.txt 
    
    # Scan a list of endpoints
    graphw00f -list list_of_graphql_endpoints.txt -o graphw00f_list_scan.txt

    # (nuclei has GraphQL templates)    
    nuclei -u https://target.com/graphql -t exposures/graphql/graphql-introspection.yaml -o nuclei_graphql_introspection.txt
    -------
    graphqlmap -u https://target.com/graphql --dump-schema
    clairvoyance -o schema.json https://target.com/graphql
    inql -t https://target.com/graphql -o inql_results
    graphw00f -d -f -t https://target.com/graphql
    ------
    graphqlmap -u https://target.com/graphql --dump-schema -o schema.gql
    graphqlmap -u https://target.com/graphql --batching -o batching_vuln.txt
    clairvoyance -o schema_full.json https://target.com/graphql -v
    clairvoyance -o introspection_disabled.json https://target.com/graphql -b
    inql -t https://target.com/graphql -o inql_results_full -headers "Authorization: Bearer token"
    inql -t https://target.com/graphql -o inql_mutation_test --mutation 'mutation { createUser(name: "test", email: "test@example.com") { id } }'
    graphw00f -d -f -t https://target.com/graphql -e
    graphw00f -d -b -t https://target.com/graphql
    ------
    graphqlmap -u https://target.com/graphql --dump-schema -o schema_very_full.gql --depth 5
    graphqlmap -u https://target.com/graphql --batching -o batching_vuln_detailed.txt --batch-size 10
    clairvoyance -o schema_hidden.json https://target.com/graphql -v --hidden
    clairvoyance -o custom_headers.json https://target.com/graphql -h "Authorization: Bearer admin_token"
    inql -t https://target.com/graphql -o inql_results_extensive -headers "X-CSRF-Token: value" -cookies "sessionid=..."
    inql -t https://target.com/graphql -o inql_mutation_complex --mutation 'mutation { updateUser(id: 1, data: { isAdmin: true }) { success } }'
    graphw00f -d -f -t https://target.com/graphql -e -v
    graphw00f -d -b -t https://target.com/graphql --timeout 15