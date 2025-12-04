### 8.1 AWS Security Auditing
    # AWS CIS Benchmarks Level 1, JSON output, silent
    prowler -g cislevel1 -M json -S -f us-east-1 -o prowler_cis_report.json 
    
    # Check specific Prowler check (e.g., S3 public access)
    prowler -c s3_bucket_public_access -M csv -o prowler_s3_public.csv
    
    # List checks for HIPAA group in JSON
    prowler aws -g hipaa --list-checks-json
    
    # AWS security auditing using a specific profile
    scoutsuite aws --profile myawscli_profile --report-dir scout_aws_report/ 
    
    # Using temporary credentials
    scoutsuite aws --access-key-id AKIA... --secret-access-key   --session-token   
    
    # Import AWS keys into Pacu
    pacu --import-keys --key-alias mycorp

    # Example Pacu command for IAM enumeration

    # Inside Pacu: run iam_enum_permissions
    # Example Pacu command for S3
    # Inside Pacu: run s3_download_bucket --bucket-name mybucket --all