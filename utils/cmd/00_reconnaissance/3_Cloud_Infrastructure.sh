### 1.3 Cloud Infrastructure
    # CLOUD ENUMERATION (Multi-cloud)
    # Full cloud reconnaissance
    cloud_enum -k target -t aws,azure,gcp -l cloud_enum_full.log -details -verify -public

    # Targeted service enumeration
    cloud_enum -k target -t aws:s3,ec2,lambda -l aws_specific.log
    cloud_enum -k target -t azure:storage,vm,appservice -l azure_specific.log
    cloud_enum -k target -t gcp:storage,compute,functions -l gcp_specific.log

    # SECURITY AUDITING (ScoutSuite)
    # Comprehensive AWS audit
    scout suite --provider aws --regions all --report-dir scout_aws_full

    # Azure tenant audit
    scout suite --provider azure --tenant-id $AZURE_TENANT_ID --report-dir scout_azure_tenant

    # Targeted region audit
    scout suite --provider aws --regions us-east-1,eu-west-1 --report-dir scout_aws_critical_regions

    # CLOUD FLAWS SCANNER (CFR)
    # S3 bucket analysis
    cfr -u https://target.s3.amazonaws.com/ -o cfr_s3_root.txt
    cfr -u https://s3.amazonaws.com/target-backups/ -o cfr_s3_backups.txt

    # Azure storage scanning
    cfr -u https://target.blob.core.windows.net/$web/ -o cfr_azure_web.txt
    cfr -u https://target.file.core.windows.net/share/ -o cfr_azure_files.txt

    # STORAGE BUCKET SCANNING
    # S3 bucket discovery
    s3scanner scan -l buckets.txt -o s3_results.json -a -p sensitive/

    # Targeted bucket checks
    s3scanner scan -b target-backup-bucket -o s3_backup_check.json -p db_backups/

    # GCP bucket brute force
    gcpbucketbrute -k target -w common_bucket_names.txt -threads 100 -o gcp_common.txt
    gcpbucketbrute -k target -prefix prod- -o gcp_prod_buckets.txt

    # SECURITY COMPLIANCE (Prowler)
    # CIS Benchmark scan
    prowler -g cislevel1 -M json -o prowler_cis_report

    # Full security assessment
    prowler -g cislevel1,cislevel2 -M html -o prowler_full_report

    # RECOMMENDED WORKFLOW:
    # 1. Start with cloud_enum for asset discovery
    # 2. Run ScoutSuite for security posture
    # 3. Check storage buckets with CFR/s3scanner
    # 4. Perform targeted brute forcing
    # 5. Validate compliance with Prowler

    # PRO TIPS:
    # Always use '-verify' with cloud_enum to confirm findings
    # For Azure: Set AZURE_TENANT_ID and AZURE_CLIENT_ID env vars
    # For GCP: Authenticate with 'gcloud auth application-default login'
    # Combine with 'awscli' for manual verification: 
    # aws s3 ls s3://target-bucket/ --no-sign-request
    # Use -details flag to get verbose cloud metadata
    # Combine with jq for JSON analysis: jq '.vulnerable_buckets[]' s3_results.json
    # For Azure: Add --subscriptions parameter to ScoutSuite for specific subscriptions
    # Schedule regular Prowler scans with -b for brief mode

#### 1.3.1 Cloud Infrastructure Identification (AWS, Azure, GCP)
    # CLOUD_ENUM (Multi-cloud discovery)
    # Full cloud reconnaissance
    cloud_enum -k target -t aws,azure,gcp -o cloud_enum_full.log

    # Targeted provider scans
    cloud_enum -k target.com -t aws -o aws_target.log
    cloud_enum -k "Company Name" -t azure -o azure_company.log
    cloud_enum -k "project-id" -t gcp -o gcp_project.log

    # File-based enumeration
    cloud_enum -kf target_list.txt -t aws -o aws_from_file.log

    # S3SCANNER (AWS S3)
    # Scan bucket list with full checks
    s3scanner scan -l buckets.txt --all-perms -o s3_full_audit.json

    # Targeted bucket inspection
    s3scanner scan --bucket target-prod -o s3_prod_bucket.json

    # GCPBUCKETBRUTE (Google Cloud)
    # Brute force with common terms
    gcpbucketbrute -k target -w top_1000.txt -o gcp_common_buckets.txt

    # Domain-based permutations
    gcpbucketbrute -d target.com -o gcp_domain_buckets.txt

    # RECOMMENDED WORKFLOW:
    # 1. Start with cloud_enum for broad discovery
    # 2. Run targeted scans for each cloud provider
    # 3. Verify S3/GCP storage buckets
    # 4. Check permissions on found resources

    # PRO TIPS:
    # For AWS: Add '-t aws:s3,ec2' to focus on specific services
    # For Azure: Include '-t azure:storage,blob' for storage checks
    # For GCP: Use '-t gcp:storage,compute' for focused scanning
    # Always check '-o' output files for sensitive findings