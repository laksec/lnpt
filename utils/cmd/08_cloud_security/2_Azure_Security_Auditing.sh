### 8.2 Azure Security Auditing
    # List Azure PIM role assignments
    az PIM role assignment list --assignee user@domain.com --all -o table 
    
    # Azure Resource Graph query for storage accountsaz graph query -q "Resources | where type =~ 'microsoft.storage/storageaccounts' | project name, properties.primaryEndpoints.
    blob" -o json 

    # (ScoutSuite supports Azure: scoutsuite azure --subscription-id "YOUR_SUB_ID")
    # GCP Security Auditing
    # (ScoutSuite supports GCP: scoutsuite gcp --project-id "your-project-id")    
    # Get GCP project IAM policy
    gcloud projects get-iam-policy YOUR_PROJECT_ID --format=json > gcp_iam_policy.json 
    
    # Search IAM policies for a service accountgcloud asset search-all-iam-policies --scope=projects/YOUR_PROJECT_ID --query="policy:serviceAccount:your-sa@project.iam.
    gserviceaccount.com" 
