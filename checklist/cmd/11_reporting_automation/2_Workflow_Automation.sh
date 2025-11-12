### 11.2 Workflow Automation
    # (Conceptual - many custom scripts exist)    
    /my_recon_script.sh target.com
    /full_scan_automation.sh target.com -o /reports/target_com_$(date +%F)

    bugbounty-auto -c config.yaml -t target.com -o output/
    reconftw -d target.com -a -r -w -o reconftw_output
    autorecon --only-scans --output scans/ target.com
    interlace -tL targets.txt -c "nuclei -u _target_"
    ------
    bugbounty-auto -c config_advanced.yaml -t target.com -o output_full/
    reconftw -d target.com -a -r -w -o reconftw_all -threads 50 -v
    autorecon --full --output autorecon_full/ target.com
    ------
    bugbounty-auto -c config_very_advanced.yaml -t target.com -o output_very_full/
    reconftw -d target.com -a -r -w -o reconftw_ultimate -threads 75 -v -all-scripts
    autorecon --full --scripts all --output autorecon_ultimate/ target.com

#### 11.2.1 Bash loop to run nuclei on subdomains


#### 11.2.2 Bash loop for directory brute-forcing


#### 11.2.3 Combine passive/active enum, resolve, check hosts


#### 11.2.4 Filter URLs for potential XSS