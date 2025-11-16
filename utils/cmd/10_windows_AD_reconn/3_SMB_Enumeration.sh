### 10.3 SMB Enumeration
    # Basic SMB enumeration on a subnet
    crackmapexec smb 192.168.1.0/24
    
    # Check credentials and list shares
    crackmapexec smb targets.txt -u username -p password --shares
    
    # Enumerate logged-in users
    crackmapexec smb targets.txt --lusers
    
    # Brute force RIDs to find users
    crackmapexec smb targets.txt -M rid_brute