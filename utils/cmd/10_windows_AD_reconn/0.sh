    # (Often used after gaining initial foothold, relevant if bug bounty scope includes internal testing or pivoting)

    # User & Group Enumeration    
    # List local users
    net user
    
    # List domain users (if joined)
    net user /domain
    
    # List domain groups
    net group /domain
    
    # List members of Domain Admins group
    net group "Domain Admins" /domain
    
    # Get users and SIDs
    wmic useraccount get name,sid