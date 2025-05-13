### 12.7 Masscan + Nmap
    # Fast port scan large range
    masscan -p80,443,8000-8100 10.0.0.0/8 --rate 100000 -oL masscan_results.txt 
    
    # Extract IPs from masscan
    awk -F'[ /]' '/open/{print $4}' masscan_results.txt | sort -u > open_ips.txt 
    
    # Detailed Nmap scan on IPs/ports from masscan (needs port extraction logic)
    nmap -sV -sC -iL open_ips.txt -pT:$(paste -sd, open_ports_for_nmap.txt) -oN nmap_detailed_scan.txt 
