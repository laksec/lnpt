
### 11.3 Markdown Notes
    echo "#### Vulnerability: SQL Injection" >> report.md    
    echo "**URL:** https://vuln.target.com/product?id=1" >> report.md
    echo "**Parameter:** id" >> report.md
    echo "**Payload:** \`1' OR '1'='1 -- \`" >> report.md
    echo "**Evidence:**" >> report.md
    echo '```sqlmap output...' >> report.md
    sqlmap -u "[https://vuln.target.com/product?id=1](https://vuln.target.com/product?id=1)" --batch --banner >> report.md    
    echo '```' >> report.md
