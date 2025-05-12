### 7.2 Google Dorking
    # (Manual via browser, conceptual via tools if available or scripting)
    # Example Google Dork for confidential PDFs
    site:target.com filetype:pdf confidential
    
    # Dork for directory listings with "backup"
    site:target.com intitle:"index of" "backup"
    
    # Dork for SQL files with credentials
    site:target.com ext:sql "username" "password"
    
    # Search GitHub for API keys related to target
    site:github.com "target.com" "api_key"
    
    # Search Trello boards
    site:trello.com "target.com" "password"

