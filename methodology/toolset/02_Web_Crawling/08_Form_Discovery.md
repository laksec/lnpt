
### 2.8 Form Discovery
    :- Specifically identifying HTML forms for further testing - CSRF, XSS, SQLi etc.
    
    katana -u https://target.com -f form -o katana_forms.txt            
    :- Use Katana's field config to extract forms
    
    :- Use general crawlers (Katana, GoSpider, Hakrawler) and grep output for `<form` tags

    grep -rio "<form" ./crawl_output/                                 
    :- Grep crawl results for form tags
