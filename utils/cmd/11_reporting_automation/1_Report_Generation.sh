### 11.1 Report Generation
    # JSON output for integration
    nuclei -l urls.txt -t critical_vulns.yaml -json -o critical_report.json 
    
    # Nikto HTML report
    nikto -h target.com -Format htm -output nikto_web_report.html
    
    # SQLMap stores results in output dir
    sqlmap -r request.txt --batch --output-dir sqlmap_results/
    ------
    nuclei -l urls.txt -t nuclei-templates/ -me reports/ -s critical,high
    dalfox report -o report.html
    dalfox report -o report.html --format html --input scan.json
    arachni --report-save-path=report.afr --checks=active/* https://target.com
    ------
    nuclei -l urls.txt -t nuclei-templates/ -me reports/ -s critical,high -json -o nuclei_report.json
    dalfox report -o report.md --format markdown --input scan.json
    arachni --report-save-path=report_full.afr --checks=* https://target.com
    ------
    nuclei -l urls.txt -t nuclei-templates/ -me reports/ -s critical,high -json -o nuclei_report_full.json -template-display-mode id
    dalfox report -o report_detailed.html --format html --input scan.json --severity-min critical --export-type markdown
    arachni --report-save-path=report_very_full.afr --checks=* --scope-exclude-pattern "logout|signout" https://target.com