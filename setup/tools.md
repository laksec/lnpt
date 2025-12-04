# Kali-Linux Tool Installation

## Go Setup

    sudo apt install gccgo-go -y && sudo apt install golang-go -y

    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"

    sudo apt install -y libpcap-dev

---

## Go Tools

    sudo apt install massdns

    # ProjectDiscovery Tool Manager
    go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest

    # Append only unique lines to files
    go install github.com/tomnomnom/anew@latest

    # Extract URLs from Wayback Machine archives
    go install github.com/tomnomnom/waybackurls@latest

    # Probe HTTP/HTTPS responsiveness of hosts
    go install github.com/tomnomnom/httprobe@latest

    # Find subdomains related to a domain
    go install github.com/tomnomnom/assetfinder@latest

    # Parallel HTTP requester and matcher
    go install github.com/tomnomnom/meg@latest

    # Intel gathering on IPs, Domains, ASN using public data sources
    go install github.com/j3ssie/metabigor@latest

---

### Npm Instalation
    npm install -g @google/gemini-cli


### Apt Instalation
    sudo apt install firefox-esr -y

    # Wordlists for security testing
    sudo apt  install seclists -y

    # --depth 1 removes git file which is huge
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git

    # Lightweight DNS server
    sudo apt install tinydns -y

    # Passive subdomain enumeration tool
    sudo apt install sublist3r -y

    # Screenshot websites for recon
    sudo apt install gowitness -y

    # Find extra archived links from the Wayback Machine
    sudo apt install waymore -y

    # IPv6 MITM attack tool for Active Directory
    sudo apt install mitm6 -y

    # Active Directory - visualization & priv esc mapping
    sudo apt install bloodhound -y

---

<!-- ### Git Tools
---
-->

### Python/Pipx Tools

    # Discover endpoints & parameters from JS files
    pipx install git+https://github.com/xnl-h4ck3r/xnLinkFinder.git

---

## API Usage Example

    # VirusTotal domain report (replace $VT_KEY with your API key)
    curl https://www.virustotal.com/vtapi/v2/domain/report/?apikey\=$VT_KEY\&domain\=snapchat.com | jq -r
