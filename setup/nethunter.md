sudo apt install gccgo-go -y && sudo apt install golang-go -y


sudo apt install subfinder
sudo apt install assetfinder
sudo apt install dirsearch
sudo apt install naabu

go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install github.com/projectdiscovery/tldfinder/cmd/tldfinder@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/projectdiscovery/wappalyzergo/cmd/update-fingerprints@latest



