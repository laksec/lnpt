# WSL Setup

    :- wsl --install kali-linux --name lnpt
    :- Set ~/.zshrc file
        - sudo nano ~/.zshrc
        - source ~/.zshrc
    :- kali-tweaks
        - Change Shell from Bash to Zsh
        - Choose What modules to install
    :- Install all the neccesory remaining tools

## Zshrc Setup

    # ln -s /mnt/d/work ~/j
    # ln -s /mnt/d/work/ws ~/ws
    # ln -s /mnt/d/work/tools ~/tool

    alias cdcyber='cd /mnt/d/work'
    alias cdws='cd /mnt/d/work/ws'          # Workspace
    alias cdtool='cd /mnt/d/work/tools'
    alias cdlnpt='cd /mnt/d/work/tools/lnpt'
    alias cdfiles='cd /mnt/d/work/files'
    alias cddownload 'cd /mnt/d/download'

    alias codelnpt='code /mnt/d/work/tools/lnpt'

    alias runUpgrade='sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y'

    alias openZsh='sudo nano ~/.zshrc'
    alias srcZsh='source ~/.zshrc'

    export PATH=$PATH:/mnt/c/Program\ Files/Sublime\ Text
    alias subl='/mnt/c/Program\ Files/Sublime\ Text/subl.exe'

    export PATH=$PATH:/mnt/c/Users/LAKS/AppData/Local/Programs/Microsoft\ VS\ Code
    alias code='/mnt/c/Users/LAKS/AppData/Local/Programs/Microsoft\ VS\ Code/Code.exe'

## Check if system distro detected GPU

    hashcat -I  # Check here
    wget https://developer.download.nvidia.com/compute/cuda/repos/wsl-ubuntu/x86_64/cuda-keyring_1.0-1_all.deb
    sudo dpkg -i cuda-keyring_1.0-1_all.deb
    sudo apt update
    sudo apt-get install -y cuda

# Virtual Box setup

    Download Kali virtual image
    install Kali
    Use Pimp_My_Kali for setup
    Export Kali

# Chrome Extensions

    - FoxyProxy
    - Link Gopher
