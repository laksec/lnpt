# WSL Setup

    :- wsl --install kali-linux --name lnpt
    :- kali-tweaks
        - Change Shell from Bash to Zsh
        - Choose What modules to install
    :- Set ~/.zshrc file
        - sudo nano ~/.zshrc
        - source ~/.zshrc
    :- Install all the neccesory remaining tools

## Zshrc Setup

    # ln -s /mnt/d/work ~/j

    alias cddefault='cd /mnt/d/work'
    alias cdws='cd /mnt/d/work/ws'
    alias cdtool='cd /mnt/d/work/tools'
    alias cdlnpt='cd /mnt/d/work/tools/lnpt'
    alias cdfiles='cd /mnt/d/work/files'

    alias cddownload='cd /mnt/d/download'

    alias emptyHistory='sudo echo "" > ~/.zsh_history'
    alias openHistory='sudo nano ~/.zsh_history'

    alias codelnpt='code /mnt/d/work/tools/lnpt'

    alias runUpgrade='sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y'

    alias openZsh='sudo nano ~/.zshrc'
    alias srcZsh='source ~/.zshrc'

    export PATH=$PATH:/mnt/c/Program\ Files/Sublime\ Text
    alias subl='/mnt/c/Program\ Files/Sublime\ Text/subl.exe'


    export PATH=$PATH:/mnt/c/Users/LAKS/AppData/Local/Programs/Microsoft\ VS\ Code
    alias code='/mnt/c/Users/LAKS/AppData/Local/Programs/Microsoft\ VS\ Code/Code.exe'

    PROMPT='%F{green}┌─(%flnpt%F{green})%f-%F{green}[%f%F{blue}%~%f%F{green}]'$'\n''└─$ '
    PS1="\[\e[32m\]┌─(\[\e[0m\]Web3\[\e[32m\])-[\[\e[34m\]\w\[\e[0m\]\[\e[32m\]]\[\e[0m\]\n\[\e[32m\]└─$\[\e[0m\] "

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
