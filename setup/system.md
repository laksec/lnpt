# WSL Setup

    # wsl --install kali-linux --name lnpt
    # kali-tweaks
        - Change Shell from Bash to Zsh
        - Choose What modules to install
    # Set ~/.zshrc file
        - sudo nano ~/.zshrc
        - source ~/.zshrc
    # Install all the neccesory remaining tools

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

    alias kupgrade='sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y'

    alias openZsh='sudo nano ~/.zshrc'
    alias srcZsh='source ~/.zshrc'

    export PATH=$PATH:/mnt/c/Program\ Files/Sublime\ Text
    alias subl='/mnt/c/Program\ Files/Sublime\ Text/subl.exe'


    export PATH=$PATH:/mnt/c/Users/laksh/AppData/Local/Programs/Microsoft\ VS\ Code
    alias code='/mnt/c/Users/laksh/AppData/Local/Programs/Microsoft\ VS\ Code/Code.exe'

    PROMPT='%F{green}┌─(%flnpt%F{green})%f-%F{green}[%f%F{blue}%~%f%F{green}]'$'\n''└─$ '
    PROMPT='%F{green}┌─(%f$(date "+%b%d")%F{green})-%F{green}[%f%F{blue}%~%f%F{green}]'$'\n''└─$ '
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

# Daily Routine for Discipline

     ____From_12:00_AM______   _________From_06:00_AM______________
    |    			        | |    By: 06:30 AM - Gentle Mobility  |
    | By: 06:00 AM - Sleep  >>>    By: 08:15 AM - Work	           |
    | 			            | |    By: 08:30 AM - Breakfast        |
    | 			            | | 				                   |
    |____From_08:30_AM______| |_________From_01:15_PM______________|
    |  By: 11:15 AM - Work  | |        By: 01:30 PM - Lunch        |
    |  By: 11:30 AM - _Nap  >>>        By: 04:15 PM - Work         |
    |  By: 01:15 PM - Work  | |        By: 04:30 PM - _Nap         |
    | 			            | | 				                   |
    |____From_04:30_PM______| |_________From_04:30_PM______________|
    | By: 08:15 PM - Work 	| | By: 10:30 PM - _Nap     	       |
    | By: 08:30 PM - Dinner	>>> By: 11:00 PM - Wind-down 	       |
    | By: 10:15 PM - Work	| | By: 12:00 AM - Light creative work |
    |_______________________| |____________________________________|
