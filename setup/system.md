#### WSL Setup

    # wsl --install kali-linux --name lnpt
    # kali-tweaks
        - Change Shell from Bash to Zsh
        - Choose What modules to install
    # Set ~/.zshrc file
        - sudo nano ~/.zshrc
        - source ~/.zshrc
    # Install all the neccesory remaining tools

## GPU Compatibility

    hashcat -I  # Check here
    wget https://developer.download.nvidia.com/compute/cuda/repos/wsl-ubuntu/x86_64/cuda-keyring_1.0-1_all.deb
    sudo dpkg -i cuda-keyring_1.0-1_all.deb
    sudo apt update
    sudo apt-get install -y cuda

### Kali NetHunter

    https://github.com/termux/termux-app/releases
    https://f-droid.org/packages/com.termux/

    pkg update -y
    pkg upgrade -y

    termux-setup-storage
    pkg install wget

    wget -O install-nethunter-termux https://offs.ec/2MceZWr
    chmod +x install-nethunter-termux
    /install-nethunter-termux

    nethunter/nh          -> Start Kali NetHunter command line interface
    nh <command>          -> Run <command> in Kali NetHunter environment

    nh -r                     -> Start Kali NetHunter cli as root
    nethunter -r <command>    -> Run <command> in Kali NetHunter environment as root

### Zshrc Setup

    # ln -s /mnt/d/work ~/j

    alias cdenv='cd /mnt/d/work'
    alias cdws='cd /mnt/d//work/ws'
    alias cdlnpt='cd /mnt/d/work/lnpt'

    alias cddownload='cd /mnt/d/download'

    alias spy3="source /mnt/d/work/py3/bin/activate"

    alias emptyHistory='sudo echo "" > ~/.zsh_history'
    alias openHistory='sudo nano ~/.zsh_history'

    alias codelnpt='code /mnt/d/penv/lnpt'

    alias kupgrade='sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y'

    alias obsh='sudo nano ~/.bashrc'
    alias sbsh='source ~/.bashrc'
    
    # python -m venv venv

    # Kali Prompt
    PROMPT='%F{green}┌─(%flnpt%F{green})%f-%F{green}[%f%F{blue}%~%f%F{green}]'$'\n''└─$ '
    PROMPT='%F{green}┌─(%f$(date "+%b%d")%F{green})-%F{green}[%f%F{blue}%~%f%F{green}]'$'\n''└─$ '

    # Ubuntu Prompt
    PS1="\[\e[32m\]┌─(\[\e[0m\]Web3\[\e[32m\])-[\[\e[34m\]\w\[\e[0m\]\[\e[32m\]]\[\e[0m\]\n\[\e[32m\]└─$\[\e[0m\] "

    cd /mnt/d/work/ws && clear

    echo -e "\n\e[97;44mWeb Application - Bug Bounty Hunting\e[0m\n"

---

# Chrome Extensions

    FoxyProxy
    Link Gopher

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
