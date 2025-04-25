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

PROMPT='%F{green}┌─(%f%F{blue}%~%f%F{green})'$'\n''└─$ '