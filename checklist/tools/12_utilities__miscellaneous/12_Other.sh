### Other
    find ~/j/tools/lnpt/methodology/toolset -type f -name "*.md" -exec bash -c 'mv "$0" "${0%.md}.sh"' {} \;