# Fuzzing Tools (General Purpose)
    wfuzz -c -z file,/SQLi/Generic-SQLi.txt --hc 200 https://target.com/index.php?id=FUZZ
    radamsa -n 1000 -o mutated.txt < input.txt
    afl-fuzz -i in -o out -t 10000 -m 100 -x Fuzzing/fuzzing-patterns.txt -- ./vulnerable_program @@
