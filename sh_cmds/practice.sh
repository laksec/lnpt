#!/bin/bash


cat domains.txt | while read vl; do ping -c 3 "$vl"; done > ping_results.txt
