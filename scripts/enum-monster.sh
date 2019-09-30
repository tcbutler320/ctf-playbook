#!/bin/bash

# enumeration monster is a script to automate pentesting associate with OSCP
if $1 < 1; do 
echo "Usage: ./enum-monster.sh [project name]"
 
# create a project folder
mkdir $1

# find live hosts
nmap -v -sn 10.11.1.1-250 -oG ping_sweep.txt
cat ping_sweep | grep "Status: Up" |  cut -d" " -f 2 > targets.txt     # File: targets.txt
                                                                       # Contents: Raw IP of live hosts



# create txt files for each target
for ip in $(cat targets.txt); do 
    touch $ip.txt 

# run nmap to enumerate services
for ip in $(cat targets.txt); do 
    nmap -sV -sT $ip -oG target-enumeration.txt; done                   # File: target-enumeration.txt
                                                                        # Contents: Services | Ports 

