#!/bin/bash 
# A simple script that scans a text file of IPS and with a text file full of nmap vulns

for vuln in $(cat vulns.txt); do
    for ip in $(cat ips.txt); do 
        nmap -v --script=$vuln $ip;done;done 