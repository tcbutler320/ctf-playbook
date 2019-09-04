![](/images/ctf-playbook.png)

# CTF Playbook Instructions
CTF playbook is my personal playbook for enumeration and attack techniques. The techniques here are meant to be loud and clumsy. No fancy obfuscation here, just smash and grab the flag

The playbook will loosely follow Lockheed Martin's [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)

Start enumerating your target with plays in the playbook. When you've successfully completed a play, you can select the arrow image to be taken to the next link in the kill chain  

Next Play Icon:  

![alt text][logo]  

# Index
- [CTF Playbook Instructions](#ctf-playbook-instructions)
- [Index](#index)
- [Reconnaissance 1](#reconnaissance-1)
- [Reconnaissance 2](#reconnaissance-2)
    - [nmap](#nmap)
    - [ncat](#ncat)
    - [Web Server Enum](#web-server-enum)
- [Reconnaissance 3](#reconnaissance-3)
- [Weaponization](#weaponization)
- [Delivery](#delivery)
- [Exploitation](#exploitation)
- [Reconnaissance 4](#reconnaissance-4)
- [Command and GitTroll (CG2)](#command-and-gittroll-cg2)
- [Priviledge Escelation](#priviledge-escelation)
- [Actions on Objectives](#actions-on-objectives)
- [Celebration](#celebration)
- [Documentation](#documentation)


# Reconnaissance 1 
Locate and identify the target 
[![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")](#reconnaissance-2)
``` bash
arp-scan -l
nmap -sn -oG sweep.txt -p [CIDR range of network] | grep "Status Up"
```
# Reconnaissance 2  
Gather information on the network
[![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")](#reconnaissance-3)
### nmap
``` bash 
nmap -T 5 [target]
nmap -sV -sT -O -A -p- [target]
nmap -sU -p- [target]
```
### ncat
``` bash 
nc -nv [target][port]
nc -nlvp [target][port]
```
### Web Server Enum
``` bash 
firefox [target]
nc -nlvp [target][port]
dirb http://[target]
```
# Reconnaissance 3 
Expose potential vulnerabilities 

+  __Nmap NSE Scripting Engine__:
    +    __Run all default scripts__: $ nmap -sc [target]
    +    __Run all discovery scripts__: $ nmap --script discovery [target]
    +    __Run all exploit scripts__: $ nmap --script exploit [target]
    +    __Use all Scripts for a service__: $ #nmap --script "[port]-*" [target]
    +    __SMB-OS-Discovery__: $ 
    +    __Look at Help Script__: $ nmap --script-help script
+  __Searchsploit__: $ searchsploit [services]
+  __Metasploit__:
    +    __Launch Metasploit Console__: $ msfconsole 
    +    __Search for exploits__: $ search [service]
+  __NBT_Scan__: $ $ nbtscan -l [target]
+  __Enum4Linux__: $ enum4linux -a [target]

# Weaponization 
Successful intrusion into network & target

+  __Metasploit__:
    +    __Select Exploit__: $ use [exploit]
    +    __See Options__: $ show options
    +    __Set Options__: $ set [option name] [option value]
    +    __Run Exploit__: $ run
    +    __Check for session__: $ session -ls

# Delivery 

# Exploitation 

# Reconnaissance 4
Gather additional information previously unavailable

+  __Secret Sauce__:
    +    __Find what CTF Creator Did__: $ history 
    +    __

# Command and GitTroll (CG2) 

# Priviledge Escelation 
Escelate to root priviledge

+  __Metasploit__:
    +    __If meterpreter shell open__: $ getsystem

# Actions on Objectives 

# Celebration 
Victory dance

+  __If CTF has a webserver__: 
    +    __Rewrite website with your personal victory site__: $

# Documentation
Documentation is important, as you will need to come back frequently to things you've found. 

+  __CherryTree__: $
+  __KeepNote__: $
+  __TextPad__: $



[logo]: https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Next Play" 