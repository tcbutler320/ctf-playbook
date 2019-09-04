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
netdiscover -i [interface] -p
```
# Reconnaissance 2  
Gather information on the network
[![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")](#reconnaissance-3)

``` bash 
nmap -T 5 [target]
nmap -sV -sT -O -A -p- [target]
nmap -sU -p- [target]
nmap -Pn -p- [target]

*sparta, add [target] to scope*

nc -nv [target][port]
nc -nlvp [target][port]

firefox [target]
firefox [target].robots
dirb http://[target]
```
# Reconnaissance 3 
Expose potential vulnerabilities 
[![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")](#weaponization)
``` bash
nmap -sc [target]
nmap --script discovery
nmap --script exploit
nmap --script "[port]-*" [target]

msfconsole

nbtscan -l [target]
enum4linux -a [target]
```
# Weaponization 
Turn recon into actionable exploit
[![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")](#delivery)

+  __Metasploit__:
    +    __Select Exploit__: $ use [exploit]
    +    __See Options__: $ show options
    +    __Set Options__: $ set [option name] [option value]
    +    __Run Exploit__: $ run
    +    __Check for session__: $ session -ls

# Delivery 
Deliver payload to the target
[![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")](#exploitation)

# Exploitation 
Successful gain unauthorized access
[![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")](#reconnaissance-4)

# Reconnaissance 4
Gather additional information previously unattainable
[![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")](#command-and-gittroll-(cg2))

``` bash
$ history 
strings [filename.extension]
file [filename.extension]
```

# Command and GitTroll (CG2) 
Establish a lasting backdoor 
[![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")](#priviledge-escelation)

# Priviledge Escelation 
Escelate to root priviledge
[![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")](#actions-on-objectives)

``` bash
meterpreter: $ getsystem
```

# Actions on Objectives 
Gather necessary CTF documentation (flags)
[![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")](#celebration)

# Celebration 
Add your mark
[![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")](#documentation)


# Documentation
Documentation is important, as you will need to come back frequently to things you've found. 

+  __CherryTree__: $
+  __KeepNote__: $
+  __TextPad__: $



[logo]: https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Next Play" 