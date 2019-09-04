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
- [Credit and Resources](#credit-and-resources)


# Reconnaissance 1 
Locate and identify the target 
[![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")](#reconnaissance-2)  

__Scan Network For Targets__
``` bash
arp-scan -l
nmap -sn -oG sweep.txt -p [CIDR range of network] | grep "Status Up"
netdiscover -i [interface] -p
nmap -sP [target/CIDR Range]
```
# Reconnaissance 2  
Gather information on the network
[![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")](#reconnaissance-3)  

__Simple Port Scanning Enumeration__
``` bash 

nmap -T 5 [target]
nmap -p 1-65535 -sV -sS -T4 [target]
nmap -sV -sT -O -A -p- [target]
nmap -sU -p- [target]
nmap -Pn -p- [target]
nmap -sT -p 161 [target/254] -oG snmp_results.txt 
(then grep)

nmap -sU --script nbstat.nse -p 137 [target]

*sparta, add [target] to scope*

nc -nv [target][port]
nc -nlvp [target][port]
ncat [host] [port]
```
__Vulnerability Scanning__
``` bash
nmap -sc [target]
nmap --script discovery
nmap --script exploit
nmap --script "[port]-*" [target]
nmap --script-args=unsafe=1 --script smb-check-vulns.nse -p 445 [target]
nmap -p80,443 [Target or CIDR] -oG - | nikto.pl -h -

msfconsole

enum4linux -a [target]

ike-scan [target]
```

# Reconnaissance 3 
Dig deeper into particular services
[![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")](#weaponization)

__Web Server Enumeration__
``` bash
firefox [target]
firefox [target].robots
dirb http://[target]
nikto -h [target]
```

__NBT SMB Scan__
```bash
nbtscan -l [target]

smbclient -L //[target]
```

# Weaponization 
Turn recon into actionable exploit
[![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")](#delivery)

__Brute Force Services__
```bash
hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 
[target] [service] -V
#Hydra brute force against SNMP
hydra -P password-file.txt -v $ip snmp
#Hydra FTP known user and password list
hydra -t 1 -l admin -P /root/Desktop/password.lst -vV $ip ftp
#Hydra SSH using list of users and passwords
hydra -v -V -u -L users.txt -P passwords.txt -t 1 -u $ip ssh
#Hydra SSH using a known password and a username list
hydra -v -V -u -L users.txt -p "<known password>" -t 1 -u $ip ssh
#Hydra SSH Against Known username on port 22
hydra $ip -s 22 ssh -l <user> -P big\_wordlist.txt
#Hydra POP3 Brute Force
hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f $ip pop3 -V
#Hydra SMTP Brute Force
hydra -P /usr/share/wordlistsnmap.lst $ip smtp -V
#Hydra attack http get 401 login with a dictionary
hydra -L ./webapp.txt -P ./webapp.txt $ip http-get /admin
#Hydra attack Windows Remote Desktop with rockyou
hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/rockyou.txt rdp://$ip
#Hydra brute force a Wordpress admin login
hydra -l admin -P ./passwordlist.txt $ip -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'

* test common services pop3,ftp,ssh, smtp

```

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

# Credit and Resources
There are countless resources and people who deserve credit for their contributions to this playbook. 

+  Credit and Resources  
    -    [CheatSheet God](https://github.com/OlivierLaflamme/Cheatsheet-God/blob/master/Cheatsheet_PenTesting.txt)


[logo]: https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Next Play" 