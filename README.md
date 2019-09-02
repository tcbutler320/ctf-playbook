# CTF-Playbook

![](/images/ctf-playbook.png)

My personal CTF playbook for enumeration and attack techniques. This playbook is different then a pentester's playbook, as these techniques are meant to be loud and clumsy. No fancy obfuscation here, smash and grab. 

## Index
- [CTF-Playbook](#ctf-playbook)
  - [Index](#index)
  - [Initial Recon](#initial-recon)
  - [Network Mapping](#network-mapping)
  - [Finding Vulnerabilities](#finding-vulnerabilities)
  - [Breach](#breach)
  - [Internal Mapping](#internal-mapping)
  - [Capturing Flags](#capturing-flags)
  - [Priviledge Escelation](#priviledge-escelation)
  - [Celebration](#celebration)
  - [Documentation](#documentation)


## Initial Recon 
Locate and identify the target

+  __Find ipv-4 addresses__: $ arp-scan -l 
+  __Find your ipv-4 address__: $ ifconfig
   +    __Sweep Network for Live Hosts__:$ nmap -sn -oG sweep.txt -p [CIDR range of network] | grep "Status Up" 

## Network Mapping 
Gather information on the network

+  __Basic Target Enunmeration__: 
   +    __Quick Nmap Scan__: $ nmap -T 5 [target]
   +    __Secondary Nmap Scan__: $ nmap -sV -sT -O -A -p- [target]
   +    __UDP Nmap Scan__: $ nmap -sU -p- [target]


+  __Playing with ports and Ncat__:
    +    __Connect to a port__: $ nc -nv [target][port]
    +   __Connect and listen to a port__: $ nc -nlvp [target][port]

After open ports have been found, increase the intensity of scans and focus on service-specefic mapping

+  __Web Server Enumeration__:
   +    __Open Hosted Website__: enter ipv-4 in browser and do a manual search 
   +    __Dirb__: $ dirb http://[target]

## Finding Vulnerabilities 
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

## Breach 
Successful intrusion into network & target

+  __Metasploit__:
    +    __Select Exploit__: $ use [exploit]
    +    __See Options__: $ show options
    +    __Set Options__: $ set [option name] [option value]
    +    __Run Exploit__: $ run
    +    __Check for session__: $ session -ls

## Internal Mapping 
Gather additional information previously unavailable

## Capturing Flags 
Capture and document flags

## Priviledge Escelation 
Escelate to root priviledge

## Celebration 
Victory dance

## Documentation



