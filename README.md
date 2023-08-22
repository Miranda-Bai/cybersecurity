# nmap
nmap -v -A -sV [ip/ip range]
nmap -p 80,443 --open [ip/ip range]

Asks Nmap to choose 100,000 hosts at random and scan them for web servers (port 80). Host enumeration is disabled with -Pn since first sending a couple probes to determine whether a host is up is wasteful when you are only probing one port on each target host anyway.
nmap -v -iR 100000 -Pn -p 80,443

nmap -A -T4 [scanme.nmap.org]

# nikto
http scan
nikto -h [web server ip]
https scan
nikto -h [web server ip] -ssl 

# Network Sniffing (SSID) 

# Metasploit

# Acunetix

# Airgeddon

# John the Ripper
Brute-force tool that cracks hashed passwords
Auto-detects the hash function and variant
Can use dictionary attacks with third party wordlists

# BURPsuite professional

# WireShark

# TOR Browser
[TOR](https://www.torproject.org/): The Onion Router
ISP: Internet Service Provider
https://browserleaks.com/

# Ransomware
1. Locker ransomware
2. Crypto-ransomware
3. Scareware

The website that provides free decryption tools for 150+ ransomware variants: https://www.nomoreransom.org/

# Malware
Malware: Malicious software
1. Intrusion
2. Execution
3. Persistence
4. Exploitation
5. Malicious activities
6. Concealment
7. Damage or profit
## Types of malware
1. Virus: A computer virus is a form of a computer program that replicates itself on execution. They alter different computer programs by attaching its own code.
    * The program contains a search routine, to locate new files or data to infect in the system.
    * The program also contains a copy routine, to copy itself into the targeted file by search routine.
2. Worm
3. Trojan Horse: Trojan looks like certified software but harms the system on installation. They create a backdoor in the system, and through this the hacker steals our information.
    * Falling for phishing attacks or other social sites attachments or visiting uncertified websites.
    * Embedded in software or executable files and create unauthorised access.
4. Ransomware
5. Spyware
6. Adware

# IDS Firewalls and Honeypots
## IDS (Intrusion Detection System)
An IDS is a security tool that monitors network traffic and system activity for signs of unauthorized access, malicious activities, or other security breaches. It works by analyzing network packets, system logs, and other data to detect patterns that might indicate an ongoing or attempted attack. IDS can be categorized into two types:

* Network-based IDS (NIDS): Monitors network traffic in real-time, analyzing data packets to identify suspicious or malicious behavior.
* Host-based IDS (HIDS): Monitors the activities on individual hosts or devices, looking for signs of compromise or intrusion.
## Firewalls
A firewall is a network security device or software that acts as a barrier between a trusted internal network and untrusted external networks (like the internet). Firewalls enforce access control policies by allowing or blocking network traffic based on defined rules. They can be configured to filter traffic based on various attributes such as IP addresses, port numbers, and protocols. Firewalls can be implemented at the network level (hardware firewalls) or at the software level (software firewalls).
## Honeypots
A honeypot is a decoy system or network that is set up to attract and monitor malicious activity. Honeypots are intentionally designed to appear vulnerable or interesting to attackers, luring them away from the actual production systems. Honeypots can be used for several purposes:

* Detection and Analysis: Honeypots capture and log the activities of attackers, providing valuable insights into their techniques and tactics.
* Diversion: By diverting attackers' attention to a honeypot, organizations can protect their actual systems and data.
* Research: Security professionals and researchers can study attackers' behavior and learn about emerging threats by analyzing honeypot data.

**IDS:** Monitors network and system activities for signs of intrusion or malicious behavior.
**Firewalls:** Control and filter network traffic based on predefined rules to prevent unauthorized access.
**Honeypots:** Attract and monitor attackers to gather information about their activities and tactics.