# Infrastructure/Operating Systems

### 1. What is the OSI model and what are its layers?

The OSI model is a conceptual framework that describes how communication happens between networked devices. It breaks down network communication into seven layers, each responsible for specific functions. 

Physical, Data Link, Network, Transport, Session, Presentation, Application

- Physical Layer:

Deals with the physical transmission of data (e.g., cabling, network interfaces).

Tools: `Wireshark` (captures signals).

- Data Link Layer:

Handles data transmission between two directly connected nodes, including error detection and correction.

Framing, MAC addressing, switches.

Protocols: Ethernet, ARP.

- Network Layer:

Responsible for routing data packets between networks, using logical addresses (e.g., IP addresses).

Protocols: IP, ICMP.

- Transport Layer:

Provides reliable and ordered data delivery between applications, including error checking and flow control.

Reliable data delivery (TCP/UDP).

Tools: `nmap` (port scanning).

- Session Layer:

Manages communication sessions between applications, including authentication, security, and connection establishment.

Manages connections (establish, maintain, terminate).

Example: NetBIOS.

- Presentation Layer:

Handles data formatting and conversion, ensuring applications understand the data being transmitted.

- Application Layer:

Provides the interface for applications to access network services, including protocols like HTTP and FTP.

User-facing protocols (HTTP, FTP, SMTP).

Tools: `Burp Suite` (web app testing).

### 2. TCP/IP model

The TCP/IP model is a more practical model with four layers that reflects the protocols used on the internet. 

- Network Interface/Access (or Physical) Layer:

This layer deals with the physical transmission of data between devices, including the network cable, hardware, and data link protocols.

Combines Physical + Data Link.

Protocols: Ethernet, Wi-Fi.

- Internet Layer: (OSI Network layer)

This layer is responsible for addressing and routing data packets across the network, using protocols like IP (Internet Protocol).

IP addressing, routing.

Protocols: IPv4, IPv6.

- Transport Layer: (OSI Transport layer)

This layer ensures reliable and ordered delivery of data between two applications, often using protocols like TCP (Transmission Control Protocol).

TCP (reliable) and UDP (unreliable).

- Application Layer: (Layers 5–7 in OSI)

This layer provides the interface for applications to access network services, like HTTP (for web browsing) or SMTP (for email). 

Merges Session, Presentation, and Application.

Protocols: HTTP, DNS, SSH.

### 3. What is the difference between TCP and UDP?

TCP and UDP are both transport layer protocols that transmit data over a network, but they differ in their approach to reliability and speed. TCP is connection-oriented, reliable, and ordered, while UDP is connectionless, unreliable, and unordered. 

### 4. ARP

The Address Resolution Protocol (ARP) is a networking protocol that resolves IP addresses to MAC addresses on a local network. It's essential for communication because devices on a network need to know the hardware (MAC) address of their destination to transmit data, while they often communicate using IP addresses. 

IP addresses to MAC addresses

### 5. DNS

The Domain Name System (DNS) is the internet's phone book, translating human-readable domain names (like example.com) into machine-readable IP addresses (like 192.168.1.1). 

### 6. What are some of the most common services and what ports do they run on?

| Service          | Protocol | Port  | Use Case                          |
|------------------|----------|-------|-----------------------------------|
| **HTTP**         | TCP      | 80    | Unencrypted web traffic           |
| **HTTPS**        | TCP      | 443   | Encrypted web traffic (TLS/SSL)   |
| **SSH**          | TCP      | 22    | Secure remote administration. Secure Shell      |
| **FTP**          | TCP      | 21    | File transfer (control). File Transfer Protocol         |
| **FTP-Data**     | TCP      | 20    | File transfer (data)              |
| **SMTP**          | TCP      | 25    | Outgoing email routing; Simple Mail Transfer Protocol            |
| **POP3**         | TCP      | 110   | Email retrieval; Post Office Protocol 3                   |
| **IMAP**         | TCP      | 143   | Email server management. Internet Message Access Protocol           |
| **DNS**          | TCP/UDP  | 53    | Domain name resolution            |
| **DHCP**         | UDP      | 67/68 | IP address assignment. Dynamic Host Configuration Protocol             |
| **RDP**          | TCP      | 3389  | Windows remote desktop. Remote Desktop Protocol            |
| **MySQL**        | TCP      | 3306  | Database queries                  |
| **MSSQL**        | TCP      | 1433  | Microsoft SQL Server              |
| **SMB**     | TCP      | 445   | Windows file/printer sharing; Server Message Block     |
| **LDAP**         | TCP/UDP  | 389   | Directory services (e.g., AD)     |
| **Kerberos**     | TCP/UDP  | 88    | Network authentication            |
| **SNMP**         | UDP      | 161   | Network monitoring. Simple Network Management Protocol               |
| **NTP**          | UDP      | 123   | Time synchronization. Network Time Protocol              |
| **SIP**          | TCP/UDP  | 5060  | VoIP calls. Session Initiation Protocol                       |
| **RTSP**         | TCP/UDP  | 554   | Video streaming. Real Time Streaming Protocol              |
| **WinRM** 	| TCP |  operate on port 5985 (for HTTP) or port 5986 (for HTTPS) | Windows Remote Management |
### 7. RDP

RDP, or Remote Desktop Protocol, is a proprietary protocol developed by Microsoft that allows users to connect to and control a remote computer or server over a network. It provides a graphical interface, allowing users to interact with the remote desktop as if they were physically in front of it. 

### 8. What is a MAC address?

A MAC (Media Access Control) address is a unique identifier, like a digital fingerprint, assigned to each network interface card (NIC) on a device connected to a network. It's a 12-digit hexadecimal number that allows devices to communicate on the local network. 

### 9. What is a firewall and how does it work?

A firewall is a network security device, either hardware or software, that monitors and controls network traffic based on pre-defined security rules. It acts as a gatekeeper, deciding which data packets are allowed to pass through and which are blocked, protecting a network from unauthorized access and potential threats. 

### 10. What is the difference between an IDS and an IPS?

An Intrusion Detection System (IDS) monitors network traffic and system activities for suspicious behavior, generating alerts when threats are detected. An Intrusion Prevention System (IPS) goes a step further by actively blocking or mitigating identified threats in real-time. In essence, IDS is a passive alerting system, while IPS is an active prevention system. 

### 11. What are honeypots?

Honeypots are decoy systems or applications designed to attract cyberattackers, allowing security professionals to study their behavior and tactics. They act as bait, luring attackers into a controlled environment where their actions can be monitored and analyzed. By understanding how attackers behave, security teams can improve their defenses and prevent real attacks. 

### 12. What is the difference between encoding, hashing and encryption?

Encoding, hashing, and encryption are related data handling techniques, but they serve different purposes. Encoding is a reversible process that converts data from one format to another, like converting text to a different character set. Hashing creates a fixed-size fingerprint of data, ensuring integrity but not reversible. Encryption transforms data into an unreadable format using a key, providing confidentiality and reversibility. 

### 13. Name a few type of encoding, hash and encryption

**Encoding:**

- ASCII Encoding: A standard for representing text as numbers, using 128 characters.

- Unicode Encoding: A broader standard that represents a wide range of characters, including those in many languages.

- Base64 Encoding: A way to encode binary data into a text format, often used for transferring data over channels that only handle text.

- URL Encoding: A process that converts special characters in a URL into a format that can be understood by web browsers and servers. 

**Hashing:**

- MD5: A widely used hashing algorithm, though it's now considered vulnerable for some applications. 

- SHA-256: A cryptographic hash function that generates a 256-bit hash value, used in various security protocols. 

- RIPEMD-160: Another hash algorithm developed in Belgium. 

**Encryption:**

- Symmetric Encryption (e.g., Triple DES): Uses the same key for encryption and decryption.

- Asymmetric Encryption (e.g., RSA): Uses different keys for encryption and decryption. 

- Hybrid Encryption: Combines symmetric and asymmetric encryption. 

- Blowfish: A symmetric encryption algorithm known for its speed and flexibility. 

- Twofish: Another symmetric encryption algorithm, also known for its security and speed. 

### 14. Why some hash algorithms can be cracked

Some hash algorithms can be cracked due to weaknesses that allow attackers to find collisions or recover the original data (preimage) faster than theoretically possible. These weaknesses can arise from algorithm design flaws or mathematical vulnerabilities that are exploited by attackers. 

### 15. What is salting and what is it used for in cyber security?

In cybersecurity, "salting" refers to adding a unique, random string (the "salt") to data, typically passwords, before hashing them. This process enhances security by making it more difficult for attackers to crack passwords using precomputed tables like rainbow tables. Salting ensures that even if two users have the same password, their hashed values will differ because of the unique salt added. 

### 16. What is the fastest way to crack hashes?

The fastest way to crack hashes depends on the hash type, hardware, and techniques used. 

Firstly, identify which hashing algorithm it is using.

### 17. Difference between symmetric and asymmetric encryption?

Symmetric and asymmetric encryption are two fundamental types of encryption with distinct approaches to key management. Symmetric encryption uses a single key for both encryption and decryption, making it efficient but reliant on secure key exchange. Asymmetric encryption, on the other hand, employs a pair of keys (a public key for encryption and a private key for decryption), simplifying key distribution and enhancing security. 

### 18. In what format are Windows and Linux hashes stored?

**Windows primarily uses NTLM and NTLMv2 for authentication**, but modern systems rely on more secure formats:

a. NTLM (NT LAN Manager)

Algorithm: MD4 (weak, deprecated but still used in older systems).

Format: NTLM = MD4(UTF-16-LE(password))

b. NTLMv2 (More Secure)

Uses a challenge-response mechanism with HMAC-MD5.

Not stored directly but derived during authentication.

c. Kerberos (Active Directory)

Uses AES-256 or RC4-HMAC (older systems) for ticket-based auth.

Hashes stored in the NTDS.dit database (extracted via secretsdump.py).

d. Modern Windows (Post-2008)

Windows 10/11 + Server 2016+ default to:

PBKDF2 + AES (for Credential Guard).

DPAPI (for encrypting user secrets).

**Linux Password Hashes**

Linux stores hashes in `/etc/shadow` (with `/etc/passwd` storing metadata). Common formats:

a. SHA-256/SHA-512 (Modern Default)

Format: `$5$salt$hash` (SHA-256) or `$6$salt$hash` (SHA-512).

b. Other Linux Formats

bcrypt: `$2a$`, `$2b$`, `$2y$` (common for web apps).

PBKDF2: `$pbkdf2-sha256$`

### 19. What are cron jobs/scheduled tasks?

Cron jobs (or scheduled tasks) are tasks that are automatically executed by a system at specified intervals or times. They are commonly used for automating repetitive actions like system maintenance, backups, and sending periodic reports. 

### 20. Where are cron jobs stored in Windows and Linux?

In Windows, scheduled tasks, which are the equivalent of cron jobs in Linux, are typically stored as XML files in the `%WINDIR%\\System32\\Tasks` directory. Individual user-level scheduled tasks (or jobs) are stored in `%HOME_DIR%\\AppData\\Local\\Microsoft\\Windows\\PowerShell\\ScheduledJobs`. 

In Linux, cron jobs are managed through the crontab utility and stored in different locations depending on the type of job:

User-specific crontab files: These are usually located in `/var/spool/cron/crontabs`, with each file named after the user account that created it. `

System-wide cron jobs: These are often found in `/etc/crontab` or within directories under `/etc/cron.d` (e.g., `/etc/cron.daily`, `/etc/cron.hourly`, etc.).

System daemons and applications: May add cron tasks to the `/etc/cron.d` directory. 

### 21. What are the different package managers used in Linux and where are they used?

In Linux, package managers are tools that automate the installation, update, and removal of software packages. Commonly used package managers include **APT** (Debian-based systems like Ubuntu), **YUM/DNF** (Red Hat-based systems like CentOS and Fedora), **Pacman** (Arch Linux), and **Portage** (Gentoo). 

### 22. Describe the permission system used in Linux file systems.


|#	|Permission	|Binary	|Meaning |
|---|-----------|-------|--------|
|7	|rwx	|111	|Read + Write + Execute |
|6	|rw-	|110	|Read + Write |
|5	|r-x	|101	|Read + Execute |
|4	|r--	|100	|Read only |
|0	|---	|000	|No permissions |

Categories:

- Owner (u): The user who created the file or directory.
- Group (g): A group of users who share access to the file or directory.
- Others (o): All other users on the system. 

```bash
# Owner: 6 (R+W) Group and Others: 4 (R)
chmod 644 sample.file
```

## 23. What are SUID and sudo?

SUID (Set User ID)

`SUID` = "Run this one program as owner."

`sudo` (Superuser Do)

`sudo` = "Let me temporarily act as root."

Always audit SUID binaries (`find / -perm -4000`) and limit `sudo` access via `/etc/sudoers`. 

### 24. What is Kerberos and how does it perform authentication?

Kerberos is a network authentication protocol that provides secure authentication between clients and servers by using tickets and a Key Distribution Center (KDC). It avoids transmitting passwords over the network, using encryption and session keys to verify user and server identities. Kerberos is stateless, meaning it doesn't require the server to remember user information between requests. 

### 25. What is the difference between WEP, WPA and WPA2?

WEP, WPA, and WPA2 are different Wi-Fi security protocols used to encrypt data transmitted over wireless networks. WEP is the oldest and least secure, while WPA and WPA2 offer significant improvements in encryption and authentication. WPA2 is currently considered the most secure of the three. 

WEP (Wired Equivalent Privacy):

- Outdated and insecure: WEP was the original Wi-Fi security protocol but has been shown to be vulnerable to attacks.

- Static keys: WEP uses a single, static key for encryption, making it easy to crack. 

- Low security: WEP offers minimal security and is not recommended for modern networks. 

WPA (Wi-Fi Protected Access):

- Improved security: WPA was introduced as an interim solution to WEP's vulnerabilities, offering stronger encryption and dynamic key generation. 

- TKIP encryption: WPA uses Temporal Key Integrity Protocol (TKIP) for encryption. 

- Still vulnerable: While better than WEP, WPA is also susceptible to certain attacks and is generally superseded by WPA2. 

WPA2 (Wi-Fi Protected Access II):

- Industry standard: WPA2 is widely considered the standard for securing wireless networks. 

- AES encryption: WPA2 uses Advanced Encryption Standard (AES) with CCMP (Counter Mode Cipher Block Chaining Message Authentication Code) for strong encryption and data integrity.

- Improved authentication: WPA2 utilizes a 4-way handshake for establishing secure encryption keys. 

- Still vulnerable to some attacks: While secure, WPA2 has been found to have vulnerabilities like the KRACK attack, which have been patched. 

In summary, WEP is outdated and insecure, WPA offers better security but is also vulnerable, and WPA2 is the current industry standard for strong Wi-Fi security. 

### 26. What is WPS? Why is it insecure?

WPS (Wi-Fi Protected Setup) is a feature that simplifies connecting devices to Wi-Fi networks without manually entering the network password. It is designed for ease of use, especially for home and small office networks. However, WPS has security vulnerabilities, making it susceptible to brute-force attacks that can compromise network security. 

Brute-force attacks:

WPS uses a PIN code that can be cracked by brute-force attacks, allowing unauthorized access to the network. 

PIN vulnerability:

The PIN is typically eight digits long, and a PIN method can be susceptible to brute-force attacks. 

KRACK vulnerability:

The KRACK vulnerability exposed a weakness in the WPA2 encryption, further increasing the risk associated with WPS. 

Default PINs:

Some routers may use default PINs, making them even easier to crack. 








