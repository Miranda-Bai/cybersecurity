# General/basic interview questions

https://github.com/kh4sh3i/Penetration-Testing-Interview-Questions?tab=readme-ov-file#infrastructureoperating-systems

https://github.com/redteamcaptain/Pentesting-Interview-Questions

### 1. What’s the main goal of cyber security?

The main goal of cybersecurity is to protect computer systems, networks, and data from unauthorized access, damage, or theft. It aims to ensure the confidentiality, integrity, and availability of information by preventing cyber threats like hacking, malware, and phishing.

### 2. TCP & UDP

TCP: Transmission Control Protocol, It operates at the transport layer (layer 4) of the OSI model and works in conjunction with IP (Internet Protocol). 

UDP: User Datagram Protocol, is a lightweight and fast communication protocol used in computer networking.

### 3. You find a potential DDoS vulnerability, do you attempt to exploit it?

Document the Vulnerability

Report Responsibly

- If in a pentest: Report to the client with remediation steps.

- If in a bug bounty: Submit via the program’s platform (e.g., HackerOne, Bugcrowd).

- If in production (no permission): Contact the organization’s security team anonymously if necessary.

### 4. You find PII (Personally Identifiable Information) on a file share in the internal network, do you screenshot it to prove what you found in the report?

No, you should not screenshot or copy Personally Identifiable Information (PII)—even for proof in a report. Instead, document its existence without storing or exfiltrating the actual data.

### 5. How do you go about taking notes during your assessments?

### 6. You want to include evidence of you cracking a password hash in your report, how do you present it (screenshot, terminal output, etc.)?

When including evidence of cracking a password hash in a penetration test report, balance proof of exploitability with responsible disclosure.

**Do Include**

Hash type (e.g., NTLM, SHA-256, bcrypt).

Cracking tool used (e.g., hashcat, John the Ripper).

Command/configuration (mask sensitive inputs).

Terminal output (redacted passwords).

Performance metrics (e.g., Speed: 500 MH/s).

**Avoid**

Plaintext passwords (even if weak).

Full hashes (unless required by scope).

Sensitive usernames (e.g., administrator → admin[REDACTED]).

```bash
[+] Hash: b4b9b02e6f09a9bd760f388b67351e2b (NTLM)  
[+] Cracked: ******** (6 chars, dictionary-based)  
[+] Time: 2h 15m (GPU: RTX 4090, Speed: 1200 MH/s)  
```

Partially Masked Screenshot

Hashcat/JTR Command (Sanitized)

### 7. What are you doing to keep current?

To stay current with the rapidly evolving cybersecurity landscape, I employ a multi-faceted approach that combines continuous learning, real-time threat monitoring, and practical application of emerging trends. Here’s how I ensure I’m up-to-date:

**a. Tracking Industry Reports and Forecasts**

- IBM (AI-driven threats, quantum computing risks) 

- CrowdStrike (adversary tactics, malware-free attacks) 

- SentinelOne (DDoS vulnerabilities, zero-trust adoption) 

- World Economic Forum (geopolitical impacts on cyber threats)

**b. Monitoring Real-Time Threat Intelligence**

- CISA alerts (e.g., OT/ICS vulnerabilities).

- CrowdStrike’s Adversary Universe (e.g., nation-state tactics like China’s LIMINAL PANDA).

- Forbes/Accenture analyses (e.g., healthcare breaches, supply chain attacks)

**c. Hands-On Practice with Emerging Tools**

- AI/ML for defense: Testing tools like Splashtop’s zero-trust remote access.

- Penetration testing: Simulating AI-driven social engineering (e.g., deepfake voice scams).

- Quantum-safe cryptography: Experimenting with NIST’s post-quantum algorithms.

**d. Participating in Communities and Training**

- CISA’s Cyber Range Training for incident response drills.

- Vendor webinars (e.g., Google Cloud’s threat forecasts).

- Red team/blue team exercises to counter malware-free attacks (79% of detections in 2024)

**e. Implementing Best Practices Proactively**

- Zero-trust adoption: Micro-segmentation for hybrid workforces.

- Secure-by-design principles: Embedding security in DevOps (e.g., container vulnerabilities).

- Employee training: Combatting insider threats (up 150% in hybrid environments).

### 8. What are the phases in the penetration testing lifecycle? (recon, scan,..)

The penetration testing lifecycle is a structured approach to identifying and exploiting vulnerabilities while minimizing risks. Here’s a breakdown of the key phases, aligned with industry standards like NIST SP 800-115 and PTES (Penetration Testing Execution Standard):

**a. Pre-Engagement (Planning & Scoping)**

Objectives: Define goals, rules of engagement (ROE), and legal agreements.

Deliverables:

- Signed contracts (including authorization).

- Scope document (IPs, apps, excluded systems).

Tools: Meetings, questionnaires, legal templates.

**b. Reconnaissance (Information Gathering)**

Passive Recon

- Gather data without direct interaction:

    - WHOIS, DNS records, social media (LinkedIn, GitHub).

    - Tools: theHarvester, Maltego, Shodan.

Active Recon

- Direct interaction with targets:

    - Port scanning (nmap), subdomain brute-forcing (gobuster).

    - Banner grabbing (netcat), SNMP walks.

**c. Scanning & Enumeration**

- Vulnerability Scanning:

    - Tools: Nessus, OpenVAS, Nmap scripts (--script vuln).

- Service Enumeration:

    - SMB (smbclient), RPC (rpcinfo), HTTP (dirb, nikto).

- Credential Testing:

    - Default logins, exposed databases (e.g., Redis, MongoDB).

**d. Exploitation**

Goal: Gain initial access using identified vulnerabilities.

Methods:

- Public exploits (Metasploit, Exploit-DB).

- Custom payloads (e.g., msfvenom for shellcode).

- Password cracking (hashcat, John the Ripper).

Example: Exploiting Log4j (CVE-2021-44228) via JNDI injection.

**e. Post-Exploitation (Privilege Escalation & Persistence)**

Local Privilege Escalation:

- Linux: SUID/GUID abuse (find / -perm -4000).

- Windows: SeImpersonatePrivilege (PrintSpoofer).

Persistence:

- Backdoors (webshells, cron jobs, registry keys).

- Credential harvesting (mimikatz, LaZagne).

**d. Lateral Movement**

Pivoting: Use compromised hosts to access internal networks.

Tools: `Chisel`, `SSH tunneling`, `Metasploit’s autoroute`.

Pass-the-Hash: Reuse credentials across systems.

Kerberoasting: Attack Active Directory (`Rubeus`).

**e. Reporting & Remediation**

Executive Summary: Business impact in non-technical terms.

Technical Findings:

- Vulnerability details (CVSS scores).

- Proof of concept (redacted screenshots, commands).

Remediation Steps: Patch guidance, configuration fixes.

Tools: Dradis, Serpico, custom Markdown templates.

**f. Cleanup (Optional)**

Remove shells, logs, and artifacts (if agreed in ROE).

Verify no unintended damage occurred.

```mermaid
graph LR
A[Pre-Engagement] --> B[Reconnaissance]
B --> C[Scanning]
C --> D[Exploitation]
D --> E[Post-Exploitation]
E --> F[Lateral Movement]
F --> G[Reporting]
G --> H[Cleanup]
```

### 9. What types of penetration testing assessments are there? (Internal/External Infrastructure Penetration Testing / Wireless/Web/mobile)

### 10. Difference between active and passive reconnaissance ?

The main difference between active and passive reconnaissance is the level of interaction with the target system. Passive reconnaissance involves gathering information from publicly available sources without directly interacting with the target, making it stealthier and less likely to be detected. Active reconnaissance, on the other hand, actively interacts with the target, such as through scanning or probing, which can be detected and may create network traffic. 