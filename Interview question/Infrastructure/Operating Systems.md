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