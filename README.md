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
 
