#!/bin/python3

# Sockets

import socket

HOST = "127.0.0.1"
PORT = 7777 # need to run command(Kali) `nc -nvlp 7777` to open listening on port 7777, in Mac os run command `nc -vlp 7777`

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # af_inet is ipv4, sock_stream is a port
s.connect((HOST, PORT))