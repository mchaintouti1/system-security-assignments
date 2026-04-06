# System Security Assignments
This repository contains coursework assignments related to system security. Each folder contains a standalone assignment with its own code and instructions.

## Assignment Overview
### Assignment 1
This assignment consists of two parts. The first one demonstrates a simple Elliptic Curve Diffie-Hellman (ECDH) Key Exchange using the 
libsodium(https://libsodium.gitbook.io/doc/) library. It allows two parties to securely establish a shared secret over an insecure 
communication channel.
The second part implements RSA key-pair generation algorithm using GNU Multiple Precision Arithmetic Library(GMP). 
The program can generate key pairs, encrypt, decrypt files and analyze performance for different key lengths.

### Assignment 2
This project provides a file access monitoring and logging system, which records all file access attempts and allows for analysis of 
unauthorized access attempts and file modifications by users.

### Assignment 3
A Python-based utility designed for signature-based scanning, recursive directory monitoring, and suspicious file quarantine.
Calculating multiple hashes (SHA1, SHA256, SHA512) for a single file provides a "Multi-Hash Validation"[cite: 5]. This prevents hash
collisions—where two different files produce the same hash—and ensures that even if a malware author manages to spoof one hash type, 
the others will likely reveal the discrepancy, significantly hardening the detection process

### Assignment 5
This project is a network packet capture and analysis tool that allows you to capture and analyze network traffic in real-time or from 
a saved packet capture file. It tracks TCP and UDP flows and computes statistics, such as the number of packets and bytes transferred, 
including retransmitted TCP packets.

### Assignment 6
This project implements a simple firewall mechanism using a Bash script to block connections based on domain names and IP addresses.
The script utilizes iptables and ip6tables to configure, save, load, reset, and list firewall rules for IPv4 and IPv6 traffic.

### Assignment 7
This project contains a Python script designed to craft and export custom network traffic into a .pcap file format using the Scapy library. 
The generated traffic simulates various network activities, ranging from standard student identification packets to suspicious scanning and 
malicious behavior.

### Assignment 8
The project involves exploiting the "Greeter" program to grade with more than 6 and spawn a terminal shell. Additionally, in the 
second task includes bypassing  DEP (Data Execution Prevention) using a return-to-libc attack on the "SecGreeter" program.

## 🛠️ Topics Covered
- Cryptography
- Secure systems
- Vulnerability analysis
- Network / system attacks
