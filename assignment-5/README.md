### Chaintouti Maria      2020030129
### Cheiladakis Nikolaos  2020030140

## Network traffic monitoring using the Packet Capture library
This project is a network packet capture and analysis tool that allows you to capture and analyze network traffic in real-time or from a saved packet capture file. It tracks TCP and UDP flows and computes statistics, such as the number of packets and bytes transferred, including retransmitted TCP packets.

### Prerequisites
- `libpcap`: required for packet capture
## For libpcap installation
Write in your Ubuntu terminal:
- `sudo apt update`
- `sudo apt-get install libpcap-dev`

### How to RUN
1. `make clean`: to clean and remove any previous executions or output files
2. `make`: to compile the source code (pcap_ex)

# For Onlive Capture
- `sudo ./pcap_ex -i <interface>`(e.g. eth0)
- `sudo ./pcap_ex -i <interface> -f "port ...."` (e.g. sudo ./pcap_ex -i eth0 -f "port 5353")
# For Offline Capture
- `./pcap_ex -r <filename.pcap>` (e.g. ./pcap_ex -r mirai.pcap)

The program will log packet details to two output files. The online_output.txt is for the online capture and the offline_output.txt is for the offline capture. The log includes the source IP, destination IP, source port, destination port, payload size and retransmission status(for TCP packets). In the terminal whenever the program is terminated(receiving a SIGINT signal (Ctrl+C), or when the program finishes processing an offline capture) will be printed the following statistics:
a. Total number of network flows captured
b. Number of TCP network flows captured
c. Number of UDP network flows captured
d. Total number of packets received
e. Total number of TCP packets received
f. Total number of UDP packets received
g. Total bytes of TCP packets received
h. Total bytes of UDP packets received

## Theoritical Questions
1. Yes, we can tell if a TCP packet is a retransmission by looking at its sequence number. If a packet has the same sequence number as a previously sent one, it is a retransmission. This happens when the sender doesn't receive an acknowledgment (ACK) for that segment, so it sends it again. Duplicate ACKs from the receiver can also indicate a missing packet and trigger retransmissions.

2. No, we cannot tell if a UDP packet is a retransmission. UDP is a connectionless protocol and it doesn't have sequence numbers or an acknowledgment mechanism like TCP, so it doesn't track packet order or retransmissions. The application layer would have to manage that if needed.