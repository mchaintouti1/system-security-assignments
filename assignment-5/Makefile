CC = gcc
CFLAGS = -Wall -g
LIBS = -lpcap

all: pcap_ex

pcap_ex: pcap_ex.c
	$(CC) $(CFLAGS) -o pcap_ex pcap_ex.c $(LIBS)

clean:
	rm -f pcap_ex
	rm -f offline_output.txt
	rm -f online_output.txt 