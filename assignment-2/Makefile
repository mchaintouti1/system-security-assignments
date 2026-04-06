all: logger acmonitor test_aclog

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl 

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog

run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

# Target to run acmonitor with -m flag to list malicious users
malicious: acmonitor
	./acmonitor -m

# Target to run acmonitor with -i flag for a specified file
monitor-file: acmonitor
	@[ -n "$(file)" ] && ./acmonitor -i $(file) || echo "Please specify a file using 'make monitor-file file=<filename>'"

clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
