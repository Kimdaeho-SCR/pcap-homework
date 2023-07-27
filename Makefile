LDLIBS += -lpcap

all: pcap-homework

pcap-test: pcap-homework.c

clean:
	rm -f pcap-homework *.o
