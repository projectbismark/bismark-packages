
CC=gcc

CFLAGS=-c -Wall -O3 -m32
LFLAGS=-m32

all: clean probeserver

prober: prober.o 
	$(CC) $(LFLAGS) prober.o wrappers.o tcp_client.o tcpserver.o tbdetect.o -o prober -lm

prober.o: prober.c
	$(CC) $(CFLAGS) prober.c tcp_client.c tcpserver.c wrappers.c tbdetect.c -lm

probeserver: probeserver.o
	$(CC) $(LFLAGS) probeserver.o wrappers.o tcpserver.o tcp_client.o tbdetect.o measflow.o -o shaperprobeserver -lm

probeserver.o: probeserver.c
	$(CC) $(CFLAGS) -DDSERVER probeserver.c wrappers.c tcpserver.c tcp_client.c tbdetect.c measflow.c -lm
tbtest: tbtest.o 
	$(CC) $(LFLAGS) tbtest.o wrappers.o tcp_client.o tcpserver.o tbdetect.o -o tbtest -lm

tbtest.o: prober.c
	$(CC) $(CFLAGS) tbtest.c tcp_client.c tcpserver.c wrappers.c tbdetect.c -lm

clean:
	rm -rf *.o prober probeserver shaperprobeserver
