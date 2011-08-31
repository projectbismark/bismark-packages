CC=gcc
CFLAGS+=-c -Wall -O3 -fno-strict-aliasing
LDFLAGS+=-lpcap
SRCS=main.c packet_series.c flow_table.c
OBJS=$(SRCS:.c=.o)
EXE=bismark-passive

all: $(EXE)

$(EXE): $(OBJS) 
	$(CC) $(LDFLAGS) $(OBJS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

tests: packet_series.o tests.o
	$(CC) -lcheck packet_series.o tests.o -o tests
	./tests

clean:
	rm -rf $(OBJS) $(EXE)
