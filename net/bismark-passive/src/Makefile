CC=gcc
CFLAGS+=-c -Wall -O3 -fno-strict-aliasing
LDFLAGS+=-lpcap
SRCS=main.c
OBJS=$(SRCS:.c=.o)
EXE=bismark-passive

all: $(EXE)

$(EXE): $(OBJS) 
	$(CC) $(LDFLAGS) $(OBJS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJS) $(EXE)
