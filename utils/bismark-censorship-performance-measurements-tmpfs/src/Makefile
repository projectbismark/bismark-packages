CC = gcc
CFLAGS += -c -Wall -O3 -fno-strict-aliasing
LDFLAGS += -lcurl

SRCS = web-performance-measurements.c
OBJS = $(SRCS:.c=.o)
EXE = measure-web-performance
.c.o:
	$(CC) $(CFLAGS) $< -o $@

$(EXE): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

clean:
	rm -rf $(OBJS) $(EXE)
