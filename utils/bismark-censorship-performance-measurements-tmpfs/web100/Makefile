CC = gcc
CFLAGS += -c -I../../../web100_userland-1.8/lib -I. -g
LDFLAGS += -L../../../web100_userland-1.8/lib/.libs -lweb100

SRCS = readconn.c 
OBJS = $(SRCS:.c=.o)
EXE = get-web100-stats

.c.o:
	$(CC) $(CFLAGS) $< -o $@

$(EXE): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

clean:
	rm -rf $(OBJS) $(EXE) 
