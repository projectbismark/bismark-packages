CC=gcc
CFLAGS+=-c -Wall -O3 -fno-strict-aliasing
LDFLAGS+=-lpcap
SRCS=main.c packet_series.c flow_table.c
OBJS=$(SRCS:.c=.o)
EXE=bismark-passive

TEST_LDFLAGS=-lcheck
TEST_OBJS=tests.o packet_series.o flow_table.o
TEST_EXE=tests

all: $(EXE)

$(EXE): $(OBJS) 
	$(CC) $(LDFLAGS) $(OBJS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

$(TEST_EXE): $(TEST_OBJS)
	$(CC) $(TEST_LDFLAGS) $(TEST_OBJS) -o $(TEST_EXE)
	./$(TEST_EXE)

clean:
	rm -rf $(OBJS) $(EXE) $(TEST_OBJS) $(TEST_EXE)
