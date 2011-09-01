CC=gcc
CFLAGS+=-c -Wall -O3 -fno-strict-aliasing
LDFLAGS+=-lpcap
SRCS=main.c packet_series.c flow_table.c
OBJS=$(SRCS:.c=.o)
EXE=bismark-passive

TEST_CFLAGS=-DTESTING
TEST_LDFLAGS=-lcheck
TEST_SRCS=tests.c packet_series.c flow_table.c
TEST_EXE=tests

all: $(EXE)

$(EXE): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

$(TEST_EXE): $(TEST_SRCS)
	$(CC) $(TEST_CFLAGS) $(TEST_LDFLAGS) $(TEST_SRCS) -o $(TEST_EXE)
	./$(TEST_EXE)

clean:
	rm -rf $(OBJS) $(EXE) $(TEST_OBJS) $(TEST_EXE)
