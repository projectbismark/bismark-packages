CC = gcc
CFLAGS += -c -Wall -O3 -fno-strict-aliasing
ifdef DISABLE_ANONYMIZATION
CFLAGS += -DDISABLE_ANONYMIZATION
endif
ifdef USE_TEMP_SEED
CFLAGS += -DANONYMIZATION_SEED_FILE="\"/tmp/passive.key\""
endif
ifdef USE_TEMP_ID
CFLAGS += -DBISMARK_ID_FILENAME="\"/tmp/bismark.id\""
endif
LDFLAGS += -lpcap -lresolv -pthread -lz -lssl -lcrypto
SRCS = \
	anonymization.c \
	dns_parser.c \
	dns_table.c \
	flow_table.c \
	address_table.c \
	main.c \
	packet_series.c \
	util.c
OBJS = $(SRCS:.c=.o)
EXE = bismark-passive

TEST_SRCS = \
	anonymization.c \
	dns_parser.c \
	dns_table.c \
	flow_table.c \
	address_table.c \
	packet_series.c \
	tests.c \
	util.c
TEST_OBJS = $(TEST_SRCS:.c=.o)
TEST_EXE = tests

all: debug

release: CFLAGS += -O3 -DNDEBUG
release: $(EXE)

debug: CFLAGS += -g
debug: $(EXE)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

$(EXE): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

fixperms: $(EXE)
	chmod 700 $(EXE)
	sudo setcap cap_net_raw,cap_net_admin=eip $(EXE)

$(TEST_EXE): CFLAGS += -g -DTESTING
$(TEST_EXE): LDFLAGS += -lcheck
$(TEST_EXE): $(TEST_OBJS)
	$(CC) $(LDFLAGS) $(TEST_OBJS) -o $@
	./$(@)

clean:
	rm -rf $(OBJS) $(EXE) $(TEST_OBJS) $(TEST_EXE)
