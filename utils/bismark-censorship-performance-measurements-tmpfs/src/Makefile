CC ?= gcc

#WEB100_CFLAGS = -c -I/data/users/bjones99/quirm/build_dir/target-mips_r2_uClibc-0.9.30.1/web100_userland-1.8/lib -I. -g
#WEB100_LDFLAGS = -L/data/users/bjones99/quirm/build_dir/target-mips_r2_uClibc-0.9.30.1/web100_userland-1.8/lib/.libs -lweb100
WEB100_CFLAGS = -c -I../web100_userland-1.8/lib -I. -g
WEB100_LDFLAGS = -L../web100_userland-1.8/lib/.libs -lweb100
CURL_LDFLAGS += -lcurl -lssl -lcrypto -lz 

all: release

release: CFLAGS += -c -O3 -DNDEBUG
release: measure-web-performance get-web100-stats 

debug: CFLAGS += -g
debug: measure-web-performance get-web100-stats 

measure-web-performance: web-performance-measurements.c
	$(CC) $(CFLAGS) web-performance-measurements.c -o web-performance-measurements.o
	$(CC) $(LDFLAGS) $(CURL_LDFLAGS) web-performance-measurements.o -o measure-web-performance

get-web100-stats: readconn.c
	$(CC) $(CFLAGS) readconn.c -o readconn.o
	$(CC) readconn.o $(LDFLAGS) $(WEB100_LDFLAGS) -o get-web100-stats
	
clean:
	rm -f readconn.o web-performance-measurements.o measure-web-performance get-web100-stats
