CC ?= gcc

#WEB100_CFLAGS = -c -I/data/users/bjones99/quirm/build_dir/target-mips_r2_uClibc-0.9.30.1/web100_userland-1.8/lib -I. -g
#WEB100_LDFLAGS = -L/data/users/bjones99/quirm/build_dir/target-mips_r2_uClibc-0.9.30.1/web100_userland-1.8/lib/.libs -lweb100
WEB100_CFLAGS = -c -I../web100_userland-1.8/lib -I. -g
WEB100_LDFLAGS = -L../web100_userland-1.8/lib/.libs -lweb100
CURL_LDFLAGS += -lcurl -lssl -lcrypto -lz 
WEB10G_LDFLAGS = -lmnl

all: release

release: measure-web-performance get-web100-stats 
release: CFLAGS += -c -O3 -DNDEBUG

debug: CFLAGS += -g
debug: measure-web-performance get-web100-stats

web100: measure-web-performance get-web100-stats

web10g: measure-web-performance get-web10g-stats

get-web10g-stats: web10g-stats.c
	$(CC) $(LDFLAGS) $(WEB10G_LDFLAGS) web10g-stats.c tcp_estats_resolve.c tcp_estats_var.c \
	-o get-web10g-stats


measure-web-performance: web-performance-measurements.c
	$(CC) $(CFLAGS) -c web-performance-measurements.c -o web-performance-measurements.o
	$(CC) $(LDFLAGS) $(CURL_LDFLAGS) web-performance-measurements.o -o measure-web-performance

get-web100-stats: readconn.c
	$(CC) $(CFLAGS) readconn.c -o readconn.o
	$(CC) readconn.o $(LDFLAGS) $(WEB100_LDFLAGS) -o get-web100-stats
	
clean:
	rm -f *.o measure-web-performance get-web100-stats get-web10g-stats
