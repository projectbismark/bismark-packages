#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "diffprobe.h"


char *sprobetypes[10] = 
{
	"BLP_P",
	"LIP_P",
	"LDP_P",
	"BLP_A",
	"LIP_A",
	"LDP_A",
	"BLP_AP",
	"LIP_AP",
	"LDP_AP",
	"UNKNOWN"
};
char *sflowtypes[2] = { "P", "A" };

int readwrapper(int sock, char *buf, size_t size)
{
	int ret = 0;
	int curread = 0;
	fd_set rfds;
	struct timeval tv;
	int retval;

	while(curread < size)
	{
		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		tv.tv_sec = 300;
		tv.tv_usec = 0;
		retval = select(sock+1, &rfds, NULL, NULL, &tv);
		if(retval == -1)
		{
			perror("error reading");
			return -1;
		}
		else if(retval == 0)
		{
			return -1;
		}

		ret = recv(sock, buf + curread, size - curread, 0);
		if(ret == -1)
		return ret;
		if(ret == 0)
		return ret;

		curread += ret;
	}

	return curread;
}
int writewrapper(int sock, char *buf, size_t size)
{
	int ret = 0;
	int curwrite = 0;

	while(curwrite < size)
	{
		ret = send(sock, buf + curwrite, size - curwrite, 0);
		if(ret == -1)
		return ret;

		curwrite += ret;
	}

	return curwrite;
}

static int nPktsSent = 0;
static int nBytesSent = 0;
static struct timeval lastSendTS = {-1,-1};

struct timeval prober_packet_gap(struct timeval y, struct timeval x);
void prober_swait(struct timeval tv, double sleepRes);

int sendtowrapper(int sock, char *buf, size_t size, int flags, 
		const struct sockaddr *dest, socklen_t addrlen, 
		double capacity, struct timeval curTS, double sleepRes)
{
	int ret = 0;

	ret = sendto(sock, buf, size, flags, dest, addrlen);

	nPktsSent++;
	nBytesSent += (size+UDPIPHEADERSZ);
	//XXX: 100 could be a function of time, so that the sleep duration is appropriate 
	// (i.e., higher than sleepRes)
	if(nPktsSent > 100)
	{
		struct timeval diffts = prober_packet_gap(lastSendTS, curTS);
		double tdiff = diffts.tv_sec+diffts.tv_usec*1e-6;
		double expT = nBytesSent*0.008/capacity; //s

		// sent rate > 2*cap : should not happen
		if(expT > 2 * tdiff && lastSendTS.tv_sec != -1)
		{
			// sleep for the difference in times
			double d = expT-tdiff;
			diffts.tv_sec = floor(d);
			diffts.tv_usec = (d - floor(d)) * 1e6;
			prober_swait(diffts, sleepRes);
			//printf("probe: waiting for %f\n", d);
		}

		nPktsSent = 1;
		nBytesSent = size+UDPIPHEADERSZ;
		lastSendTS = curTS;
	}

	return ret;
}

