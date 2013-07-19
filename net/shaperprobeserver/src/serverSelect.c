/*
** server.c - a stream socket server demo
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#define SELECTPORT 55000 // the port users will be connecting to
#define BACKLOG 10// how many pending connections queue will hold
//#define NUM_SERVERS 49
#define NUM_SERVERS 47

void sigchld_handler(int s)
{
    while(wait(NULL) > 0);
}

int main(void)
{
    int sockfd, new_fd; // listen on sock_fd, new connection on new_fd
    struct sockaddr_in my_addr; // my address information
    struct sockaddr_in their_addr; // connector’s address information
    int sin_size;
    struct sigaction sa;
    int yes=1,i,ctr_code_n;
	char ctr_buff[8];

    char *serverList[NUM_SERVERS] = {"213.244.128.138","213.244.128.151","213.244.128.168","217.163.1.100","217.163.1.74","217.163.1.87","38.102.0.111","38.102.0.85","38.102.0.87","38.106.70.149","38.106.70.162","38.106.70.175","38.107.216.19","38.107.216.34","38.107.216.47","38.98.51.17","38.98.51.25","38.98.51.47","4.71.210.213","4.71.210.226","4.71.210.239","4.71.251.149","4.71.251.162","4.71.251.175","4.71.254.149","4.71.254.162","64.9.225.142","64.9.225.153","64.9.225.166","64.9.225.179","74.63.50.21","74.63.50.34","74.63.50.40","72.26.217.102","72.26.217.87","80.239.142.202","80.239.142.215","80.239.142.234","80.239.168.202","80.239.168.215","80.239.168.233","83.212.4.11","83.212.4.23","83.212.4.36","203.5.76.139","203.5.76.153","203.5.76.164"};
    // following is a full list (as of 24th Jan'12): NUM_SERVERS = 61 servers
//    char *serverList[NUM_SERVERS] = {"4.71.251.162","38.102.0.111","4.71.254.149","217.163.1.100","203.5.76.164","64.9.225.179","4.71.210.213","80.239.168.233","4.71.210.239","103.10.233.23","38.106.70.162","74.63.50.34","83.212.5.175","80.239.142.215","83.212.5.151","38.98.51.17","38.106.70.175","38.106.70.149","216.156.197.138","4.71.254.175","72.26.217.102","203.178.130.228","4.71.210.226","83.212.4.23","203.178.130.215","80.239.142.234","213.244.128.151","64.9.225.166","213.244.128.138","213.244.128.168","203.5.76.153","4.71.251.175","74.63.50.40","74.63.50.21","38.107.216.19","38.98.51.25","38.102.0.85","203.5.76.139","83.212.4.11","216.156.197.164","4.71.251.149","64.9.225.153","83.212.4.36","38.102.0.87","72.26.217.81","103.10.233.36","216.156.197.151","83.212.5.138","217.163.1.87","38.107.216.47","217.163.1.74","38.107.216.34","80.239.142.202","4.71.254.162","80.239.168.215","103.10.233.10","64.9.225.142","38.98.51.47","72.26.217.87","80.239.168.202","203.178.130.202"};

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }
    if (setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1) {
        perror("setsockopt");
        exit(1);
    }
    my_addr.sin_family = AF_INET; // host byte order
    my_addr.sin_port = htons(SELECTPORT); // short, network byte order
    my_addr.sin_addr.s_addr = INADDR_ANY; // automatically fill with my IP
    memset(&(my_addr.sin_zero), '\0', 8); // zero the rest of the struct
    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr))    == -1) {
        perror("bind");
        exit(1);
    }
    
    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    while(1) { // main accept() loop

        sin_size = sizeof(struct sockaddr_in);
        if ((new_fd = accept(sockfd, (struct sockaddr *)&their_addr,&sin_size)) == -1) {
            perror("accept");
            continue;
        }

        printf("server: got connection from %s\n",
        inet_ntoa(their_addr.sin_addr));
        
        if (!fork()) { // this is the child process
 // child doesn’t need the listener
		close(sockfd);
		ctr_code_n = htonl(NUM_SERVERS);
		memcpy((void*)ctr_buff, &ctr_code_n, sizeof(ctr_code_n));
		if (send(new_fd, ctr_buff, sizeof(int), 0) == -1)
	                perror("send");
		printf("\nSent size");
	    for(i=0;i<NUM_SERVERS;i++)
	    {
				printf("\nSending %d bytes",strlen(serverList[i]));
				ctr_code_n = htonl(strlen(serverList[i]));
				memcpy((void*)ctr_buff, &ctr_code_n, sizeof(ctr_code_n));
				if (send(new_fd, ctr_buff, sizeof(int), 0) == -1)
	                perror("send");
 	            if (send(new_fd, serverList[i], strlen(serverList[i]), 0) == -1)
	                perror("send");
	    }
		printf("\nSent server List");
            close(new_fd);
            exit(0);
        }

        close(new_fd); // parent doesn’t need this
    }
    return 0;
}
