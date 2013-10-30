/* Ben Jones
 * Fall 2013
 * Georgia Tech
 * Curl test script to get data
 */

//includes
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <curl/curl.h>

struct passed_data{
    struct tcp_info stats;
    socklen_t stats_len;
    FILE * xmlFile;
    int socketsSeen;
};

curl_socket_t open_socket_func(void *clientp, curlsocktype purpose, struct curl_sockaddr *address);
int close_socket_func(void *clientP, curl_socket_t item);
int get_measurement_data(CURL * handle, FILE * xmlFile);

/* expected syntax: <executable-name> <site> <xml output file> <html-output-file> <headers-output-file> */
int main(int argc, char * argv[]){
    struct passed_data data;
    data.stats_len = sizeof(data.stats);
    data.socketsSeen = 0;
    CURL * handle;
    FILE * xmlFile, *htmlFile, *headerFile;
    char site[100] = "http://\0";
    int curlReturnValue = -1;

    //curl constants
    char * USER_AGENT = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)";
    long MAX_FILE_SIZE = 750*1024;
    long TIMEOUT = 60;

    //get command line arguments and print out errors
    if(argc != 5){
	printf("Error: improper syntax\n");
	printf("Expected syntax: <executable name> <site> <xml output file> <html output file> <headers output file>\n");
	return 1;
    }
    strncat(site, argv[1], 90);
    if((xmlFile = fopen(argv[2], "a")) == NULL){
	printf("Error: bad xml filename");
	return 1;}
    data.xmlFile = xmlFile;
    if((htmlFile = fopen(argv[3], "w")) == NULL){
	printf("Error: bad html filename");
	return 1;}
    if((headerFile = fopen(argv[4], "w")) == NULL){
	printf("Error: bad headers filename");
	return 1;}

    //initialize
    curl_global_init(CURL_GLOBAL_DEFAULT);
    handle = curl_easy_init();
    curl_easy_setopt(handle, CURLOPT_URL, site);
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(handle, CURLOPT_MAXREDIRS, 5);
    curl_easy_setopt(handle, CURLOPT_MAXFILESIZE, MAX_FILE_SIZE);
    curl_easy_setopt(handle, CURLOPT_USERAGENT,USER_AGENT);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT,TIMEOUT);

    curl_easy_setopt(handle, CURLOPT_WRITEDATA, htmlFile);
    curl_easy_setopt(handle, CURLOPT_WRITEHEADER, headerFile);
    curl_easy_setopt(handle, CURLOPT_CLOSESOCKETFUNCTION, close_socket_func);
    curl_easy_setopt(handle, CURLOPT_CLOSESOCKETDATA, (void*) &data);

    //do the measurement
    curlReturnValue = curl_easy_perform(handle);
    fprintf(xmlFile, "<curl_return_value>%d</curl_return_value>\n", curlReturnValue);

    //get the results
    get_measurement_data(handle, xmlFile);

    //cleanup
    curl_easy_cleanup(handle);
    curl_global_cleanup();
    fclose(xmlFile);
    fclose(htmlFile);
    fclose(headerFile);
    return 0;
}

curl_socket_t open_socket_func(void *clientp, curlsocktype purpose, struct curl_sockaddr *address){
    //force the connection to use IPv4
    return socket(AF_INET, address->socktype, address->protocol);
}

int close_socket_func(void * clientP, curl_socket_t item){
    struct passed_data * data = (struct passed_data *) clientP;
    struct sockaddr_storage addr;
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;
    socklen_t addrSize = sizeof(addr);
    uint localPort;
    char remoteIP[INET6_ADDRSTRLEN] = "\0";
    //    if(getsockopt(item, SOL_TCP, TCP_INFO, (void *)&(data->stats), &(data->stats_len)) == 0){
    //	fprintf(stdout, "lost: %u retrans: %u retransmit: %u total_retrans: %u\n", data->stats.tcpi_lost, data->stats.tcpi_retrans, data->stats.tcpi_retransmits, data->stats.tcpi_total_retrans);
    //	fprintf(stdout, "rtt: %u reordering: %u unacked: %u sacked: %u\n", data->stats.tcpi_rtt, data->stats.tcpi_reordering, data->stats.tcpi_unacked, data->stats.tcpi_sacked);
    //    }

    //get the local port
    if(getsockname((int)item, (struct sockaddr *)&addr, &addrSize) == 0){
	if(addr.ss_family == AF_INET){
	    addr4 = (struct sockaddr_in *) &addr;
	    localPort = ntohs(addr4->sin_port);
	}else{
	    addr6 = (struct sockaddr_in6 *) &addr;
	    localPort = ntohs(addr6->sin6_port);
	}
    }
    //get the remote ip
    if(getpeername((int)item, (struct sockaddr *)&addr, &addrSize) == 0){
	if(addr.ss_family == AF_INET){
	    addr4 = (struct sockaddr_in *) &addr;
	    inet_ntop(AF_INET,(void *) &(addr4->sin_addr), remoteIP, sizeof(remoteIP));
	}else{
	    addr6 = (struct sockaddr_in6 *) &addr;
	    inet_ntop(AF_INET6,(void *) &(addr6->sin6_addr), remoteIP, sizeof(remoteIP));	    
	}
    }
    fprintf(data->xmlFile, "<remote_ip>%s</remote_ip>\n", remoteIP);
    //deal with the case that we use multiple tcp connections-> have tcpdump track all of these ports
    if(data->socketsSeen > 1){
	printf("and ");
    }
    printf("port %u and host %s\n", localPort, remoteIP);
    shutdown((int) item, 2);
    data->socketsSeen++;
    return 0;
}

int get_measurement_data(CURL * handle, FILE * xmlFile){
    long statLong;
    char *statString;
    double statDouble;

    curl_easy_getinfo(handle, CURLINFO_EFFECTIVE_URL, &statString);
    fprintf(xmlFile, "<actual_url>%s</actual_url>\n", statString);
    curl_easy_getinfo(handle, CURLINFO_REDIRECT_URL, &statString);
    fprintf(xmlFile, "<redirect_url>%s</redirect_url>\n", statString);
    curl_easy_getinfo(handle, CURLINFO_CONTENT_TYPE, &statString);
    fprintf(xmlFile, "<content_type>%s</content_type>\n", statString);
    curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &statLong);
    fprintf(xmlFile, "<http_code>%d</http_code>\n", (int)statLong);

    curl_easy_getinfo(handle, CURLINFO_SPEED_DOWNLOAD, &statDouble);
    fprintf(xmlFile, "<speed_download>%f</speed_download>\n", statDouble);
    curl_easy_getinfo(handle, CURLINFO_SPEED_UPLOAD, &statDouble);
    fprintf(xmlFile, "<speed_upload>%f</speed_upload>\n", statDouble);

    curl_easy_getinfo(handle, CURLINFO_TOTAL_TIME, &statDouble);
    fprintf(xmlFile, "<time_total>%f</time_total>\n", statDouble);
    curl_easy_getinfo(handle, CURLINFO_NAMELOOKUP_TIME, &statDouble);
    fprintf(xmlFile, "<time_lookup>%f</time_lookup>\n", statDouble);
    curl_easy_getinfo(handle, CURLINFO_CONNECT_TIME, &statDouble);
    fprintf(xmlFile, "<time_connect>%f</time_connect>\n", statDouble);
    curl_easy_getinfo(handle, CURLINFO_PRETRANSFER_TIME, &statDouble);
    fprintf(xmlFile, "<time_pretransfer>%f</time_pretransfer>\n", statDouble);
    curl_easy_getinfo(handle, CURLINFO_STARTTRANSFER_TIME, &statDouble);
    fprintf(xmlFile, "<time_starttransfer>%f</time_starttransfer>\n", statDouble);

    curl_easy_getinfo(handle, CURLINFO_SIZE_UPLOAD, &statDouble);
    fprintf(xmlFile, "<size_upload>%f</size_upload>\n", statDouble);
    curl_easy_getinfo(handle, CURLINFO_SIZE_DOWNLOAD, &statDouble);
    fprintf(xmlFile, "<size_download>%f</size_download>\n", statDouble);
    curl_easy_getinfo(handle, CURLINFO_REQUEST_SIZE, &statDouble);
    fprintf(xmlFile, "<size_request>%f</size_request>\n", statDouble);
    curl_easy_getinfo(handle, CURLINFO_HEADER_SIZE, &statDouble);
    fprintf(xmlFile, "<size_header>%f</size_header>\n", statDouble);

    curl_easy_getinfo(handle, CURLINFO_NUM_CONNECTS, &statLong);
    fprintf(xmlFile, "<num_connects>%d</num_connects>\n", (int)statLong);

    return 0;
}
