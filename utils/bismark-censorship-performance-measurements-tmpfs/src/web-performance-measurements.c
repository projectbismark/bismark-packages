/* Ben Jones
 * Fall 2013
 * Georgia Tech
 * Curl test script to get data
 */

// includes
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <curl/curl.h>

// curl constants
#define USER_AGENT "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)"
#define MAX_FILE_SIZE  768000
#define TIMEOUT  60

// declarations
struct passed_data{
    FILE * xmlFile;
    int printedData;
};

curl_socket_t open_socket_func(void *clientp, curlsocktype purpose, struct curl_sockaddr *address);
int close_socket_func(void *clientP, curl_socket_t item);
int get_measurement_data(CURL * handle, FILE * xmlFile);
CURL * create_curl_handle(char * site, void * data, FILE * htmlFile, FILE * headerFile);

/* expected syntax: <executable-name> <site> <xml output file> <html-output-file> <headers-output-file> */
int main(int argc, char * argv[]){
    struct passed_data data;
    data.printedData = 0;
    CURL * handle;
    FILE * xmlFile, *htmlFile, *headerFile;
    char site[100] = "http://";
    int curlReturnValue;

    // get command line arguments and print out errors
    if(argc != 5){
        printf("Error: improper syntax\n");
        printf("Expected syntax: <executable name> <site> <xml output file> <html output file> <headers output file>\n");
        return 1;
    }
    strncat(site, argv[1], 90);
    if((xmlFile = fopen(argv[2], "a")) == NULL){
        printf("Error: bad xml filename");
        return 1;
    }
    data.xmlFile = xmlFile;
    if((htmlFile = fopen(argv[3], "w")) == NULL){
        printf("Error: bad html filename");
        return 1;
    }
    if((headerFile = fopen(argv[4], "w")) == NULL){
        printf("Error: bad headers filename");
        return 1;
    }

    // initialize
    curl_global_init(CURL_GLOBAL_DEFAULT);
    handle = create_curl_handle(site, (void *) &data, htmlFile, headerFile);
    // if the handle is not properly initialized, then exit with error
    if(handle == NULL){
        fclose(xmlFile);
        fclose(htmlFile);
        fclose(headerFile);
        return 1;
    }

    // do the measurement
    curlReturnValue = curl_easy_perform(handle);
    fprintf(xmlFile, "<curl_return_value>%d</curl_return_value>\n", curlReturnValue);

    // get the results
    get_measurement_data(handle, xmlFile);

    // cleanup
    curl_easy_cleanup(handle);
    curl_global_cleanup();
    fclose(xmlFile);
    fclose(htmlFile);
    fclose(headerFile);

    // print a trailing newline to finish the tcpdump command
    printf("\n");
    return 0;
}

curl_socket_t open_socket_func(void *clientp, curlsocktype purpose, struct curl_sockaddr *address){
    // force the connection to use IPv4
    return socket(AF_INET, address->socktype, address->protocol);
}

int close_socket_func(void * clientP, curl_socket_t item){
    struct passed_data * data = (struct passed_data *) clientP;
    struct sockaddr_storage addr;
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;
    socklen_t addrSize = sizeof(addr);
    uint localPort = 0;
    char remoteIP[INET6_ADDRSTRLEN] = "\0";

    // get the local port
    if(getsockname(item, (struct sockaddr *)&addr, &addrSize) == 0){
        if(addr.ss_family == AF_INET){
            addr4 = (struct sockaddr_in *) &addr;
            localPort = ntohs(addr4->sin_port);
        }else{
            addr6 = (struct sockaddr_in6 *) &addr;
            localPort = ntohs(addr6->sin6_port);
        }
    }
    // get the remote ip
    if(getpeername(item, (struct sockaddr *)&addr, &addrSize) == 0){
        if(addr.ss_family == AF_INET){
            addr4 = (struct sockaddr_in *) &addr;
            inet_ntop(AF_INET,(void *) &(addr4->sin_addr), remoteIP, sizeof(remoteIP));
        }else if (addr.ss_family == AF_INET6){
            addr6 = (struct sockaddr_in6 *) &addr;
            inet_ntop(AF_INET6,(void *) &(addr6->sin6_addr), remoteIP, sizeof(remoteIP));
        }
    }
    if(localPort != 0 && strcmp(remoteIP, "") != 0){
	fprintf(data->xmlFile, "<remote_ip>%s</remote_ip>\n", remoteIP);

        // deal with the case that we use multiple tcp connections-> have tcpdump track all of these ports
        if(data->printedData ==1){
            printf("\\|");
        }
	// used for grep of spec-ascii file in /proc/web100/*/spec-ascii
	// spec-ascii has the format localIP:localPort remoteIP:remotePort
	// Therefore, this format will allow us to match the correct spec-ascii file
        printf("%u\\ %s", localPort, remoteIP);
        data->printedData = 1;
    }
    shutdown((int) item, SHUT_RDWR);
    return 0;
}

int get_measurement_data(CURL * handle, FILE * xmlFile){
    long statLong;
    char *statString;
    double statDouble;

    if(curl_easy_getinfo(handle, CURLINFO_EFFECTIVE_URL, &statString) == CURLE_OK){
        fprintf(xmlFile, "<actual_url>%s</actual_url>\n", statString);
    }
    if(curl_easy_getinfo(handle, CURLINFO_REDIRECT_URL, &statString) == CURLE_OK){
        fprintf(xmlFile, "<redirect_url>%s</redirect_url>\n", statString);
    }
    if(curl_easy_getinfo(handle, CURLINFO_CONTENT_TYPE, &statString) == CURLE_OK){
        fprintf(xmlFile, "<content_type>%s</content_type>\n", statString);
    }
    if(curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &statLong) == CURLE_OK){
        fprintf(xmlFile, "<http_code>%ld</http_code>\n", statLong);
    }

    if(curl_easy_getinfo(handle, CURLINFO_SPEED_DOWNLOAD, &statDouble) == CURLE_OK){
        fprintf(xmlFile, "<speed_download>%f</speed_download>\n", statDouble);
    }
    if(curl_easy_getinfo(handle, CURLINFO_SPEED_UPLOAD, &statDouble) == CURLE_OK){
        fprintf(xmlFile, "<speed_upload>%f</speed_upload>\n", statDouble);
    }

    if(curl_easy_getinfo(handle, CURLINFO_TOTAL_TIME, &statDouble)  == CURLE_OK){
        fprintf(xmlFile, "<time_total>%f</time_total>\n", statDouble);
    }
    if(curl_easy_getinfo(handle, CURLINFO_NAMELOOKUP_TIME, &statDouble) == CURLE_OK){
        fprintf(xmlFile, "<time_lookup>%f</time_lookup>\n", statDouble);
    }
    if(curl_easy_getinfo(handle, CURLINFO_CONNECT_TIME, &statDouble) == CURLE_OK){
        fprintf(xmlFile, "<time_connect>%f</time_connect>\n", statDouble);
    }
    if(curl_easy_getinfo(handle, CURLINFO_PRETRANSFER_TIME, &statDouble) == CURLE_OK){
        fprintf(xmlFile, "<time_pretransfer>%f</time_pretransfer>\n", statDouble);
    }
    if(curl_easy_getinfo(handle, CURLINFO_STARTTRANSFER_TIME, &statDouble) == CURLE_OK){
        fprintf(xmlFile, "<time_starttransfer>%f</time_starttransfer>\n", statDouble);
    }

    if(curl_easy_getinfo(handle, CURLINFO_SIZE_UPLOAD, &statDouble) == CURLE_OK){
        fprintf(xmlFile, "<size_upload>%f</size_upload>\n", statDouble);
    }
    if(curl_easy_getinfo(handle, CURLINFO_SIZE_DOWNLOAD, &statDouble) == CURLE_OK){
        fprintf(xmlFile, "<size_download>%f</size_download>\n", statDouble);
    }
    if(curl_easy_getinfo(handle, CURLINFO_REQUEST_SIZE, &statLong) == CURLE_OK){
        fprintf(xmlFile, "<size_request>%ld</size_request>\n", statLong);
    }
    if(curl_easy_getinfo(handle, CURLINFO_HEADER_SIZE, &statLong) == CURLE_OK){
        fprintf(xmlFile, "<size_header>%ld</size_header>\n", statLong);
    }

    if(curl_easy_getinfo(handle, CURLINFO_NUM_CONNECTS, &statLong) == CURLE_OK){
        fprintf(xmlFile, "<num_connects>%ld</num_connects>\n", statLong);
    }

    return 0;
}

/* create_curl_handle: create a handle for curl to perform measurements with
 * Note: if at any point we encounter an error, we return a NULL pointer,
 * which the main function should be checking for
 */
CURL * create_curl_handle(char * site, void * data, FILE * htmlFile, FILE * headerFile){
    CURL * handle;
    handle = curl_easy_init();
    if(curl_easy_setopt(handle, CURLOPT_URL, site) != CURLE_OK){
        return NULL;
    }
    if(curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1) != CURLE_OK){
        return NULL;
    }
    if(curl_easy_setopt(handle, CURLOPT_MAXREDIRS, 5) != CURLE_OK){
        return NULL;
    }
    if(curl_easy_setopt(handle, CURLOPT_MAXFILESIZE, MAX_FILE_SIZE) != CURLE_OK){
        return NULL;
    }
    if(curl_easy_setopt(handle, CURLOPT_USERAGENT,USER_AGENT) != CURLE_OK){
        return NULL;
    }
    if(curl_easy_setopt(handle, CURLOPT_TIMEOUT,TIMEOUT) != CURLE_OK){
        return NULL;
    }
    if(curl_easy_setopt(handle, CURLOPT_WRITEDATA, htmlFile) != CURLE_OK){
        return NULL;
    }
    if(curl_easy_setopt(handle, CURLOPT_WRITEHEADER, headerFile) != CURLE_OK){
        return NULL;
    }
    if(curl_easy_setopt(handle, CURLOPT_CLOSESOCKETFUNCTION, close_socket_func) != CURLE_OK){
        return NULL;
    }
    if(curl_easy_setopt(handle, CURLOPT_CLOSESOCKETDATA, data) != CURLE_OK){
        return NULL;
    }

    return handle;
}
