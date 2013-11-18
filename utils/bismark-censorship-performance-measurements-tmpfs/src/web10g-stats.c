#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <libmnl/libmnl.h>
#include <linux/genetlink.h>
#include <arpa/inet.h>

#include "tcp_estats_resolve.h"
#include "tcp_estats_val.h"
#include "tcp_estats_nl.h"

// Global Variables
// Note: I am aware that this is awful coding convention,
// but I don't want to rewrite and retest every function in
// this file
char * outputFile;

struct index_attr {
    struct nlattr **tb;
    int index;
};

struct mnl_socket{
    int fd;
    struct sockaddr_nl addr;
};

static int parse_4tuple_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = (const struct nlattr **)data;
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, NEA_4TUPLE_MAX) < 0) {
        perror("mnl_attr_type_valid");
        return MNL_CB_ERROR;
    }

    switch(type) {
    case NEA_REM_ADDR:
        if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
            perror("mnl_attr_validate");
            return MNL_CB_ERROR;
        }
        break;
    case NEA_LOCAL_ADDR:
        if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
            perror("mnl_attr_validate");
            return MNL_CB_ERROR;
        }
        break;
    case NEA_REM_PORT:
        if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
            perror("mnl_attr_validate");
            return MNL_CB_ERROR;
        }
        break;
    case NEA_LOCAL_PORT:
        if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
            perror("mnl_attr_validate");
            return MNL_CB_ERROR;
        }
        break;
    }
    tb[type] = attr;

    return MNL_CB_OK;
}

static void parse_4tuple(struct nlattr *nested)
{
    struct nlattr *tb[NEA_4TUPLE_MAX+1];
    struct nlattr *attr;
    char rem_addr_str[40];
    char local_addr_str[40];
    uint16_t rem_port;
    uint16_t local_port;
    int cid;

    mnl_attr_parse_nested(nested, parse_4tuple_cb, tb);

    if (tb[NEA_LOCAL_ADDR]) {
        inet_ntop(AF_INET, mnl_attr_get_str(tb[NEA_LOCAL_ADDR]),
                  &local_addr_str[0], 40);
    }
    if (tb[NEA_REM_ADDR]) {
        inet_ntop(AF_INET, mnl_attr_get_str(tb[NEA_REM_ADDR]),
                  &rem_addr_str[0], 40);
    }
    if (tb[NEA_LOCAL_PORT]) {
        local_port = mnl_attr_get_u16(tb[NEA_LOCAL_PORT]);
    }
    if (tb[NEA_REM_PORT]) {
        rem_port = mnl_attr_get_u16(tb[NEA_REM_PORT]);
    }
    if (tb[NEA_CID]) {
        cid = mnl_attr_get_u32(tb[NEA_CID]);
    }

    FILE * output = fopen(outputFile, "a");
    fprintf(output, "CID: %d Addr: %s %d %s %d\n", cid, local_addr_str, local_port,
            rem_addr_str, rem_port);
    fclose(output);
}

static int parse_table_cb(const struct nlattr *attr, void *data)
{
    struct index_attr *ia = (struct index_attr *)data;
    const struct nlattr **tb = (const struct nlattr **)ia->tb;
    int type = mnl_attr_get_type(attr);
    int tblnum = ia->index;

    if (mnl_attr_type_valid(attr, max_index[tblnum]) < 0) {
        perror("mnl_attr_type_valid");
        return MNL_CB_ERROR;
    }

    switch(estats_var_array[tblnum][type].type) {

    case TCP_ESTATS_UNSIGNED8:
        if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0) {
            perror("mnl_attr_validate");
            return MNL_CB_ERROR;
        }
        break;
    case TCP_ESTATS_UNSIGNED16:
        if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
            perror("mnl_attr_validate");
            return MNL_CB_ERROR;
        }
        break;
    case TCP_ESTATS_UNSIGNED32:
    case TCP_ESTATS_SIGNED32:
        if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
            perror("mnl_attr_validate");
            return MNL_CB_ERROR;
        }
        break;
    case TCP_ESTATS_UNSIGNED64:
        if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) {
            perror("mnl_attr_validate");
            return MNL_CB_ERROR;
        }
        break;
    default:
        break;
    }

    tb[type] = attr;
    return MNL_CB_OK;
}

static void parse_table(struct nlattr *nested, int index)
{

    struct nlattr *tb_perf[PERF_INDEX_MAX+1]   = {};
    struct nlattr *tb_path[PATH_INDEX_MAX+1]   = {};
    struct nlattr *tb_stack[STACK_INDEX_MAX+1] = {};
    struct nlattr *tb_app[APP_INDEX_MAX+1]     = {};
    struct nlattr *tb_tune[TUNE_INDEX_MAX+1]   = {};

    struct index_attr ia = { .index = index };
    int i;
    FILE * output = fopen(outputFile, "a");

    switch (index) {
    case PERF_TABLE:
        ia.tb = tb_perf;
        break;
    case PATH_TABLE:
        ia.tb = tb_path;
        break;
    case STACK_TABLE:
        ia.tb = tb_stack;
        break;
    case APP_TABLE:
        ia.tb = tb_app;
        break;
    case TUNE_TABLE:
        ia.tb = tb_tune;
        break;
    }
    mnl_attr_parse_nested(nested, parse_table_cb, &ia);

    for (i = 0; i < max_index[index]; i++) {
        if (ia.tb[i]) {
            switch(estats_var_array[index][i].type) {

            case TCP_ESTATS_UNSIGNED64:
                fprintf(output, "%s=%"PRIu64"\n",
                        estats_var_array[index][i].name,
                        mnl_attr_get_u64(ia.tb[i]));
                break;
            case TCP_ESTATS_UNSIGNED32:
                fprintf(output, "%s=%"PRIu32"\n",
                        estats_var_array[index][i].name,
                        mnl_attr_get_u32(ia.tb[i]));
                break;
            case TCP_ESTATS_SIGNED32:
                fprintf(output, "%s=%"PRId32"\n",
                        estats_var_array[index][i].name,
                        (int32_t) mnl_attr_get_u32(ia.tb[i]));
                break;
            case TCP_ESTATS_UNSIGNED16:
                fprintf(output,"%s=%"PRIu16"\n",
                        estats_var_array[index][i].name,
                        mnl_attr_get_u16(ia.tb[i]));
                break;
            case TCP_ESTATS_UNSIGNED8:
                fprintf(output, "%s=%"PRIu8"\n",
                        estats_var_array[index][i].name,
                        mnl_attr_get_u8(ia.tb[i]));
                break;
            default:
                break;
            }
        }
    }
    fclose(output);

}

static int data_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, NLE_ATTR_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case NLE_ATTR_4TUPLE:
        if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
            perror("mnl_attr_validate NLE_ATTR_PERF");
            return MNL_CB_ERROR;
        }
        break;
    case NLE_ATTR_PERF:
        if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
            perror("mnl_attr_validate NLE_ATTR_PERF");
            return MNL_CB_ERROR;
        }
        break;
    case NLE_ATTR_PATH:
        if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
            perror("mnl_attr_validate NLE_ATTR_PATH");
            return MNL_CB_ERROR;
        }
        break;
    case NLE_ATTR_STACK:
        if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
            perror("mnl_attr_validate NLE_ATTR_STACK");
            return MNL_CB_ERROR;
        }
        break;
    case NLE_ATTR_APP:
        if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
            perror("mnl_attr_validate NLE_ATTR_APP");
            return MNL_CB_ERROR;
        }
        break;
    case NLE_ATTR_TUNE:
        if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
            perror("mnl_attr_validate NLE_ATTR_TUNE");
            return MNL_CB_ERROR;
        }
        break;
    }
    tb[type] = attr;
    return MNL_CB_OK;
}

static int data_cb(const struct nlmsghdr *nlh, void *data)
{
    struct nlattr *tb[NLE_ATTR_MAX+1] = {};
    struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

    mnl_attr_parse(nlh, sizeof(*genl), data_attr_cb, tb);

    if (tb[NLE_ATTR_4TUPLE])
        parse_4tuple(tb[NLE_ATTR_4TUPLE]);
    if (tb[NLE_ATTR_PERF])
        parse_table(tb[NLE_ATTR_PERF], PERF_TABLE);
    if (tb[NLE_ATTR_PATH])
        parse_table(tb[NLE_ATTR_PATH], PATH_TABLE);
    if (tb[NLE_ATTR_STACK])
        parse_table(tb[NLE_ATTR_STACK], STACK_TABLE);
    if (tb[NLE_ATTR_APP])
        parse_table(tb[NLE_ATTR_APP], APP_TABLE);
    if (tb[NLE_ATTR_TUNE])
        parse_table(tb[NLE_ATTR_TUNE], TUNE_TABLE);

    return MNL_CB_OK;
}

void usage(void)
{
        printf("\n\n");
        printf("web10g_request cid [-m mask] || -l\n");
        printf("\n -l list all open connections in the form:\n");
        printf("    \"cid: local-addr local-port rem-addr rem-port\"\n");
        printf("\n cid -m mask : list tcp_estats vars for connection\n");
        printf("  specified by cid, with optional mask given as a\n");
        printf("  5-tuple of hex values, e.g.\n");
        printf("\n");
        printf("  web10g_request <cid> -m f,f,f,f,f\n");
        printf("\n");
        printf("  returns the first 4 entries of each of the mib tables.\n");
        printf("\n");
        printf("  web10g_request <cid> -m 0,0,0,,0\n");
        printf("\n");
        printf("  returns only the mib app table, etc.\n");
        printf("\n");
}

int main(int argc, char *argv[])
{
    // receiver initializations
    struct mnl_socket *receiver;
    int recvFd = 0;
    char recvBuf[MNL_SOCKET_BUFFER_SIZE];
    int ret, grp;
    // Resolve genetlink family name
    int fam_id;
    int grp_id;

    // requestor initializations
    // Standard genetlink overhead
    char sendBuf[getpagesize()];
    struct nlmsghdr *nlh;
    struct genlmsghdr *genl;
    struct mnl_socket *sender;
    unsigned int seq, oper, portid;
    uint8_t cmd = 50;
    // Netlink atrribute
    struct nlattr *attrp;
    // Defined in tcp_estat_val.h
    struct estats_connection_spec spec;
    int cid;
    // For requesting a sub-collection of metrics by mask
    uint64_t masks[MAX_TABLE] = { DEFAULT_PERF_MASK, DEFAULT_PATH_MASK,
				  DEFAULT_STACK_MASK, DEFAULT_APP_MASK, DEFAULT_TUNE_MASK };
    int if_mask[] = { [0 ... MAX_TABLE-1] = 0 };
    uint64_t tmpmask;
    int opt, j, option;
    char *strmask = NULL;
    const char delim = ',';
    char *str;

    // Step 1: open a socket to listen for info from the kernel
    receiver = mnl_socket_open(NETLINK_GENERIC);
    if (receiver == NULL) {
        perror("mnl_socket_open");
        exit(EXIT_FAILURE);
    }
    // Note: we need non-blocking io, so set the file descriptor not to block
    recvFd = receiver->fd;
    fcntl(recvFd, F_SETFL, O_NONBLOCK); 

    ret = mnl_socket_bind(receiver, 0, MNL_SOCKET_AUTOPID);
    if (ret == -1) {
        perror("mnl_socket_bind");
        exit(EXIT_FAILURE);
    }

    if (resolve_web10g_nladdr("tcp_estats", &fam_id, &grp_id)) {
        perror("resolve_web10g_nladdr");
        exit(EXIT_FAILURE);
    }
    mnl_socket_setsockopt(receiver, NETLINK_ADD_MEMBERSHIP, &grp_id, sizeof(grp_id));

    // start of requestor code
    if (argc < 2) {
	usage();
	exit(EXIT_FAILURE);
    }
        
    while ((opt = getopt(argc, argv, "lm:f:c:")) != -1) {
	switch (opt) {
	case 'l':
	    cmd = TCPE_CMD_LIST_CONNS;
	    break;
	case 'f':
	    outputFile = optarg;
	    break;
	case 'c':
	    cid = strtol(optarg, NULL, 10);
	    if(cid == 0){
		perror("Invalid CID");
		exit(EXIT_FAILURE);
	    }
	    cmd = TCPE_CMD_READ_CONN;
	    break;
	case 'm':
	    strmask = strdup(optarg);

	    for (j = 0; j < 5; j++) {
		char *strtmp;
		strtmp = strsep(&strmask, &delim);
		if (strtmp && strlen(strtmp)) {
		    char *str;
		    str = (str = strchr(strtmp, 'x')) ? str+1 : strtmp;
		    if (sscanf(str, "%"PRIx64, &tmpmask) == 1) {
			masks[j] = tmpmask & masks[j];
			if_mask[j] = 1;
		    }
		}
	    }
	    cmd = TCPE_CMD_READ_CONN;
	    option = opt;

	    break;
	default:
	    exit(EXIT_FAILURE);
	    break;
	}
    }
    if ((option == 'm') && (optind+1 > argc)) {
	printf("Too few non-option args\n");
	exit(EXIT_FAILURE);
    }

    if (cmd == 50){
	perror("Invalid options");
	exit(EXIT_FAILURE);
    }

    if (resolve_web10g_nladdr("tcp_estats", &fam_id, &grp_id)) {
	perror("resolve_web10g_nladdr");
	exit(EXIT_FAILURE);
    }

    nlh = mnl_nlmsg_put_header(sendBuf);
    nlh->nlmsg_type = fam_id;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = seq = time(NULL);
    genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));

    genl->cmd = cmd;

    if (genl->cmd == TCPE_CMD_READ_CONN) {

	attrp = mnl_attr_nest_start_check(nlh, getpagesize(), NLE_ATTR_4TUPLE);
	if (!attrp) {
	    printf("attr_nest_start failure\n");
	    exit(EXIT_FAILURE);
	}

	mnl_attr_put_u32(nlh, NEA_CID, cid);

	mnl_attr_nest_end(nlh, attrp);

	attrp = mnl_attr_nest_start_check(nlh, getpagesize(), NLE_ATTR_MASK);
	if (!attrp) {
                        printf("attr_nest_start failure\n");
                        exit(EXIT_FAILURE);
                }
                if (if_mask[0]) mnl_attr_put_u64(nlh, NEA_PERF_MASK, masks[0]);
                if (if_mask[1]) mnl_attr_put_u64(nlh, NEA_PATH_MASK, masks[1]);
                if (if_mask[2]) mnl_attr_put_u64(nlh, NEA_STACK_MASK, masks[2]);
                if (if_mask[3]) mnl_attr_put_u64(nlh, NEA_APP_MASK, masks[3]);
                if (if_mask[4]) mnl_attr_put_u64(nlh, NEA_TUNE_MASK, masks[4]);

                mnl_attr_nest_end(nlh, attrp);
    }

    sender = mnl_socket_open(NETLINK_GENERIC);
    if (sender == NULL) {
	perror("mnl_socket_open");
	exit(EXIT_FAILURE);
    }
    ret = mnl_socket_bind(sender, 0, MNL_SOCKET_AUTOPID);
    if (ret == -1) {
	perror("mnl_socket_bind");
	exit(EXIT_FAILURE);
    }
    portid = mnl_socket_get_portid(sender);

    ret = mnl_socket_sendto(sender, nlh, nlh->nlmsg_len);
    if (ret == -1) {
	perror("mnl_socket_send");
	exit(EXIT_FAILURE);
    }

    ret = mnl_socket_recvfrom(sender, sendBuf, sizeof(sendBuf));
    while (ret == -1) {
	perror("mnl_socket_recvfrom");
	exit(EXIT_FAILURE);
    }
    
    ret = mnl_cb_run(sendBuf, ret, seq, portid, NULL, NULL);
    
    if (ret == -1) {
	perror("mnl_cb_run");
	exit(EXIT_FAILURE);
    }
    
    mnl_socket_close(sender);
    
    // setup the data structure to receive data
    fd_set fds;
    struct timeval timeout;
    
    // receive the data back from the kernel
    while (1) {
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;
	
	FD_ZERO(&fds);
	FD_SET(recvFd, &fds);
	ret = select(sizeof(fds)*8, &fds, NULL, NULL, &timeout);
	// exit on error
	if(ret == -1){
	    perror("select error");
	    exit(EXIT_FAILURE);
	}
	// If the timeout expired and we don't have anything, then use
	// the data and break out of the loop
        else if(ret == 0){
	    break;
	}
	// otherwise, read the data, then continue reading
	else{
	    ret = mnl_socket_recvfrom(receiver, recvBuf, sizeof(recvBuf));
	    if (ret == -1) {
		perror("mnl_socket_recvfrom");
		exit(EXIT_FAILURE);
	    }
	    ret = mnl_cb_run(recvBuf, ret, 0, 0, data_cb, NULL);
	    if (ret == -1) {
		perror("mnl_cb_run");
		exit(EXIT_FAILURE);
	    }
	}
    }
    mnl_socket_close(receiver);
    return 0;
}
