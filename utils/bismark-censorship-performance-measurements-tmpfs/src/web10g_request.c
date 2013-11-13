#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>

#include <libmnl/libmnl.h>
#include <linux/genetlink.h>
#include <arpa/inet.h>

#include "tcp_estats_resolve.h"
#include "tcp_estats_val.h"
#include "tcp_estats_nl.h"

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
        /*
         * Standard genetlink overhead
         */
	char buf[getpagesize()];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct mnl_socket *nl;
	int ret;
	unsigned int seq, oper, portid;

        uint8_t cmd = TCPE_CMD_READ_CONN;
        /*
         * Resolve genetlink family name
         */
        int fam_id;
        int grp_id;
        /*
         * Netlink atrribute
         */
        struct nlattr *attrp;

        /*
         * Defined in tcp_estat_val.h
         */
        struct estats_connection_spec spec;
        int cid;

        /*
         * For requesting a sub-collection of metrics by mask
         */
        uint64_t masks[MAX_TABLE] = { DEFAULT_PERF_MASK, DEFAULT_PATH_MASK,
                DEFAULT_STACK_MASK, DEFAULT_APP_MASK, DEFAULT_TUNE_MASK };
        int if_mask[] = { [0 ... MAX_TABLE-1] = 0 };
        uint64_t tmpmask;


        int opt, j, option;
        char *strmask = NULL;
        const char delim = ',';
        char *str;

	if (argc < 2) {
                usage();
		exit(EXIT_FAILURE);
	}
        
        while ((opt = getopt(argc, argv, "lm:")) != -1) {
                switch (opt) {
                case 'l':
                        cmd = TCPE_CMD_LIST_CONNS;
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

        if (resolve_web10g_nladdr("tcp_estats", &fam_id, &grp_id)) {
                perror("resolve_web10g_nladdr");
                exit(EXIT_FAILURE);
        }

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = fam_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = seq = time(NULL);
	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));

	genl->cmd = cmd;

        if (genl->cmd == TCPE_CMD_READ_CONN) {

                cid = atoi(argv[optind]);

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

	nl = mnl_socket_open(NETLINK_GENERIC);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}
	ret = mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
	if (ret == -1) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl);

	ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
	if (ret == -1) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret == -1) {
		perror("mnl_socket_recvfrom");
		exit(EXIT_FAILURE);
	}

	ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);

	if (ret == -1) {
		perror("mnl_cb_run");
		exit(EXIT_FAILURE);
	}

	mnl_socket_close(nl);

	return 0;
}
