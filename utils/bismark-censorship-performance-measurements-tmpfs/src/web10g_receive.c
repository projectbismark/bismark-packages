#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

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
        fprintf(output, "\n\n Perf Table\n\n");
        break;
    case PATH_TABLE:
        ia.tb = tb_path;
        fprintf(output, "\n\n Path Table\n\n");
        break;
    case STACK_TABLE:
        ia.tb = tb_stack;
        fprintf(output, "\n\n Stack Table\n\n");
        break;
    case APP_TABLE:
        ia.tb = tb_app;
        fprintf(output, "\n\n App Table\n\n");
        break;
    case TUNE_TABLE:
        ia.tb = tb_tune;
        fprintf(output, "\n\n Tune Table\n\n");
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

int main(int argc, char *argv[])
{
    struct mnl_socket *nl;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    int ret, grp;
    int fam_id;
    int grp_id;
    FILE * output;

    // open the file to write out to
    if (argc != 2){
        fprintf(stderr,"Wrong number of arguments");
        exit(EXIT_FAILURE);
    }
    else {
	outputFile = argv[1];
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

    if (resolve_web10g_nladdr("tcp_estats", &fam_id, &grp_id)) {
        perror("resolve_web10g_nladdr");
        exit(EXIT_FAILURE);
    }

    mnl_socket_setsockopt(nl, NETLINK_ADD_MEMBERSHIP, &grp_id, sizeof(grp_id));

    while (1) {
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        if (ret == -1) {
            perror("mnl_socket_recvfrom");
            exit(EXIT_FAILURE);
        }
        ret = mnl_cb_run(buf, ret, 0, 0, data_cb, NULL);
        if (ret == -1) {
            perror("mnl_cb_run");
            exit(EXIT_FAILURE);
        }
    }

    mnl_socket_close(nl);

    return 0;
}
