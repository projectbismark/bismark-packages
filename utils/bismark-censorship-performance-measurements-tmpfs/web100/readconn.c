#include <stdio.h>
#include <stdlib.h>

#include "web100.h"

int main(int argc, char *argv[])
{
    web100_agent       *agent;
    web100_group       *group;
    web100_connection  *conn;

    struct web100_connection_spec spec;

    char buf[8];
    int  cid;
    if (argc != 2 ) {
        fprintf(stdout, "Usage %s <connection_id>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // initialize the stat measurement stuff
    if ((agent = web100_attach(WEB100_AGENT_TYPE_LOCAL, NULL)) == NULL) {
        web100_perror("web100_attach");
        exit(EXIT_FAILURE);
    }
    cid  = atoi(argv[1]);
    conn = web100_connection_lookup(agent, cid);
    if(conn == NULL){
        fprintf(stdout, "Error creating connection to stats files. Are you root?\n");
        exit(EXIT_FAILURE);
    }
    web100_get_connection_spec(conn, &spec);
    {
        unsigned char *src = (unsigned char *)&spec.src_addr;
        unsigned char *dst = (unsigned char *)&spec.dst_addr;
        printf("Connection %d (%u.%u.%u.%u:%u %u.%u.%u.%u:%u)\n",
               cid,
               src[0], src[1], src[2], src[3], spec.src_port,
               dst[0], dst[1], dst[2], dst[3], spec.dst_port);
    }

    group = web100_group_head(agent); // begin at the head

    while (group) {                   // loop through all the groups

        web100_var      *var;
        web100_snapshot *snap;

        printf("Group \"%s\"\n", web100_get_group_name(group));

        if ((snap = web100_snapshot_alloc(group, conn)) == NULL) {
            web100_perror("web100_snapshot_alloc");
            exit(EXIT_FAILURE);
        }

        if (web100_snap(snap)) {
            perror("web100_snap");
            if (web100_errno == WEB100_ERR_NOCONNECTION)
                continue;
            exit(EXIT_FAILURE);
        }

        var = web100_var_head(group);
        while (var) {
            if (web100_snap_read(var, snap, buf)) {
                web100_perror("web100_snap_read");
                exit(EXIT_FAILURE);
            }

            printf("%-20s %s\n",
                   web100_get_var_name(var),
                   web100_value_to_text(web100_get_var_type(var), buf));

            var = web100_var_next(var);
        }

        web100_snapshot_free(snap);
        group = web100_group_next(group);

        if (group != NULL){
            printf("\n");
        }
    }
    printf("\n");
    return 0;
}
