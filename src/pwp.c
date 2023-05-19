//
// Created by ziqi on 2023/5/18.
//

#include "pwp.h"

void* upload_for_peers(void *arg) {
    int listenfd, connfd;
    listenfd = make_listen_port(g_peerport);
    if (listenfd < 0) {
        printf("Error: could not listen on port %d\n", g_peerport);
        exit(-1);
    }
    while (!g_done) {
        connfd = accept(listenfd, (struct sockaddr *) NULL, NULL);
        if (connfd < 0) {
            printf("Error: accept failed\n");
            exit(-1);
        }
        // TODO: handle incoming connections and record them in g_peers
        
    }
    return NULL;
}

void* download_from_peers(void *arg){
    return NULL;
}