#include "btdata.h"
#include "util.h"

// 正确的关闭客户端
void client_shutdown(int sig) {
    // 设置全局停止变量以停止连接到其他peer, 以及允许其他peer的连接. Set global stop variable so that we stop trying to connect to peers and
    // 这控制了其他peer连接的套接字和连接到其他peer的线程.
    g_done = 1;
    // do some cleanup
    if (g_file)
        fclose(g_file);
    int mlen;
    char *MESG = make_tracker_request(BT_STOPPED, &mlen);
    printf("<client_shutdown> connect to tracker\n");
    int sockfd = connect_to_host(g_tracker_ip, g_tracker_port);
    printf("<client_shutdown> send stopped to tracker\n");
    send(sockfd, MESG, mlen, 0);
    printf("<client_shutdown> close tracker\n");
    close(sockfd);
    free(MESG);
}
