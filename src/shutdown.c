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

    // if download is not finished, save the global state to file *.bf under the same directory of the torrent file
    if (!is_seed()) {
        sleep(1); // wait for other threads to finish
        char bf_file[256];
        strcpy(bf_file, g_torrent_file_name);
        strcat(bf_file, ".bf");
        printf("<client_shutdown> save bitfield to file %s\n", bf_file);
        FILE *fp = fopen(bf_file, "wb");
        fwrite(g_bitfield->bitfield, sizeof(uint8_t), g_bitfield->size, fp);
        fclose(fp);
        printf("<client_shutdown> bitfield saved\n");
    }
}
