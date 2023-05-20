#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include "util.h"
#include "btdata.h"
#include "bencode.h"
#include "pwp.h"

//#define MAXLINE 4096
// pthread数据

int create_empty_file(const char *filename, int size, FILE **fp) {
    *fp = fopen(filename, "w");
    if (fp == NULL) {
        printf("create_empty_file: fopen error\n");
        return -1;
    }
    fseek(*fp, size - 1, SEEK_SET);
    fputc('\0', *fp);
    return 0;
}

void init(int argc, char **argv) {
    if (argc < 4) {
        printf("Usage: simpleTorrent <torrent file> <ip of this machine (XXX.XXX.XXX.XXX form)> <file target location>\n");
        printf("\t i will judge from the file's existence in the target location and determine if you are seed or not\n");
        exit(-1);
    }
    g_done = 0;
    g_tracker_response = NULL;
    srand(time(NULL));
    int val[5];
    for (int i = 0; i < 5; i++) {
        val[i] = rand();
    }
    memcpy(g_my_id, (char *) val, 20);
    strncpy(g_my_ip, argv[2], strlen(argv[2]));
    g_my_ip[strlen(argv[2]) + 1] = '\0';
    g_filename = argv[3];
    g_torrentmeta = parsetorrentfile(argv[1]);
    memcpy(g_infohash, g_torrentmeta->info_hash, 20);
    g_filelen = g_torrentmeta->length;
    g_num_pieces = g_torrentmeta->num_pieces;
    g_piece_len = g_torrentmeta->piece_len;
    g_peerport = 2706;
    if (access(argv[3], F_OK) != -1) {
        g_left = 0;
        g_file = fopen(argv[3], "r+");
        if (g_file == NULL) {
            printf("<init>: fopen error\n");
            exit(-1);
        }
        printf("File already exists, running as seed.\n");
    } else {
        g_left = g_num_pieces;
        int err = create_empty_file(argv[3], g_filelen, &g_file);
        if (err < 0) {
            printf("<init>: create_empty_file error\n");
            exit(-1);
        }
        printf("File does not exist, running as client.\n");
    }
    g_bitfield = bitfield_create(g_num_pieces);
    pthread_mutex_init(&g_bitfield_lock, NULL);
    for (int i = 0; i < g_bitfield->size; ++i) {
        if (is_seed()) {
            bitfield_set(g_bitfield, i);
        } else {
            bitfield_clear(g_bitfield, i);
        }
    }
    bzero(g_peers, sizeof(g_peers));
    pthread_mutex_init(&g_peers_lock, NULL);
    g_uploaded = 0;
    g_downloaded = 0;

    announce_url_t *announce_info;
    announce_info = parse_announce_url(g_torrentmeta->announce);
    // 提取tracker url中的IP地址
    printf("HOSTNAME: %s\n", announce_info->hostname);
    struct hostent *record;
    record = gethostbyname(announce_info->hostname);
    if (record == NULL) {
        printf("gethostbyname(%s) failed", announce_info->hostname);
        exit(1);
    }
    struct in_addr *address;
    address = (struct in_addr *) record->h_addr_list[0];
    printf("Tracker IP Address: %s\n", inet_ntoa(*address));
    strcpy(g_tracker_ip, inet_ntoa(*address));
    g_tracker_port = announce_info->port;

    free(announce_info);
    announce_info = NULL;
}

int main(int argc, char **argv) {
    int sockfd = -1;
    char rcvline[MAXLINE];
    char tmp[MAXLINE];

    int i;

    // 初始化全局变量
    init(argc, argv);

    // 设置信号句柄
    signal(SIGINT, client_shutdown);

    // 设置监听peer的线程

    pthread_t listen_thread;
    pthread_create(&listen_thread, NULL, listen_for_peers, NULL);

    // 定期联系Tracker服务器
    int firsttime = 1;
    int mlen;
    char *MESG;
    MESG = make_tracker_request(BT_STARTED, &mlen);
    while (!g_done) {
        assert(sockfd <= 0);
        //创建套接字发送报文给Tracker
        printf("Creating socket to tracker...\n");
        sockfd = connect_to_host(g_tracker_ip, g_tracker_port);
        if (sockfd < 0) {
            sleep(5);
            continue;
        }
        printf("Sending request to tracker...\n");

        if (!firsttime) {
            free(MESG);
            // -1 指定不发送event参数
            MESG = make_tracker_request(-1, &mlen);
            printf("send MESG again: ");
            for (i = 0; i < mlen; i++)
                printf("%c", MESG[i]);
            printf("\n");
        }
        send(sockfd, MESG, mlen, 0);
        firsttime = 0;

        memset(rcvline, 0x0, MAXLINE);
        memset(tmp, 0x0, MAXLINE);

        // 读取并处理来自Tracker的响应
        tracker_response *tr;
        tr = preprocess_tracker_response(sockfd);

        // 关闭套接字, 以便再次使用
        shutdown(sockfd, SHUT_RDWR);
        close(sockfd);
        sockfd = 0;

        printf("Decoding response...\n");
        char *tmp2 = (char *) malloc(tr->size * sizeof(char));
        memcpy(tmp2, tr->data, tr->size * sizeof(char));

        printf("Parsing tracker data\n");
        g_tracker_response = get_tracker_data(tmp2, tr->size);

        if (tmp2) {
            free(tmp2);
            tmp2 = NULL;
        }

        printf("Num Peers: %d\n", g_tracker_response->numpeers);
        for (i = 0; i < g_tracker_response->numpeers; i++) {
//            printf("Peer id: ");
//            int idl;
//            for (idl = 0; idl < 20; idl++)
//                printf("%02X ", (unsigned char) g_tracker_response->peers[i].id[idl]);
//            printf("\n");
            printf("Peer ip: %s\n", g_tracker_response->peers[i].ip);
            printf("Peer port: %d\n", g_tracker_response->peers[i].port);
            if (is_seed()) {

            }
        }

        // 必须等待td->interval秒, 然后再发出下一个GET请求
        sleep(g_tracker_response->interval);
    }

    // 睡眠以等待其他线程关闭它们的套接字, 只有在用户按下ctrl-c时才会到达这里
    printf("Application shutting down...\n");
    fclose(g_file);
    sleep(2);
    exit(0);
}
