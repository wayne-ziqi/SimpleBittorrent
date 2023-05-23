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
#include "sha1.h"

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
    // initialize torrent client basic info
    g_done = 0;
    g_tracker_response = NULL;
    pthread_mutex_init(&g_tracker_response_lock, NULL);
    srand(time(NULL));
    int val[5];
    for (int i = 0; i < 5; i++) {
        val[i] = rand();
    }
    memcpy(g_my_id, (uint8_t *) val, 20);
    printf("My id is: ");
    for (int i = 0; i < PEER_ID_LEN; ++i) {
        printf("%02x", g_my_id[i]);
    }
    printf("\n");
    strncpy(g_my_ip, argv[2], strlen(argv[2]));
    g_my_ip[strlen(argv[2]) + 1] = '\0';
    g_peerport = 2706;
    g_filename = argv[3];
    g_torrent_file_name = argv[1];
    // check if g_torrent_file_name end with .torrent
    size_t len = strlen(g_torrent_file_name);
    if (len < 8 || strcmp(g_torrent_file_name + len - 8, ".torrent") != 0) {
        printf("<init> torrent file name error\n");
        exit(-1);
    } else if (access(g_torrent_file_name, F_OK) == -1) {
        printf("<init> torrent file not exist\n");
        exit(-1);
    }

    // initialize torrent meta info
    g_torrentmeta = parsetorrentfile(g_torrent_file_name);
    memcpy(g_infohash, g_torrentmeta->info_hash, 20);
    g_filelen = g_torrentmeta->length;
    g_num_pieces = g_torrentmeta->num_pieces;
    g_piece_len = g_torrentmeta->piece_len;

    // initialize bitfield
    g_bitfield = bitfield_create(g_num_pieces);
    pthread_mutex_init(&g_bitfield_lock, NULL);

    if (access(argv[3], F_OK) != -1) {
        // check if *.bf exists, if so, load it and set bitfield, left, downloaded
        // else g_left = 0, g_downloaded = g_filelen
        char bf_file[256];
        strcpy(bf_file, g_torrent_file_name);
        strcat(bf_file, ".bf");
        if (access(bf_file, F_OK) != -1) {
            FILE *fp = fopen(bf_file, "rb");
            if (fp == NULL) {
                printf("<init>: fopen bf file error\n");
                exit(-1);
            }
            printf("<init>: loading bitfield from %s\n", bf_file);
            fseek(fp, 0, SEEK_END);
            int bf_size = (int) ftell(fp);
            fseek(fp, 0, SEEK_SET);
            uint8_t *bf = (uint8_t *) malloc(sizeof(uint8_t) * bf_size);
            fread(bf, sizeof(uint8_t), bf_size, fp);
            fclose(fp);
            fp = NULL;
            if (bf_size != g_num_pieces) {
                printf("<init>: bitfield size error, delete the .bf file and restart\n");
                exit(-1);
            }
            for (int i = 0; i < g_num_pieces; ++i) {
                g_bitfield->bitfield[i] = bf[i];
            }
            g_downloaded = 0, g_left = 0;
            for (int i = 0; i < g_bitfield->size; ++i) {
                int piece_len = g_piece_len;
                if (i == g_bitfield->size - 1) {
                    piece_len = g_filelen - (g_bitfield->size - 1) * g_piece_len;
                }
                if (bitfield_get(g_bitfield, i)) {
                    g_downloaded += piece_len;
                } else {
                    g_left += piece_len;
                }
            }
            free(bf);
            if (is_seed()) {
                printf("<init> File is complete, running as seed\n");
                // remove .bf file
                remove(bf_file);
            } else {
                printf("<init> File is not complete, running as client, left: %dB, downloaded: %dB\n", g_left,
                       g_downloaded);
            }
        } else {
            g_left = 0;
            g_downloaded = g_filelen;
            bitfield_fill(g_bitfield);
            g_file = fopen(argv[3], "r+");
            if (g_file == NULL) {
                printf("<init>: fopen error\n");
                exit(-1);
            }
            // checking file integrity
            int piece_len = g_piece_len;
            int num_pieces = g_num_pieces;
            int file_len = g_filelen;
            int last_piece_len = file_len % piece_len;
            if (last_piece_len == 0) {
                last_piece_len = piece_len;
            }
            fseek(g_file, 0, SEEK_SET);
            SHA1Context sha;
            printf("<init>: data file found, checking file integrity...\n");
            for (int i = 0; i < num_pieces; ++i) {
                if (i == num_pieces - 1) {
                    piece_len = last_piece_len;
                }
                uint8_t *piece = (uint8_t *) malloc(sizeof(uint8_t) * piece_len);
                fread(piece, sizeof(uint8_t), piece_len, g_file);
                SHA1Reset(&sha);
                SHA1Input(&sha, (uint8_t *) piece, piece_len);
                if (!SHA1Result(&sha)) {
                    printf("<init>: SHA1Result error\n");
                    exit(-1);
                }

                int piece_hash[5];
                memcpy(piece_hash, g_torrentmeta->pieces + 20 * i, 20);
                for (int j = 0; j < 5; ++j) {
                    piece_hash[j] = reverse_byte_orderi(piece_hash[j]);
                }
                if (memcmp(sha.Message_Digest, piece_hash, 20) != 0) {
                    printf("<init>: file integrity check failed, please delete and download again\n");
                    printf("<init> piece #%d expected: ", i);
                    for (int j = 0; j < 20; ++j) {
                        printf("%02x", g_torrentmeta->pieces[20 * i + j]);
                    }
                    printf(" got: ");
                    for (int j = 0; j < 5; ++j) {
                        printf("%02x", sha.Message_Digest[j]);
                    }
                    printf("\n");
                    exit(-1);
                } else {
                    printf("\r<init> check passed [%d]", i + 1);
                    fflush(stdout);
                }
                free(piece);
            }
            printf("\n<init> file check complete, running as seed.\n");
        }

    } else {
        g_left = g_filelen;
        g_downloaded = 0;
        bitfield_flush(g_bitfield);
        // create and open file
        int err = create_empty_file(argv[3], g_filelen, &g_file);
        if (err < 0) {
            printf("<init> create_empty_file error\n");
            exit(-1);
        }
        printf("<init> File does not exist, running as client.\n");
    }

    // initialize pieces


    g_pieces = (piece_t **) malloc(sizeof(piece_t *) * g_num_pieces);
    pthread_mutex_init(&g_pieces_lock, NULL);
    for (int i = 0; i < g_num_pieces; ++i) {
        if (i == g_num_pieces - 1)
            g_pieces[i] = piece_create(i, g_filelen - (g_num_pieces - 1) * g_piece_len);
        else
            g_pieces[i] = piece_create(i, g_piece_len);
    }
    if (is_seed()) {
        for (int i = 0; i < g_num_pieces; ++i) {
            g_pieces[i]->state = PIECE_DOWNLOADED;
            g_pieces[i]->num_blocks_downloaded = g_pieces[i]->num_blocks;
        }
    }

    // initialize peers
    bzero(g_peers, sizeof(g_peers));
    pthread_mutex_init(&g_peers_lock, NULL);
    g_uploaded = 0;
    g_downloaded = 0;

    // initialize tracker info
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

    // 设置监视器线程
    pthread_t monitor_thread;
    pthread_create(&monitor_thread, NULL, transmission_monitor, NULL);

    // 设置监听peer的线程
    pthread_t listen_thread;
    pthread_create(&listen_thread, NULL, listen_for_peers, NULL);

    // 设置连接peer的线程
    pthread_t connect_thread;
    pthread_create(&connect_thread, NULL, connect_to_peers, NULL);

    // 设置下载piece的线程
    pthread_t download_thread;
    pthread_create(&download_thread, NULL, download_handler, NULL);



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

        LOCK_TRACKER_RESPONSE;
        if (g_tracker_response != NULL)
            free(g_tracker_response);
        g_tracker_response = NULL;
        UNLOCK_TRACKER_RESPONSE;
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
        LOCK_TRACKER_RESPONSE;
        g_tracker_response = get_tracker_data(tmp2, tr->size);
        UNLOCK_TRACKER_RESPONSE;

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
        }

        // 必须等待td->interval秒, 然后再发出下一个GET请求
        sleep(g_tracker_response->interval);
    }

    // 睡眠以等待其他线程关闭它们的套接字, 只有在用户按下ctrl-c时才会到达这里
    printf("Application shutting down...\n");
    sleep(5);
    printf("bye\n");
    exit(0);
}
