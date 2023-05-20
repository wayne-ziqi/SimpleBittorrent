//
// Created by ziqi on 2023/5/18.
//

#ifndef SIMPLETORRENT_PWP_H
#define SIMPLETORRENT_PWP_H

#include "bitfield.h"

#define HANDSHAKE_LEN 68  // peer握手消息的长度, 以字节为单位
#define BT_PROTOCOL_STR "BitTorrent protocol"
#define BT_RESERVED_STR "\0\0\0\0\0\0\0\0"
#define INFOHASH_LEN 20
#define PEER_ID_LEN 20
#define MAXPEERS 100
#define KEEP_ALIVE_INTERVAL 3
#define KEEP_ALIVE_TIMEOUT 120

#define CHOKE 0
#define UNCHOKE 1
#define INTERESTED 2
#define NOT_INTERESTED 3
#define HAVE 4
#define BITFIELD 5
#define REQUEST 6
#define PIECE 7
#define CANCEL 8

typedef struct pwp_shaking{
    uint8_t pstrlen; // string length of <pstr>, as a single raw byte
    char pstr[19]; // string identifier of the protocol
    uint8_t reserved[8]; // eight (8) reserved bytes. All current implementations use all zeroes. Each bit in these bytes can be used to change the behavior of the protocol. An email from Bram suggests that trailing bits should be used first, so that leading bits may be used to change the meaning of trailing bits.
    uint8_t info_hash[20]; // 20-byte SHA1 hash of the info key in the metainfo file. This is the same info_hash that is transmitted in tracker requests.
    uint8_t peer_id[20]; // 20-byte string used as a unique ID for the client, generated by the client at startup. This is allowed to be any value, and may be binary data.
}pwp_shaking_pkt;

typedef struct pwp_msg_type{
    uint32_t len; // length of <payload>, in bytes (big endian)
    uint8_t id; // id of message, as a single raw byte
    uint8_t *payload; // payload of message. Generally, this is either a string or a number of integers.
}pwp_msg;

// 针对到一个peer的已建立连接, 维护相关数据
typedef struct _peer_t {
    char ip[16];
    int port;
    uint8_t id[20];
    long last_keep_alive;
    bitfield_t *bitfield;
    int sockfd;
    int am_choking;        // 作为上传者, 阻塞远端peer
    int am_interested;     // 远端peer对我们的分片有兴趣
    int peer_choking;         // 作为下载者, 我们被远端peer阻塞
    int peer_interested;  // 作为下载者, 对远端peer的分片有兴趣

} peer_t;

/**
 * check handshake basic info (length, protocol, reserved, info_hash)
 */
int check_hand_shake(pwp_shaking_pkt * shake_pkt);

/**
 * some peers want to download from me, so I need to listen to them, this thread
 * upload downloaded pieces to interested peers
 */
void* listen_for_peers(void *arg);

/**
 * handle connection after handshake
 */
void* peer_handler(void *arg);

/**
 * connect to peers
 */
void *connect_to_peers(void *arg);

/**
 * connect to peers and send the first hanshake message
 * receive handshake message from peer and send bitfield message
 */
void *connect_to_handshake_handler(void *arg);

/**
 * check if peer_id is in g_peers
 */
int get_peer_idx(uint8_t *peer_id);

/**
 * check if ip is in g_peers
 */
int get_peer_idx_by_ip(char *ip);

/**
 * add peer_id to g_peers
 */
int add_peer(uint8_t *peer_id, char*ip, int port,  int socket);

/**
 * remove peer_id from g_peers
 */
void remove_peer(int peer_idx);

/**
 * check if ip is in g_tracker_response
 */
int peer_ip_exist(char *ip);

/**
 * make a handshake packet
 */
pwp_shaking_pkt * make_handshake_pkt(uint8_t *info_hash, uint8_t *peer_id);

/**
 * receive a packet from peer
 */
int recv_pwpmsg(int sockfd, pwp_msg *pkt);

/**
 * send a packet to peer
 */

int send_pwpmsg(int sockfd, pwp_msg *pkt);

/**
 * free a message
 */
void free_msg(pwp_msg *pkt);

/**
 * extract request info
 */
void extract_request_info(pwp_msg *pkt, int *index, int *begin, int *length);

/**
 * extract piece info
 */
void extract_piece_info(pwp_msg *pkt, int *index, int *begin, int *length, char**block);

#endif //SIMPLETORRENT_PWP_H
