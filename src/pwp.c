//
// Created by ziqi on 2023/5/18.
//

#include "pwp.h"
#include "util.h"

/**============================================
 * Peer connection
 * ============================================ */

int check_hand_shake(pwp_shaking_pkt *shake_pkt) {
    if (shake_pkt->pstrlen != strlen(BT_PROTOCOL_STR) &&
        strncmp(shake_pkt->pstr, BT_PROTOCOL_STR, strlen(BT_PROTOCOL_STR)) != 0) {
        printf("<listen_for_peers> Error: pstr is not BitTorrent protocol\n");
        return -1;
    }
    int reversed_info_hash[5];
    for (int i = 0; i < 5; ++i)
        reversed_info_hash[i] = reverse_byte_orderi(g_infohash[i]);
    if (!equal_sha1(shake_pkt->info_hash, (uint8_t *) reversed_info_hash)) {
        printf("<listen_for_peers> Error: info_hash is not equal\n needed: ");
        for (int i = 0; i < INFOHASH_LEN; ++i)
            printf("%02X", ((uint8_t *) g_torrentmeta->info_hash)[i]);
        printf(", got: ");
        for (int i = 0; i < INFOHASH_LEN; ++i)
            printf("%02X", shake_pkt->info_hash[i]);
        printf("\n");
        return -1;
    }
    return 1;
}

void *listen_for_peers(void *arg) {
    int listenfd, connfd;
    struct sockaddr_in clientaddr;
    socklen_t clientlen = sizeof(clientaddr);
    listenfd = make_listen_port(g_peerport);
    if (listenfd < 0) {
        printf("<listen_for_peers> Error: could not listen on port %d\n", g_peerport);
        exit(-1);
    }
    pwp_shaking_pkt *shake_pkt = (pwp_shaking_pkt *) malloc(sizeof(pwp_shaking_pkt));
    while (!g_done) {
        connfd = accept(listenfd, (struct sockaddr *) &clientaddr, &clientlen);
        if (connfd < 0) {
            printf("<listen_for_peers> Error: accept failed\n");
            close(connfd);
            continue;
        }
        printf("<listen_for_peers> Incoming connection from %s:%d\n", inet_ntoa(clientaddr.sin_addr),
               ntohs(clientaddr.sin_port));
        if (!peer_ip_exist(inet_ntoa(clientaddr.sin_addr))) {
            printf("<listen_for_peers> Error: peer is not recorded in tracker's response\n");
            close(connfd);
            continue;
        }
        bzero(shake_pkt, sizeof(pwp_shaking_pkt));
        ssize_t len = recv(connfd, shake_pkt, sizeof(pwp_shaking_pkt), 0);
        if (len != sizeof(pwp_shaking_pkt)) {
            printf("<listen_for_peers> Error: read shaking packet failed\n");
            close(connfd);
            continue;
        }
        if (check_hand_shake(shake_pkt) < 0) {
            printf("<listen_for_peers> Error: check handshake failed\n");
            close(connfd);
            continue;
        }
        int *peer_idx = (int *) malloc(sizeof(int));
        LOCK_PEERS;
        *peer_idx = get_peer_idx(shake_pkt->peer_id);
        UNLOCK_PEERS;
        if (*peer_idx == -1) {
            memcpy(shake_pkt->peer_id, g_my_id, PEER_ID_LEN);
            len = send(connfd, shake_pkt, sizeof(pwp_shaking_pkt), 0);
            if (len != sizeof(pwp_shaking_pkt)) {
                printf("<listen_for_peers> Error: send shaking packet failed\n");
                close(connfd);
                continue;
            }
            // peer_idx officially connected
            LOCK_PEERS;
            *peer_idx = add_peer(shake_pkt->peer_id, inet_ntoa(clientaddr.sin_addr),
                                 ntohs(clientaddr.sin_port), connfd);
            UNLOCK_PEERS;
            if (*peer_idx == -1) {
                printf("<listen_for_peers> Error: max peer num exceeded\n");
                close(connfd);
                continue;
            }
            printf("<listen_for_peers> Peer ");
            // peer_idx id
            for (int i = 0; i < PEER_ID_LEN; ++i) {
                printf("%02x", shake_pkt->peer_id[i]);
            }
            printf(" connected\n");
            // start a new thread to handle this peer_idx
            pthread_t peer_thread;
            pthread_create(&peer_thread, NULL, peer_handler, peer_idx);
        } else {
            printf("<listen_for_peers> Error: peer_idx already exist\n");
            LOCK_PEERS;
            remove_peer(*peer_idx);
            UNLOCK_PEERS;
            close(connfd);
            free(peer_idx);
            continue;
        }
    }
    free(shake_pkt);
    close(listenfd);
    return NULL;
}

void *peer_handler(void *arg) {
    int peer_idx = *((int *) arg);
    free(arg);
    peer_t *peer = g_peers[peer_idx];
    while (!g_done && g_peers[peer_idx]) {
        pwp_msg *msg = (pwp_msg *) malloc(sizeof(pwp_msg));
        int msg_len = recv_pwpmsg(peer->sockfd, msg);
        if (msg_len == -1) {
            printf("<peer_handler> Error: recv_pwpmsg failed\n");
            LOCK_PEERS;
            remove_peer(peer_idx);
            UNLOCK_PEERS;
            free_msg(msg);
            break;
        } else if (msg_len == 0) {
            // peer keep alive
            long now = now_seconds();
            peer->last_keep_alive = now;
        } else {
            LOCK_PEERS;
            switch (msg->id) {
                case CHOKE: {
                    printf("<peer_handler> Peer ");
                    for (int i = 0; i < PEER_ID_LEN; ++i) {
                        printf("%02x", peer->id[i]);
                    }
                    printf(" choked\n");
                    peer->am_choking = 1;
                    break;
                }
                case UNCHOKE: {
                    printf("<peer_handler> Peer ");
                    for (int i = 0; i < PEER_ID_LEN; ++i) {
                        printf("%02x", peer->id[i]);
                    }
                    printf(" unchoked\n");
                    peer->am_choking = 0;
                    break;
                }
                case INTERESTED: {
                    printf("<peer_handler> Peer ");
                    for (int i = 0; i < PEER_ID_LEN; ++i) {
                        printf("%02x", peer->id[i]);
                    }
                    printf(" interested\n");
                    // send unchoke
                    pwp_msg *unchoke_msg = (pwp_msg *) malloc(sizeof(pwp_msg));
                    unchoke_msg->id = UNCHOKE;
                    unchoke_msg->len = 1;
                    int len = send_pwpmsg(peer->sockfd, unchoke_msg);
                    if (len == -1) {
                        printf("<peer_handler> Error: send unchoke failed\n");
                        LOCK_PEERS;
                        remove_peer(peer_idx);
                        UNLOCK_PEERS;
                        free_msg(msg);
                        free_msg(unchoke_msg);
                    } else {
                        printf("<peer_handler> unchoke sent\n");
                        peer->peer_interested = 1;
                    }
                    break;
                }
                case NOT_INTERESTED: {
                    printf("<peer_handler> Peer ");
                    for (int i = 0; i < PEER_ID_LEN; ++i) {
                        printf("%02x", peer->id[i]);
                    }
                    printf(" not interested\n");
                    peer->peer_interested = 0;
                    break;
                }
                case HAVE: {
                    printf("<peer_handler> Peer ");
                    for (int i = 0; i < PEER_ID_LEN; ++i) {
                        printf("%02x", peer->id[i]);
                    }
                    assert(msg->len == 5);
                    int piece_idx = msg->payload[0];
                    printf(" have piece %d\n", piece_idx);
                    bitfield_set(peer->bitfield, piece_idx);
                    if (!bitfield_get(g_bitfield, piece_idx)) {
                        // peer has a piece that I don't have
                        if (!peer->am_interested) {
                            // send interested
                            peer->am_interested = 1;
                            pwp_msg *interested_msg = (pwp_msg *) malloc(sizeof(pwp_msg));
                            interested_msg->id = INTERESTED;
                            interested_msg->len = htonl(1);
                            interested_msg->payload = NULL;
                            send_pwpmsg(peer->sockfd, interested_msg);
                            free_msg(interested_msg);
                        }
                    }
                    // check whether I have all pieces and send not interested
                    if (bitfield_all_set(g_bitfield, peer->bitfield)) {
                        if (peer->am_interested) {
                            peer->am_interested = 0;
                            pwp_msg *not_interested_msg = (pwp_msg *) malloc(sizeof(pwp_msg));
                            not_interested_msg->id = NOT_INTERESTED;
                            not_interested_msg->len = htonl(1);
                            not_interested_msg->payload = NULL;
                            send_pwpmsg(peer->sockfd, not_interested_msg);
                            free_msg(not_interested_msg);
                        }
                    }
                    break;
                }
                case BITFIELD: {
                    printf("<peer_handler> Peer ");
                    for (int i = 0; i < PEER_ID_LEN; ++i) {
                        printf("%02x", peer->id[i]);
                    }
                    printf(" bitfield\n");
                    if (msg->len != 1 + BITFIELD_SIZE(g_bitfield->size)) {
                        printf("<peer_handler> Error: bitfield byte length not match, got: %d, expected: %d\n",
                               msg->len - 1, BITFIELD_SIZE(g_bitfield->size));
                        remove_peer(peer_idx);
                        break;
                    }
                    bitfield_t *msg_bitfield = bitfield_create_from_string(msg->payload, g_bitfield->size);
                    for (int i = 0; i < g_bitfield->size; ++i) {
                        if (bitfield_get(msg_bitfield, i)) {
                            bitfield_set(peer->bitfield, i);
                        } else {
                            bitfield_clear(peer->bitfield, i);
                        }
                    }
                    bitfield_destroy(msg_bitfield);
                    if (bitfield_all_set(g_bitfield, peer->bitfield)) {
                        if (peer->am_interested) {
                            peer->am_interested = 0;
                            pwp_msg *not_interested_msg = (pwp_msg *) malloc(sizeof(pwp_msg));
                            not_interested_msg->id = NOT_INTERESTED;
                            not_interested_msg->len = htonl(1);
                            not_interested_msg->payload = NULL;
                            send_pwpmsg(peer->sockfd, not_interested_msg);
                            free_msg(not_interested_msg);
                        }
                    } else {
                        if (!peer->am_interested) {
                            // send interested
                            peer->am_interested = 1;
                            pwp_msg *interested_msg = (pwp_msg *) malloc(sizeof(pwp_msg));
                            interested_msg->id = INTERESTED;
                            interested_msg->len = htonl(1);
                            interested_msg->payload = NULL;
                            send_pwpmsg(peer->sockfd, interested_msg);
                            free_msg(interested_msg);
                        }
                    }
                    break;
                }
                case REQUEST: {
                    printf("<peer_handler> Peer ");
                    for (int i = 0; i < PEER_ID_LEN; ++i) {
                        printf("%02x", peer->id[i]);
                    }
                    if (peer->peer_choking == 1) {
                        printf(" Error: peer choked\n");
                        break;
                    }
                    assert(msg->len == 13);
                    int piece_idx, block_offset, block_len;
                    extract_request_info(msg, &piece_idx, &block_offset, &block_len);
                    printf(" request piece %d, offset %d, len %d\n", piece_idx, block_offset, block_len);
                    // send piece if we have it
                    if (bitfield_get(g_bitfield, piece_idx) == 0) {
                        printf("<peer_handler> Error: don't have piece %d\n", piece_idx);
                        break;
                    }
                    if (block_len > 0) {
                        int reverse_idx = reverse_byte_orderi(piece_idx);
                        int reverse_offset = reverse_byte_orderi(block_offset);
                        char *block = (char *) malloc(block_len);
                        read_block(g_file, piece_idx, block_offset, block_len, block);
                        pwp_msg *piece_msg = (pwp_msg *) malloc(sizeof(pwp_msg));
                        piece_msg->id = PIECE;
                        piece_msg->len = htonl(9 + block_len);
                        piece_msg->payload = (uint8_t *) malloc(8 + block_len);
                        memcpy(piece_msg->payload, &reverse_idx, 4);
                        memcpy(piece_msg->payload + 4, &reverse_offset, 4);
                        memcpy(piece_msg->payload + 8, block, block_len);
                        send_pwpmsg(peer->sockfd, piece_msg);
                        free_msg(piece_msg);
                        free(block);
                    }
                    break;
                }
                case PIECE: {
                    printf("<peer_handler> Peer ");
                    for (int i = 0; i < PEER_ID_LEN; ++i) {
                        printf("%02x", peer->id[i]);
                    }
                    if (peer->am_interested == 0) {
                        printf(" Error: i'm not interested\n");
                        break;
                    }
                    assert(msg->len >= 9);
                    int piece_idx, block_offset, block_len;
                    char *block = NULL;
                    extract_piece_info(msg, &piece_idx, &block_offset, &block_len, &block);
                    printf(" piece, piece %d, offset %d, len %d\n", piece_idx, block_offset, block_len);
                    if (block_len > 0 && bitfield_get(g_bitfield, piece_idx) == 0) {
                        write_block(g_file, piece_idx, block_offset, block_len, block);
                    }
                    // TODO: determine when the piece is fully downloaded， maybe need a recorder
                    if (block_offset == 0 && block_len == g_piece_len) {
                        printf("piece %d fully downloaded\n", piece_idx);
                        bitfield_set(g_bitfield, piece_idx);
                    }
                    break;
                }
                case CANCEL: {
                    printf("<peer_handler> Peer ");
                    for (int i = 0; i < PEER_ID_LEN; ++i) {
                        printf("%02x", peer->id[i]);
                    }
                    assert(msg->len == 13);
                    int piece_idx, block_offset, block_len;
                    extract_request_info(msg, &piece_idx, &block_offset, &block_len);
                    printf(" cancel piece %d, offset %d, len %d\n", piece_idx, block_offset, block_len);
                    // TODO: cancel logic in end game
                    break;
                }
                default:
                    printf("<peer_handler> Error: unknown msg id\n");
                    break;
            } // switch(msg->id)
            UNLOCK_PEERS;
        }
        free_msg(msg);
    }
    return NULL;
}

void *connect_to_peers(void *arg) {
    while (!g_done) {
        if (g_tracker_response == NULL || g_tracker_response->numpeers == 0) {
            sleep(1);
            continue;
        }
        LOCK_TRACKER_RESPONSE;
        for (int i = 0; i < g_tracker_response->numpeers; ++i) {
            if (strcmp(g_tracker_response->peers[i].ip, g_my_ip) == 0) {
                continue;
            }
            int peer_idx = get_peer_idx_by_ip(g_tracker_response->peers[i].ip);
            if (peer_idx != -1) {
                continue;
            }
            struct handshake_arg_t {
                int port;
                char ip[16];
            };
            struct handshake_arg_t *handshake_arg = (struct handshake_arg_t *) malloc(sizeof(struct handshake_arg_t));
            handshake_arg->port = g_tracker_response->peers[i].port;
            strcpy(handshake_arg->ip, g_tracker_response->peers[i].ip);
            pthread_t handshake_thread;
            pthread_create(&handshake_thread, NULL, connect_to_handshake_handler, (void *) handshake_arg);
        }
        UNLOCK_TRACKER_RESPONSE;
        sleep(1);
    }
    return NULL;
}

void *connect_to_handshake_handler(void *arg) {
#define connect_to_handshake_handler_FAIL_RETURN {close(sockfd); free(handshake_arg); return NULL;}
    struct handshake_arg_t {
        int port;
        char ip[16];
    };
    struct handshake_arg_t *handshake_arg = (struct handshake_arg_t *) arg;
    int peer_port = handshake_arg->port;
    char *peer_ip = handshake_arg->ip;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("<connect_to_peer> Error: socket");
        connect_to_handshake_handler_FAIL_RETURN
    }
    struct sockaddr_in peer_addr;
    bzero(&peer_addr, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(peer_port);
    if (inet_pton(AF_INET, peer_ip, &peer_addr.sin_addr) <= 0) {
        perror("<connect_to_peer> Error: inet_pton");
        connect_to_handshake_handler_FAIL_RETURN;
    }
    if (connect(sockfd, (struct sockaddr *) &peer_addr, sizeof(peer_addr)) < 0) {
        perror("<connect_to_peer> Error: connect");
        connect_to_handshake_handler_FAIL_RETURN
    }
    int reversed_info_hash[5];
    for (int j = 0; j < 5; ++j)
        reversed_info_hash[j] = reverse_byte_orderi(g_infohash[j]);
    pwp_shaking_pkt *pkt = make_handshake_pkt((uint8_t *) reversed_info_hash, g_my_id);
    if (send(sockfd, pkt, HANDSHAKE_LEN, 0) < 0) {
        perror("<connect_to_peer> Error: send");
        connect_to_handshake_handler_FAIL_RETURN
    }
    free(pkt);
    printf("<connect_to_peer> Sent handshake to peer %s:%d\n", peer_ip, peer_port);
    // recv handshake and fill peer id into peer_idx
    pwp_shaking_pkt handshake;
    if (recv(sockfd, &handshake, HANDSHAKE_LEN, 0) < 0) {
        perror("<connect_to_peer> Error: recv");
        connect_to_handshake_handler_FAIL_RETURN
    }
    if (check_hand_shake(&handshake) < 0) {
        printf("<connect_to_peer> handshake check failed\n");
        connect_to_handshake_handler_FAIL_RETURN
    }
    LOCK_PEERS;
    int peer_idx = get_peer_idx(handshake.peer_id);
    UNLOCK_PEERS;
    if (peer_idx != -1) {
        printf("<connect_to_peer> redundant connection from peer %s:%d\n", peer_ip, peer_port);
        connect_to_handshake_handler_FAIL_RETURN
    } else {
        printf("<connect_to_peer> Connected to peer ");
        for (int j = 0; j < PEER_ID_LEN; ++j) {
            printf("%02x", handshake.peer_id[j]);
        }
        printf("\n");
        LOCK_PEERS;
        peer_idx = add_peer(handshake.peer_id, peer_ip, peer_port, sockfd);
        UNLOCK_PEERS;
        if (peer_idx == -1) {
            printf("<connect_to_peer> Error: add_peer, peer max num exceeded\n");
            connect_to_handshake_handler_FAIL_RETURN
        }

        // start peer thread to handle coming messages
        int *peer_idx_ptr = (int *) malloc(sizeof(int));
        *peer_idx_ptr = peer_idx;
        pthread_t peer_thread;
        pthread_create(&peer_thread, NULL, peer_handler, peer_idx_ptr);

        // send bitfield
        pwp_msg *bitfield_pkt = (pwp_msg *) malloc(sizeof(pwp_msg));
        bitfield_pkt->len = htonl(1 + BITFIELD_SIZE(g_bitfield->size));
        bitfield_pkt->id = BITFIELD;
        bitfield_pkt->payload = (uint8_t *) malloc(BITFIELD_SIZE(g_bitfield->size));
        memcpy(bitfield_pkt->payload, g_bitfield->bitfield, BITFIELD_SIZE(g_bitfield->size));
        if (send(sockfd, bitfield_pkt, 1 + BITFIELD_SIZE(g_bitfield->size), 0) < 0) {
            perror("<connect_to_peer> Error: send");
            connect_to_handshake_handler_FAIL_RETURN
        }
        free_msg(bitfield_pkt);
    }
    free(handshake_arg);
    return NULL;
}


/**============================================
 * Peer management
 * ============================================ */

int get_peer_idx(uint8_t *peer_id) {
    for (int i = 0; i < MAXPEERS; ++i) {
        if (g_peers[i] != NULL) {
            if (memcmp(g_peers[i]->id, peer_id, 20) == 0) {
                return i;
            }
        }
    }
    return -1;
}

int get_peer_idx_by_ip(char *ip) {
    for (int i = 0; i < MAXPEERS; ++i) {
        if (g_peers[i] != NULL) {
            if (strcmp(g_peers[i]->ip, ip) == 0) {
                return i;
            }
        }
    }
    return -1;
}

int add_peer(uint8_t *peer_id, char *ip, int port, int socket) {
    for (int i = 0; i < MAXPEERS; ++i) {
        if (g_peers[i] == NULL) {
            g_peers[i] = (peer_t *) malloc(sizeof(peer_t));
            g_peers[i]->sockfd = socket;
            assert(peer_id != NULL);
            memcpy(g_peers[i]->id, peer_id, PEER_ID_LEN);
            strcpy(g_peers[i]->ip, ip);
            g_peers[i]->port = port;
            g_peers[i]->last_keep_alive = now_seconds();
            g_peers[i]->bitfield = bitfield_create(g_num_pieces);
            g_peers[i]->am_choking = 1;
            g_peers[i]->am_interested = 0;
            g_peers[i]->peer_choking = 1;
            g_peers[i]->peer_interested = 0;
            return i;
        }
    }
    return -1;
}

void remove_peer(int peer_idx) {
    assert(peer_idx >= 0 && peer_idx < MAXPEERS);
    if (g_peers[peer_idx] != NULL) {
        if (g_peers[peer_idx]->sockfd > 0)
            close(g_peers[peer_idx]->sockfd);
        bitfield_destroy(g_peers[peer_idx]->bitfield);
        free(g_peers[peer_idx]);
        g_peers[peer_idx] = NULL;
    }
}


int peer_ip_exist(char *ip) {
    if (g_tracker_response == NULL) {
        printf("<peer_ip_exist> Error: g_tracker_response is NULL\n");
        return 0;
    }
    LOCK_TRACKER_RESPONSE;
    for (int i = 0; i < g_tracker_response->numpeers; ++i) {
        if (strcmp(g_tracker_response->peers[i].ip, ip) == 0) {
            return 1;
        }
    }
    UNLOCK_TRACKER_RESPONSE;
    return 0;
}

/**============================================
 * Peer packet and message functions
 * ============================================ */

pwp_shaking_pkt *make_handshake_pkt(uint8_t *info_hash, uint8_t *peer_id) {
    pwp_shaking_pkt *pkt = (pwp_shaking_pkt *) malloc(sizeof(pwp_shaking_pkt));
    bzero(pkt, sizeof(pwp_shaking_pkt));
    pkt->pstrlen = 19;
    memcpy(pkt->pstr, BT_PROTOCOL_STR, 19);
    memcpy(pkt->reserved, BT_RESERVED_STR, 8);
    memcpy(pkt->info_hash, info_hash, 20);
    memcpy(pkt->peer_id, peer_id, 20);
    return pkt;
}

int recv_pwpmsg(int sockfd, pwp_msg *pkt) {
    ssize_t len = recv(sockfd, &pkt->len, sizeof(pkt->len), 0);
    if (len != sizeof(pkt->len)) {
        printf("<recv_pwpmsg> Error: recv msg length failed\n");
        return -1;
    }
    pkt->len = ntohl(pkt->len);
    if (pkt->len == 0) {
        // keep alive
        return 0;
    }
    len = recv(sockfd, &pkt->id, sizeof(pkt->id), 0);
    if (len != sizeof(pkt->id)) {
        printf("<recv_pwpmsg> Error: recv msg id failed\n");
        return -1;
    }
    if (pkt->len == 1) {
        // have no payload
        pkt->payload = NULL;
        return (int) pkt->len;
    }
    assert(sizeof(pkt->id) == 1);
    pkt->payload = (uint8_t *) malloc(pkt->len - sizeof(pkt->id));
    len = recv(sockfd, pkt->payload, pkt->len - sizeof(pkt->id), 0);
    if (len != pkt->len - sizeof(pkt->id)) {
        printf("<recv_pwpmsg> Error: recv msg payload failed\n");
        return -1;
    }
    return (int) pkt->len;
}

int send_pwpmsg(int sockfd, pwp_msg *pkt) {
    ssize_t len = send(sockfd, &pkt->len, sizeof(pkt->len), 0);
    if (len != sizeof(pkt->len)) {
        printf("<send_pwpmsg> Error: send msg length failed\n");
        return -1;
    }
    pkt->len = ntohl(pkt->len);
    if (pkt->len == 0) {
        // keep alive
        return 0;
    }
    len = send(sockfd, &pkt->id, sizeof(pkt->id), 0);
    if (len != sizeof(pkt->id)) {
        printf("<send_pwpmsg> Error: send msg id failed\n");
        return -1;
    }
    if (pkt->len == 1) {
        // have no payload
        return 1;
    }
    assert(sizeof(pkt->id) == 1);
    assert(pkt->payload != NULL);
    len = send(sockfd, pkt->payload, pkt->len - sizeof(pkt->id), 0);
    if (len != pkt->len - sizeof(pkt->id)) {
        printf("<send_pwpmsg> Error: send msg payload failed\n");
        return -1;
    }
    return (int) pkt->len;
}

void free_msg(pwp_msg *pkt) {
    if (pkt->payload != NULL)
        free(pkt->payload);
    free(pkt);
}

void extract_request_info(pwp_msg *pkt, int *index, int *begin, int *length) {
    *index = pkt->payload[0] << 24 | pkt->payload[1] << 16 | pkt->payload[2] << 8 | pkt->payload[3];
    *begin = pkt->payload[4] << 24 | pkt->payload[5] << 16 | pkt->payload[6] << 8 | pkt->payload[7];
    *length = pkt->payload[8] << 24 | pkt->payload[9] << 16 | pkt->payload[10] << 8 | pkt->payload[11];
}

void extract_piece_info(pwp_msg *pkt, int *index, int *begin, int *length, char **block) {
    *index = pkt->payload[0] << 24 | pkt->payload[1] << 16 | pkt->payload[2] << 8 | pkt->payload[3];
    *begin = pkt->payload[4] << 24 | pkt->payload[5] << 16 | pkt->payload[6] << 8 | pkt->payload[7];
    *length = (int) pkt->len - 9;
    if (*length > 0)
        *block = (char *) malloc(*length);
    memcpy(*block, pkt->payload + 8, *length);
}
