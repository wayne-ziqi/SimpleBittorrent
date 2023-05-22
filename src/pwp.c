//
// Created by ziqi on 2023/5/18.
//

#include "pwp.h"
#include "piece.h"
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
            close(listenfd);
            listenfd = make_listen_port(g_peerport);
            sleep(1);
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
//        *peer_idx = get_peer_idx(shake_pkt->peer_id);
        *peer_idx = get_peer_idx_by_ip(inet_ntoa(clientaddr.sin_addr));
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
            *peer_idx = add_peer(inet_ntoa(clientaddr.sin_addr),
                                 ntohs(clientaddr.sin_port), connfd);
            UNLOCK_PEERS;
            if (*peer_idx == -1) {
                printf("<listen_for_peers> Error: max peer num exceeded\n");
                close(connfd);
                continue;
            }
            printf("<listen_for_peers> Peer %s:%d connected\n", inet_ntoa(clientaddr.sin_addr),
                   ntohs(clientaddr.sin_port));
            // start a new thread to handle this peer_idx
            pthread_t peer_thread;
            pthread_create(&peer_thread, NULL, peer_handler, peer_idx);

            // send bitfield
            pwp_msg *bitfield_msg = make_bitfield_msg(g_bitfield);
            if (send_pwpmsg(connfd, bitfield_msg) < 0) {
                perror("<connect_to_peer> Error: send");
            }
            free_msg(bitfield_msg);

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
        bzero(msg, sizeof(pwp_msg));
        int msg_len = recv_pwpmsg(peer->sockfd, msg);
        if (msg_len == -1) {
            printf("<peer_handler> closing peer %s:%d\n", peer->ip, peer->port);
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
            LOCK_PEERS; // lock peers, visiting to peers in switch are all safe
            switch (msg->id) {
                case CHOKE: {
                    printf("<peer_handler> Peer %s:%d choked me\n", peer->ip, peer->port);
                    peer->am_choking = 1;
                    break;
                }
                case UNCHOKE: {
                    printf("<peer_handler> Peer %s:%d unchoked me\n", peer->ip, peer->port);
                    peer->am_choking = 0;
                    break;
                }
                case INTERESTED: {
                    printf("<peer_handler> Peer %s:%d interested\n", peer->ip, peer->port);
                    // send unchoke
                    pwp_msg *unchoke_msg = make_unchoke_msg();
                    send_pwpmsg(peer->sockfd, unchoke_msg);
                    printf("<peer_handler> unchoke sent\n");
                    peer->peer_choking = 0;
                    peer->peer_interested = 1;

                }
                case NOT_INTERESTED: {
                    printf("<peer_handler> Peer %s:%d not interested\n", peer->ip, peer->port);
                    peer->peer_interested = 0;
                    // don't send choke
                    break;
                }
                case HAVE: {
                    assert(msg->len == 5);
                    printf("<peer_handler> Peer %s:%d", peer->ip, peer->port);
                    int piece_idx = msg->payload[0];
                    printf(" have piece %d\n", piece_idx);
                    if (!bitfield_get(g_bitfield, piece_idx)) {
                        // peer has a piece that I don't have
                        bitfield_set(peer->bitfield, piece_idx);
                        if (!peer->am_interested) {
                            // send interested
                            peer->am_interested = 1;
                            pwp_msg *interested_msg = make_interested_msg();
                            send_pwpmsg(peer->sockfd, interested_msg);
                            free_msg(interested_msg);
                        }
                    }
                    // check whether I have all pieces and send not interested
                    if (bitfield_all_set(g_bitfield, peer->bitfield)) {
                        if (peer->am_interested) {
                            peer->am_interested = 0;
                            pwp_msg *not_interested_msg = make_not_interested_msg();
                            send_pwpmsg(peer->sockfd, not_interested_msg);
                            free_msg(not_interested_msg);
                        }
                    }
                    break;
                }
                case BITFIELD: {
                    printf("<peer_handler> Peer %s:%d bitfield\n", peer->ip, peer->port);
//                    print_peer_id(peer->id)
//                    printf(" bitfield\n");
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
                    bitfield_free(msg_bitfield);

                    // seed<->seed detection
                    if (is_seed() && bitfield_full(peer->bitfield)) {
                        printf("<peer_handler> seed<->seed detected\n");
                        // add peer to seed list
                        remove_peer(peer_idx);
                        break;
                    }

                    if (bitfield_all_set(g_bitfield, peer->bitfield)) {
                        if (peer->am_interested) {
                            peer->am_interested = 0;
                            pwp_msg *not_interested_msg = make_not_interested_msg();
                            send_pwpmsg(peer->sockfd, not_interested_msg);
                            free_msg(not_interested_msg);
                            printf("<peer_handler> not interested to peer %s:%d sent\n", peer->ip, peer->port);
//                            print_peer_id(peer->id)
//                            printf(" sent\n");
                            // close connection
                            break;
                        }
                    } else {
                        if (!peer->am_interested) {
                            // send interested
                            peer->am_interested = 1;
                            pwp_msg *interested_msg = make_interested_msg();
                            send_pwpmsg(peer->sockfd, interested_msg);
                            free_msg(interested_msg);
                            printf("<peer_handler> interested to peer %s:%d sent\n", peer->ip, peer->port);
                        }
                    }
                    break;
                }
                case REQUEST: {
                    printf("<peer_handler> Peer %s:%d request\n", peer->ip, peer->port);
//                    print_peer_id(peer->id)
                    if (peer->peer_choking == 1) {
                        printf("<peer_handler> Error: peer choked\n");
                        break;
                    }

                    if (peer->peer_interested == 0) {
                        peer->peer_interested = 1;
                        printf("<peer_handler> peer not interested, set to interested\n");
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
                        uint8_t *block = (uint8_t *) malloc(block_len);
                        read_block(piece_idx, block_offset, block_len, block);
                        pwp_msg *piece_msg = make_piece_msg(piece_idx, block_offset, block_len, block);
                        send_pwpmsg(peer->sockfd, piece_msg);
                        free_msg(piece_msg);
                        free(block);
                    }
                    break;
                }
                case PIECE: {
                    printf("<peer_handler> Peer %s:%d send piece\n", peer->ip, peer->port);
//                    print_peer_id(peer->id)
//                    printf(" piece\n");
                    if (peer->am_interested == 0) {
                        printf(" Error: i'm not interested\n");
                        pwp_msg *not_interested_msg = make_not_interested_msg();
                        send_pwpmsg(peer->sockfd, not_interested_msg);
                        free_msg(not_interested_msg);
                        break;
                    }
                    assert(msg->len >= 9);
                    int piece_idx, block_offset, block_len;
                    uint8_t *block = NULL;
                    extract_piece_info(msg, &piece_idx, &block_offset, &block_len, &block);
                    printf("<peer_handler> piece msg, piece %d, offset %d, len %d\n", piece_idx, block_offset,
                           block_len);
                    if (block_len > 0 && bitfield_get(g_bitfield, piece_idx) == 0) {
                        write_block(piece_idx, block_offset, block_len, block);
                    }
                    free(block);
                    // determine when the piece is fully downloaded， maybe need a recorder, remember to add mutex
                    LOCK_PIECES;
                    piece_t *piece = g_pieces[piece_idx];
                    piece_set_block(piece, block_offset, block_len);
                    if (piece_full(piece)) {
                        UNLOCK_PIECES;
                        printf("<peer_handler> Piece #%d fully downloaded\n", piece_idx);
                        LOCK_BITFIELD;
                        bitfield_set(g_bitfield, piece_idx);
                        UNLOCK_BITFIELD;

                        LOCK_PIECES;
                        g_pieces[piece_idx]->state = PIECE_DOWNLOADED;
                        UNLOCK_PIECES;

                        LOCK_VARIABLE;
                        g_downloaded += g_pieces[piece_idx]->length;
                        g_left -= g_pieces[piece_idx]->length;
                        assert(g_left >= 0);
                        UNLOCK_VARIABLE;
                        break;
                    }
                    UNLOCK_PIECES;
                    break;
                }
                case CANCEL: {
                    printf("<peer_handler> Peer %s:%d cancel\n", peer->ip, peer->port);
//                    print_peer_id(peer->id)
//                    assert(msg->len == 13);
                    int piece_idx, block_offset, block_len;
                    extract_request_info(msg, &piece_idx, &block_offset, &block_len);
                    printf("<peer_handler> cancel piece %d, offset %d, len %d\n", piece_idx, block_offset, block_len);
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
        // FIXME: extract ip:port from tracker response and record number of connection fails,
        // if fails too many times, remove it from extracted data
        LOCK_TRACKER_RESPONSE;
        for (int i = 0; i < g_tracker_response->numpeers; ++i) {
            if (strcmp(g_tracker_response->peers[i].ip, g_my_ip) == 0) {
                continue;
            }
            LOCK_PEERS;
            int peer_idx = get_peer_idx_by_ip(g_tracker_response->peers[i].ip);
            UNLOCK_PEERS;
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
        sleep(5);
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
    int sockfd = connect_to_host(peer_ip, peer_port);
    if (sockfd < 0) {
        printf("<connect_to_peer> Error: connect to peer %s:%d\n", peer_ip, peer_port);
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
//    int peer_idx = get_peer_idx(handshake.peer_id);
    int peer_idx = get_peer_idx_by_ip(peer_ip);
    UNLOCK_PEERS;
    if (peer_idx != -1) {
        printf("<connect_to_peer> redundant connection from peer %s:%d\n", peer_ip, peer_port);
        connect_to_handshake_handler_FAIL_RETURN
    } else {
        printf("<connect_to_peer> Connected to peer %s:%d\n", peer_ip, peer_port);
//        print_peer_id(handshake.peer_id);
//        printf("\n");
        LOCK_PEERS;
        peer_idx = add_peer(peer_ip, peer_port, sockfd);
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
        if (is_seed()) {
            pwp_msg *msg = make_bitfield_msg(g_bitfield);
            send_pwpmsg(sockfd, msg);
            free(msg);
            printf("<connect_to_peer> Sent bitfield to peer %s:%d\n", peer_ip, peer_port);
        }
    }
    free(handshake_arg);
    return NULL;
}

void *download_handler(void *arg) {
    printf("<download_handler> Download handler started\n");
    bitfield_t *oldField = bitfield_copy(g_bitfield);
    int first_time = 1;
    while (!g_done) {
        // check if pieces from specific peer are downloaded
        LOCK_PEERS;
        for (int i = 0; i < MAXPEERS; ++i) {
            if (g_peers[i] == NULL)continue;
            if (g_peers[i]->am_interested && bitfield_have_all_from(g_bitfield, g_peers[i]->bitfield)) {
                g_peers[i]->am_interested = 0;
                // send not interested
                pwp_msg *msg = make_not_interested_msg();
                send_pwpmsg(g_peers[i]->sockfd, msg);
                free(msg);
            }
        }
        UNLOCK_PEERS;
        // check if all pieces are downloaded
        if (is_seed()) {
            LOCK_VARIABLE;
            if (g_file != NULL) {
                fclose(g_file);
                g_file = NULL;
            }
            if (first_time) {
                // send to tracker
                printf("<download_handler> Download complete, connect to tracker\n");
                int sockfd = connect_to_host(g_tracker_ip, g_tracker_port);
                if (sockfd < 0) {
                    printf("<download_handler> Error: connect to tracker\n");
                } else {
                    int msg_len;
                    char *msg = make_tracker_request(BT_COMPLETED, &msg_len);
                    if (send(sockfd, msg, msg_len, MSG_NOSIGNAL) < 0) {
                        perror("<download_handler> Error: send complete msg to tracker");
                    }
                    free(msg);
                    printf("<download_handler> close tracker\n");
                    close(sockfd);
                }
                first_time = 0;
            }

            UNLOCK_VARIABLE;


            sleep(5);
            continue;
        }

        // check if i have new pieces
        bitfield_t *xorfield = bitfield_copy(g_bitfield);
        bitfield_xor(xorfield, oldField);
        if (!bitfield_empty(xorfield)) {
            printf("<download_handler> New piece downloaded\n");
            bitfield_free(oldField);
            oldField = bitfield_copy(g_bitfield);
            int piece_num;
            int *piece_idxes = bitfield_get_set_indexes(xorfield, &piece_num);
            bitfield_free(xorfield);
            // send have msg to all peers
            LOCK_PEERS;
            for (int i = 0; i < MAXPEERS; ++i) {
                if (g_peers[i] == NULL)continue;
                if (!g_peers[i]->am_choking) {
                    for (int j = 0; j < piece_num; ++j) {
                        pwp_msg *msg = make_have_msg(piece_idxes[j]);
                        send_pwpmsg(g_peers[i]->sockfd, msg);
                        free(msg);
                    }
                }
            }
            UNLOCK_PEERS;
            free(piece_idxes);
        } else {
            bitfield_free(xorfield);
        }

        int piece_idx = get_rarest_piece_index();
        if (piece_idx != -1) {
            LOCK_PIECES;
            piece_t *piece = g_pieces[piece_idx];
            UNLOCK_PIECES;
            int success = 1;
            do {
                int seed_num;
                LOCK_PEERS;
                int *seed_peer = get_avail_seed_peers(piece_idx, &seed_num);
                UNLOCK_PEERS;
                if (seed_num == 0) {
                    printf("<download_handler> No seed for piece %d\n", piece_idx);
                    success = 0;
                    sleep(3);
                    break;
                }
                // send all block requests in this piece
                int i;
                for (i = 0; i < piece->num_blocks; ++i) {
                    if (piece->block_lengths[i] == 0) {
                        int block_offset = i * BLOCK_SIZE;
                        int block_length = get_expected_block_length(piece, i);
                        pwp_msg *request_pkt = make_request_msg(piece_idx, block_offset, block_length);
                        int peer_to_send = i % seed_num;
                        LOCK_PEERS;
                        if (!g_peers[seed_peer[peer_to_send]] ||
                            send_pwpmsg(g_peers[seed_peer[peer_to_send]]->sockfd, request_pkt) < 0) {
                            perror("<download_handler> Error: send");
                            free_msg(request_pkt);
                            success = 0;
                            UNLOCK_PEERS;
                            sleep(1);
                            break;
                        }
                        free_msg(request_pkt);
                        if (g_peers[seed_peer[peer_to_send]]) {
                            printf("<download_handler> request piece %d block %d from peer %s:%d\n", piece_idx, i,
                                   g_peers[seed_peer[peer_to_send]]->ip, g_peers[seed_peer[peer_to_send]]->port);
                        }
                        UNLOCK_PEERS;
                    }
                }
                if (i == piece->num_blocks) {
                    success = 1;
                }
            } while (!success);
            if (success) {
                printf("<download_handler> piece %d requests are all sent\n", piece_idx);
                LOCK_PIECES;
                g_pieces[piece_idx]->state = PIECE_DOWNLOADING;
                UNLOCK_PIECES;
            }
        } else {
            printf("<download_handler> No rarest piece found\n");
            sleep(3);
        }
        usleep(1000);
    }
    return NULL;
}

void *transmission_monitor(void *arg) {
    printf("<transmission_monitor> Transmission monitor started\n");
    int cnt = 0;
    char running_state[4] = {'-', '\\', '|', '/'};
    while (!g_done) {
        // print transmission info in the same line
        printf("%c <transmission_monitor> Uploaded: %d bytes, Downloaded: %d bytes, Left: %d bytes\n",
               running_state[cnt++ % 4], g_uploaded, g_downloaded, g_left);
        sleep(1);
    }
    return NULL;
}


/**============================================
 * Peer management
 * ============================================ */

//int get_peer_idx(uint8_t *peer_id) {
//    for (int i = 0; i < MAXPEERS; ++i) {
//        if (g_peers[i] != NULL) {
//            if (memcmp(g_peers[i]->id, peer_id, 20) == 0) {
//                return i;
//            }
//        }
//    }
//    return -1;
//}

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

int add_peer(char *ip, int port, int socket) {
    for (int i = 0; i < MAXPEERS; ++i) {
        if (g_peers[i] == NULL) {
            g_peers[i] = (peer_t *) malloc(sizeof(peer_t));
            g_peers[i]->sockfd = socket;
//            assert(peer_id != NULL);
//            memcpy(g_peers[i]->id, peer_id, PEER_ID_LEN);
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
        bitfield_free(g_peers[peer_idx]->bitfield);
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

int *get_avail_seed_peers(int piece_idx, int *num_peers) {
    int *seed_peers = (int *) malloc(sizeof(int) * MAXPEERS);
    int num = 0;
    for (int i = 0; i < MAXPEERS; ++i) {
        if (g_peers[i] && g_peers[i]->am_interested && !g_peers[i]->am_choking) {
            if (bitfield_get(g_peers[i]->bitfield, piece_idx)) {
                seed_peers[num++] = i;
            }
        }
    }
    *num_peers = num;
    return seed_peers;
}

/**============================================
 * Peer packet and message functions
 * ============================================ */



int recv_pwpmsg(int sockfd, pwp_msg *pkt) {
    ssize_t len = readn(sockfd, &pkt->len, sizeof(pkt->len));
    if (len != sizeof(pkt->len)) {
        printf("<recv_pwpmsg> Error: recv msg length failed, expected: %ld, got: %ld\n", sizeof(pkt->len), len);
        return -1;
    }
    pkt->len = reverse_byte_orderi(pkt->len);
    if (pkt->len == 0) {
        // keep alive
        return 0;
    }
    len = readn(sockfd, &pkt->id, sizeof(pkt->id));
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
    len = readn(sockfd, pkt->payload, pkt->len - sizeof(pkt->id));
    if (len != pkt->len - sizeof(pkt->id)) {
        printf("<recv_pwpmsg> Error: recv msg payload failed, expected: %ld, got: %ld\n", pkt->len - sizeof(pkt->id),
               len);
        return -1;
    }
    return (int) pkt->len;
}

int send_pwpmsg(int sockfd, pwp_msg *pkt) {
    int reverse_len = reverse_byte_orderi(pkt->len);
    ssize_t len = send(sockfd, &reverse_len, sizeof(pkt->len), MSG_NOSIGNAL);
    if (len != sizeof(pkt->len)) {
        printf("<send_pwpmsg> Error: send msg length failed\n");
        return -1;
    }
    if (pkt->len == 0) {
        // keep alive
        return 0;
    }
    len = send(sockfd, &pkt->id, sizeof(pkt->id), MSG_NOSIGNAL);
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
    len = send(sockfd, pkt->payload, pkt->len - sizeof(pkt->id), MSG_NOSIGNAL);
    if (len != pkt->len - sizeof(pkt->id)) {
        printf("<send_pwpmsg> Error: send msg payload failed, got len: %ld, expected: %ld\n", len,
               pkt->len - sizeof(pkt->id));
        return -1;
    }
    return (int) pkt->len;
}
