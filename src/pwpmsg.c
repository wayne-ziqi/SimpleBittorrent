//
// Created by ziqi on 2023/5/22.
//

#include "pwp.h"
#include "bitfield.h"
#include "util.h"
#include <string.h>

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

pwp_msg *make_choke_msg() {
    pwp_msg *msg = malloc(sizeof(pwp_msg));
    bzero(msg, sizeof(pwp_msg));
    msg->len = 1;
    msg->id = CHOKE;
    msg->payload = NULL;
    return msg;
}

pwp_msg *make_unchoke_msg() {
    pwp_msg *msg = malloc(sizeof(pwp_msg));
    bzero(msg, sizeof(pwp_msg));
    msg->len = 1;
    msg->id = UNCHOKE;
    msg->payload = NULL;
    return msg;
}

pwp_msg *make_interested_msg() {
    pwp_msg *msg = malloc(sizeof(pwp_msg));
    bzero(msg, sizeof(pwp_msg));
    msg->len = 1;
    msg->id = INTERESTED;
    msg->payload = NULL;
    return msg;
}

pwp_msg *make_not_interested_msg() {
    pwp_msg *msg = malloc(sizeof(pwp_msg));
    bzero(msg, sizeof(pwp_msg));
    msg->len = 1;
    msg->id = NOT_INTERESTED;
    msg->payload = NULL;
    return msg;
}

pwp_msg *make_have_msg(int index) {
    pwp_msg *have_msg = (pwp_msg *) malloc(sizeof(pwp_msg));
    bzero(have_msg, sizeof(pwp_msg));
    have_msg->len = 5;
    have_msg->id = HAVE;
    have_msg->payload = (uint8_t *) malloc(4);
    int reverse_index = reverse_byte_orderi(index);
    memcpy(have_msg->payload, &reverse_index, 4);
    return have_msg;
}

pwp_msg *make_bitfield_msg(bitfield_t *bitfield) {
    pwp_msg *bitfield_msg = (pwp_msg *) malloc(sizeof(pwp_msg));
    bzero(bitfield_msg, sizeof(pwp_msg));
    bitfield_msg->len = 1 + BITFIELD_SIZE(bitfield->size);
    bitfield_msg->id = BITFIELD;
    bitfield_msg->payload = (uint8_t *) malloc(BITFIELD_SIZE(bitfield->size));
    memcpy(bitfield_msg->payload, bitfield->bitfield, BITFIELD_SIZE(bitfield->size));
    return bitfield_msg;
}

pwp_msg *make_request_msg(int index, int begin, int length) {
    pwp_msg *request_msg = (pwp_msg *) malloc(sizeof(pwp_msg));
    bzero(request_msg, sizeof(pwp_msg));
    request_msg->len = 13;
    request_msg->id = REQUEST;
    request_msg->payload = (uint8_t *) malloc(12);
    int reverse_index = reverse_byte_orderi(index);
    int reverse_begin = reverse_byte_orderi(begin);
    int reverse_length = reverse_byte_orderi(length);
    memcpy(request_msg->payload, &reverse_index, 4);
    memcpy(request_msg->payload + 4, &reverse_begin, 4);
    memcpy(request_msg->payload + 8, &reverse_length, 4);
    return request_msg;
}

pwp_msg *make_piece_msg(int index, int offset, int length, uint8_t *block) {
    pwp_msg *piece_msg = (pwp_msg *) malloc(sizeof(pwp_msg));
    bzero(piece_msg, sizeof(pwp_msg));
    piece_msg->len = 9 + length;
    piece_msg->id = PIECE;
    piece_msg->payload = (uint8_t *) malloc(8 + length);
    int reverse_index = reverse_byte_orderi(index);
    int reverse_offset = reverse_byte_orderi(offset);
    memcpy(piece_msg->payload, &reverse_index, 4);
    memcpy(piece_msg->payload + 4, &reverse_offset, 4);
    memcpy(piece_msg->payload + 8, block, length);
    return piece_msg;
}

pwp_msg *make_cancel_msg(int index, int offset, int length) {
    pwp_msg *cancel_msg = (pwp_msg *) malloc(sizeof(pwp_msg));
    bzero(cancel_msg, sizeof(pwp_msg));
    cancel_msg->len = 13;
    cancel_msg->id = CANCEL;
    cancel_msg->payload = (uint8_t *) malloc(12);
    int reverse_index = reverse_byte_orderi(index);
    int reverse_offset = reverse_byte_orderi(offset);
    int reverse_length = reverse_byte_orderi(length);
    memcpy(cancel_msg->payload, &reverse_index, 4);
    memcpy(cancel_msg->payload + 4, &reverse_offset, 4);
    memcpy(cancel_msg->payload + 8, &reverse_length, 4);
    return cancel_msg;
}


void extract_request_info(pwp_msg *pkt, int *index, int *begin, int *length) {
    *index = pkt->payload[0] << 24 | pkt->payload[1] << 16 | pkt->payload[2] << 8 | pkt->payload[3];
    *begin = pkt->payload[4] << 24 | pkt->payload[5] << 16 | pkt->payload[6] << 8 | pkt->payload[7];
    *length = pkt->payload[8] << 24 | pkt->payload[9] << 16 | pkt->payload[10] << 8 | pkt->payload[11];
}

void extract_piece_info(pwp_msg *pkt, int *index, int *begin, int *length, uint8_t **block) {
    *index = pkt->payload[0] << 24 | pkt->payload[1] << 16 | pkt->payload[2] << 8 | pkt->payload[3];
    *begin = pkt->payload[4] << 24 | pkt->payload[5] << 16 | pkt->payload[6] << 8 | pkt->payload[7];
    *length = (int) pkt->len - 9;
    if (*length > 0)
        *block = (uint8_t *) malloc(*length);
    memcpy(*block, pkt->payload + 8, *length);
}

void free_msg(pwp_msg *pkt) {
    if (pkt->payload != NULL)
        free(pkt->payload);
    free(pkt);
}

