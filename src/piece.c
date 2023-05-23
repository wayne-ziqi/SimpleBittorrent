//
// Created by ziqi on 2023/5/20.
//

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "piece.h"
#include "btdata.h"

piece_t *piece_create(int index, int length) {
    piece_t *piece = malloc(sizeof(piece_t));
    piece->index = index;
    piece->length = length;
    piece->state = PIECE_MISSING;
    piece->num_blocks = (length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    piece->num_blocks_downloaded = 0;
    piece->block_lengths = malloc(sizeof(int) * piece->num_blocks);
    bzero(piece->block_lengths, sizeof(int) * piece->num_blocks);
    return piece;
}

void piece_free(piece_t *piece) {
    free(piece->block_lengths);
    free(piece);
}

void piece_set_block(piece_t *piece, int offset, int length) {
    int index = offset / BLOCK_SIZE;
    assert(index < piece->num_blocks);
    assert(length <= BLOCK_SIZE);
    if (piece->block_lengths[index] == 0) {
        piece->block_lengths[index] = length;
        piece->num_blocks_downloaded++;
    }
}

int get_expected_block_length(piece_t *piece, int index) {
    assert(index < piece->num_blocks);
    if (index == piece->num_blocks - 1) {
        return piece->length - (piece->num_blocks - 1) * BLOCK_SIZE;
    } else {
        return BLOCK_SIZE;
    }
}

int piece_full(piece_t *piece) {
    return piece->num_blocks_downloaded == piece->num_blocks;
}

int get_rarest_piece_index() {
    int minCnt = 0x7fffffff;
    int minIndex = -1;
    for (int i = 0; i < g_num_pieces; ++i) {
        int curCnt = 0x7fffffff;
        LOCK_VARIABLE;
        if (g_bitfield && bitfield_get(g_bitfield, i)) {
            UNLOCK_VARIABLE;
            continue;
        }
        UNLOCK_VARIABLE;
        LOCK_PEERS;
        for (int j = 0; j < MAXPEERS; ++j) {
            if (g_peers[j] && bitfield_get(g_peers[j]->bitfield, i)) {
                if (curCnt == 0x7fffffff) {
                    curCnt = 1;
                } else {
                    curCnt++;
                }
            }
        }
        UNLOCK_PEERS;

        if (curCnt < minCnt) {
            LOCK_PIECES;
            if (g_pieces[i]->state == PIECE_MISSING) {
                minCnt = curCnt;
                minIndex = i;
            }
            UNLOCK_PIECES;
        }
    }
    return minIndex;
}

