//
// Created by ziqi on 2023/5/20.
//

#ifndef SIMPLETORRENT_PIECE_H
#define SIMPLETORRENT_PIECE_H

#define BLOCK_SIZE 16384 // 16KB

#define PIECE_MISSING 0
#define PIECE_DOWNLOADING 1
#define PIECE_DOWNLOADED 2

#include <stdint.h>

typedef struct _piece {
    int index;
    int length;
    int state;
    int num_blocks;
    int num_blocks_downloaded;
    int *block_lengths;
} piece_t;

/**
 * create a piece with given index and length
 */
piece_t *piece_create(int index, int length);

/**
 * free the piece
 */
void piece_free(piece_t *piece);

/**
 * set the block at given index
 */
void piece_set_block(piece_t *piece, int offset, int length);

/**
 * get the expected block length
 */
int get_expected_block_length(piece_t *piece, int index);

/**
 * check if the piece is full
 */
int piece_full(piece_t *piece);

/**
 *  rarest piece selection
 */
int get_rarest_piece_index();

#endif //SIMPLETORRENT_PIECE_H
