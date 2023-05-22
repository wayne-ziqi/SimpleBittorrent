//
// Created by ziqi on 2023/5/20.
//

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "btdata.h"

unsigned long write_block(int index, int begin, int length, uint8_t *block) {
    LOCK_VARIABLE;
    if (g_file == NULL) {
        g_file = fopen(g_filename, "r+");
    }
    UNLOCK_VARIABLE;
    fseek(g_file, index * g_piece_len + begin, SEEK_SET);
    return fwrite(block, sizeof(uint8_t), length, g_file);
}

unsigned long read_block(int index, int begin, int length, uint8_t *block) {
    LOCK_VARIABLE;
    if (g_file == NULL) {
        g_file = fopen(g_filename, "r+");
    }
    UNLOCK_VARIABLE;
    fseek(g_file, index * g_piece_len + begin, SEEK_SET);
    return fread(block, sizeof(uint8_t), length, g_file);
}