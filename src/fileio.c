//
// Created by ziqi on 2023/5/20.
//

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "btdata.h"

unsigned long write_block(FILE *fp, int index, int begin, int length, uint8_t *block) {
    fseek(fp, index * g_piece_len + begin, SEEK_SET);
    return fwrite(block, sizeof(uint8_t), length, fp);
}

unsigned long read_block(FILE *fp, int index, int begin, int length, uint8_t *block) {
    fseek(fp, index * g_piece_len + begin, SEEK_SET);
    return fread(block, sizeof(uint8_t), length, fp);
}