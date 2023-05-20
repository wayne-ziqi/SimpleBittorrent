//
// Created by ziqi on 2023/5/20.
//

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "btdata.h"

unsigned long write_block(FILE * fp, int index, int begin, int length, char *block) {
    fseek(fp, index * g_piece_len + begin, SEEK_SET);
    return fwrite(block, sizeof(char), length, fp);
}

unsigned long read_block(FILE * fp, int index, int begin, int length, char *block) {
    fseek(fp, index * g_piece_len + begin, SEEK_SET);
    return fread(block, sizeof(char), length, fp);
}