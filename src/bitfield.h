//
// Created by ziqi on 2023/5/20.
//

#ifndef SIMPLETORRENT_BITFIELD_H
#define SIMPLETORRENT_BITFIELD_H

#include <stdlib.h>
#include <stdint.h>

#define BITFIELD_SIZE(size) ((size + 7) / 8)

typedef struct _bitfield {
    int size;
    uint8_t *bitfield;
} bitfield_t;

/**
 * create a bitfield with given bit length
 */
bitfield_t *bitfield_create(int size);

/**
 * create a bitfield with given bit length and str
 */
bitfield_t *bitfield_create_from_string(uint8_t *str, int size);

/**
 * get the bit at given index
 */
int bitfield_get(bitfield_t *bitfield, int index);

/**
 * set the bit at given index
 */
void bitfield_set(bitfield_t *bitfield, int index);

/**
 * clear the bit at given index
 */
void bitfield_clear(bitfield_t *bitfield, int index);

/**
 * check if the bitfield is full
 */
int bitfield_full(bitfield_t *bitfield);

/**
 * check if the bitfield is all set according to another bitfield (src)
 */
int bitfield_all_set(bitfield_t *dst, bitfield_t *src);

/**
 * check if the bitfield is empty
 */
int bitfield_empty(bitfield_t *bitfield);

/**
 * count the number of bits that are set
 */
int bitfield_count(bitfield_t *bitfield);

/**
 * destroy the bitfield
 */
void bitfield_destroy(bitfield_t *bitfield);

/**
 * compare two bitfields
 */
int bitfield_compare(bitfield_t *bitfield1, bitfield_t *bitfield2);

#endif //SIMPLETORRENT_BITFIELD_H
