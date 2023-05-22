//
// Created by ziqi on 2023/5/20.
//

#include <string.h>
#include <assert.h>
#include "bitfield.h"

bitfield_t *bitfield_create(int size) {
    bitfield_t *bitfield = malloc(sizeof(bitfield_t));
    bitfield->size = size;
    bitfield->bitfield = malloc(BITFIELD_SIZE(size));
    memset(bitfield->bitfield, 0, BITFIELD_SIZE(size));
    return bitfield;
}

bitfield_t *bitfield_copy(bitfield_t *bitfield) {
    bitfield_t *copy = malloc(sizeof(bitfield_t));
    copy->size = bitfield->size;
    copy->bitfield = malloc(BITFIELD_SIZE(bitfield->size));
    memcpy(copy->bitfield, bitfield->bitfield, BITFIELD_SIZE(bitfield->size));
    return copy;
}

bitfield_t *bitfield_create_from_string(uint8_t *str, int size) {
    bitfield_t *bitfield = malloc(sizeof(bitfield_t));
    bitfield->size = size;
    bitfield->bitfield = malloc(BITFIELD_SIZE(size));
    memcpy(bitfield->bitfield, str, BITFIELD_SIZE(size));
    return bitfield;
}

int bitfield_get(bitfield_t *bitfield, int index) {
    assert(index < bitfield->size);
    int byte = index / 8;
    int bit = index % 8;
    return (bitfield->bitfield[byte] >> (7 - bit)) & 0x01;
}

void bitfield_set(bitfield_t *bitfield, int index) {
    assert(index < bitfield->size);
    int byte = index / 8;
    int bit = index % 8;
    bitfield->bitfield[byte] |= (0x01 << (7 - bit));
}

void bitfield_set_from(bitfield_t *dst, bitfield_t *src) {
    assert(dst->size == src->size);
    for (int i = 0; i < src->size; ++i) {
        if (bitfield_get(src, i) == 1) {
            bitfield_set(dst, i);
        }
    }
}

void bitfield_clear(bitfield_t *bitfield, int index) {
    assert(index < bitfield->size);
    int byte = index / 8;
    int bit = index % 8;
    bitfield->bitfield[byte] &= ~(0x01 << (7 - bit));
}

int bitfield_full(bitfield_t *bitfield) {
    for (int i = 0; i < bitfield->size; i++) {
        if (bitfield_get(bitfield, i) == 0) {
            return 0;
        }
    }
    return 1;
}

int bitfield_all_set(bitfield_t *dst, bitfield_t *src) {
    assert(dst->size == src->size);
    for (int i = 0; i < src->size; i++) {
        if (bitfield_get(src, i) == 1 && bitfield_get(dst, i) == 0) {
            return 0;
        }
    }
    return 1;
}

int bitfield_have_all_from(bitfield_t *dst, bitfield_t *src) {
    assert(dst->size == src->size);
    for (int i = 0; i < src->size; i++) {
        if (bitfield_get(src, i) == 1 && bitfield_get(dst, i) == 0) {
            return 0;
        }
    }
    return 1;
}

int *bitfield_get_set_indexes(bitfield_t *bitfield, int *size) {
    int *indexes = malloc(sizeof(int) * bitfield->size);
    int count = 0;
    for (int i = 0; i < bitfield->size; i++) {
        if (bitfield_get(bitfield, i) == 1) {
            indexes[count++] = i;
        }
    }
    *size = count;
    return indexes;
}

int bitfield_empty(bitfield_t *bitfield) {
    for (int i = 0; i < bitfield->size; i++) {
        if (bitfield_get(bitfield, i) == 1) {
            return 0;
        }
    }
    return 1;
}

void bitfield_xor(bitfield_t *dst, bitfield_t *src) {
    assert(dst->size == src->size);
    for (int i = 0; i < src->size; i++) {
        if (bitfield_get(dst, i) == bitfield_get(src, i)) {
            bitfield_clear(dst, i);
        } else {
            bitfield_set(dst, i);
        }
    }
}

int bitfield_count(bitfield_t *bitfield) {
    int count = 0;
    for (int i = 0; i < bitfield->size; i++) {
        if (bitfield_get(bitfield, i) == 1) {
            count++;
        }
    }
    return count;
}

void bitfield_free(bitfield_t *bitfield) {
    free(bitfield->bitfield);
    free(bitfield);
}

int bitfield_compare(bitfield_t *bitfield1, bitfield_t *bitfield2) {
    if (bitfield1->size != bitfield2->size) {
        return 0;
    }
    for (int i = 0; i < bitfield1->size; i++) {
        if (bitfield_get(bitfield1, i) != bitfield_get(bitfield2, i)) {
            return 0;
        }
    }
    return 1;
}