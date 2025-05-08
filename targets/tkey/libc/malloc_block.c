// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

#include <stdint.h>
#include <stdlib.h>

#include <tkey/debug.h>
#include <tkey/lib.h>

struct block {
    uint8_t data[192];
    uint8_t is_used;
    uint8_t padding[31];
};

// TODO: Figure out alignment requirements
_Static_assert(sizeof(struct block) == 224, "struct block size not a multiple of 32");
struct block blocks[60] __attribute__((aligned(16))) = {0};

static struct block *find_empty()
{
    for (size_t i = 0; i < (sizeof(blocks) / sizeof(blocks[0])); i++) {
        if (!blocks[i].is_used) {
            return &blocks[i];
        }
    }

    return NULL;
}

static struct block *find_allocated(void *ptr)
{
    for (size_t i = 0; i < (sizeof(blocks) / sizeof(blocks[0])); i++) {
        if (blocks[i].is_used && blocks[i].data == ptr) {
            return &blocks[i];
        }
    }

    return NULL;
}

void *malloc(size_t size)
{
    if (size > sizeof(blocks[0].data)) {
        puts(IO_DEBUG, "malloc: trying to allocate ");
        putinthex(IO_DEBUG, size);
        puts(IO_DEBUG, " bytes\n");

        return NULL;
    }

    struct block *block = find_empty();

    if (block == NULL) {
        puts(IO_DEBUG, "malloc: out of memory\n");
        return NULL;
    }

    block->is_used = 1;

    // puts(IO_DEBUG, "malloc: allocated ptr: ");
    // putinthex(IO_DEBUG, (uint32_t)block->data);
    // puts(IO_DEBUG, " size: ");
    // putinthex(IO_DEBUG, size);
    // puts(IO_DEBUG, "\n");

    return block->data;
}

void *calloc(size_t n, size_t size)
{
    _Static_assert(sizeof(n) == 4, "size_t is not 32 bit");
    _Static_assert(sizeof(size) == 4, "size_t is not 32 bit");

    uint64_t size64 = (uint64_t)n * size;

    if (size64 > sizeof(blocks[0].data)) {
        return NULL;
    }

    void *ptr = malloc(n * size);

    memset(ptr, 0, (uint32_t)size64);

    return ptr;
}

void free(void *ptr)
{
    if (ptr == NULL) {
        puts(IO_DEBUG, "free: NULL argument\n");
        return;
    }

    struct block *block = find_allocated(ptr);

    if (block == NULL) {
        puts(IO_DEBUG, "free: trying to free not allocated ptr: ");
        putinthex(IO_DEBUG, (uint32_t)block->data);
        puts(IO_DEBUG, "\n");
    }

    block->is_used = 0;
    // TODO: zero memory?

    // puts(IO_DEBUG, "free: freed ptr: ");
    // putinthex(IO_DEBUG, (uint32_t)block->data);
    // puts(IO_DEBUG, "\n");
}
