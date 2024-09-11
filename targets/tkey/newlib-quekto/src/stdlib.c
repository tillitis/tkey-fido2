#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Size of the initial memory pool
#define POOL_SIZE 1024

// Start of the memory pool
static uint8_t pool[POOL_SIZE];

// Define a structure to represent memory blocks
typedef struct block
{
    size_t size;
    struct block *next;
    int free;
} block_t;

// Initial free block in the pool
static block_t *free_list = NULL;

void abort(void)
{
    // Force illegal instruction to halt CPU
    asm volatile("unimp");

    // Not reached
    __builtin_unreachable();

    // Enter an infinite loop to halt the system
    while (1) {
        // Optionally: you could add a no-operation instruction to prevent optimization
        __asm__("nop");
    }
}

void exit(int status)
{
    (void) status;

    while (1)
        ;
}

// Initialize the memory pool
void initialize_malloc_pool()
{
    free_list = (block_t*) pool;
    free_list->size = POOL_SIZE - sizeof(block_t);
    free_list->next = NULL;
    free_list->free = 1;
}

// Minimal calloc implementation
void* calloc(size_t num, size_t size)
{
    // Calculate total size to allocate
    size_t total_size = num * size;

    // Allocate memory
    void *ptr = malloc(total_size);
    if (ptr == NULL) {
        return NULL;  // Return NULL if allocation fails
    }

    // Initialize allocated memory to zero
    memset(ptr, 0, total_size);

    return ptr;
}

// Minimal malloc implementation
void* malloc(size_t size)
{
    block_t *curr = free_list;
    block_t *best_fit = NULL;

    // Traverse the free list to find the best fit block
    while (curr != NULL) {
        if (curr->free && curr->size >= size && (best_fit == NULL || curr->size < best_fit->size)) {
            best_fit = curr;
        }
        curr = curr->next;
    }

    // If no suitable block found, return NULL
    if (best_fit == NULL) {
        return NULL;
    }

    // If the best fit is larger than needed, split the block
    if (best_fit->size > size + sizeof(block_t)) {
        block_t *new_block = (block_t*) ((uint8_t*) best_fit + sizeof(block_t) + size);
        new_block->size = best_fit->size - size - sizeof(block_t);
        new_block->next = best_fit->next;
        new_block->free = 1;
        best_fit->size = size;
        best_fit->next = new_block;
    }

    best_fit->free = 0;
    return (void*) ((uint8_t*) best_fit + sizeof(block_t));
}

// Minimal free implementation
void free(void *ptr)
{
    if (ptr == NULL) {
        return;
    }

    block_t *block = (block_t*) ((uint8_t*) ptr - sizeof(block_t));
    block->free = 1;

    // Coalesce free blocks
    while (block->next != NULL && block->next->free) {
        block->size += block->next->size + sizeof(block_t);
        block->next = block->next->next;
    }
}

// Swap two elements in an array
void swap(void *a, void *b, size_t size)
{
    unsigned char *p = a, *q = b, tmp;
    for (size_t i = 0; i < size; ++i) {
        tmp = p[i];
        p[i] = q[i];
        q[i] = tmp;
    }
}

// Partition function for quicksort
size_t partition(void *array, size_t left, size_t right, size_t size, int (*cmp)(const void*, const void*))
{
    void *pivot = (char*) array + right * size;
    size_t i = left;

    for (size_t j = left; j < right; ++j) {
        if (cmp((char*) array + j * size, pivot) < 0) {
            swap((char*) array + i * size, (char*) array + j * size, size);
            ++i;
        }
    }
    swap((char*) array + i * size, (char*) array + right * size, size);
    return i;
}

// Quicksort function
void qsort(void *array, size_t count, size_t size, int (*cmp)(const void*, const void*))
{
    if (count > 1) {
        size_t pivot = partition(array, 0, count - 1, size, cmp);
        qsort(array, pivot, size, cmp);
        qsort((char*) array + (pivot + 1) * size, count - pivot - 1, size, cmp);
    }
}

// Example usage
//int compare_int(const void *a, const void *b)
//{
//    return (*(int*) a - *(int*) b);
//}
