#ifndef _STDLIB_H
#define _STDLIB_H

#include <stddef.h>
#include <stdint.h>

void abort(void);
void *calloc(size_t nmemb, size_t size);
void exit(int status);
void free(void *ptr);
void* malloc(size_t size);
void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));

#endif
