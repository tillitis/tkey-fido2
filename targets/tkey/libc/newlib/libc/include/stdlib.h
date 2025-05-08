#ifndef _STDLIB_H
#define _STDLIB_H

#include <stddef.h>
#include <stdint.h>

void abort(void);
void exit(int status);
void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));

void *calloc(size_t n, size_t size);
void free(void *ptr);

#endif
