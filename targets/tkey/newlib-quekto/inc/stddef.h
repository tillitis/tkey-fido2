#ifndef _STDDEF_H
#define _STDDEF_H

#include <stdint.h>

#define NULL 0
typedef typeof(sizeof(0)) size_t;
typedef long ptrdiff_t;

#endif
