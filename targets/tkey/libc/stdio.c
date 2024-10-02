// Copyright 2024 Tillitis AB

#include <stdint.h>
#include <stdio.h>

#ifdef ENABLE_PRINTF

#include "printf-emb.h"
#include "tkey/qemu_debug.h"

int printf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    return 0;
}

int vprintf(const char *format, va_list ap)
{
    char buf[256];
    int overflow = 0;
    int n_out = 0;

    int nc = vsnprintf(buf, sizeof(buf), format, ap);

    if (nc < 0) {
        qemu_puts("[PRINTF ERROR]\n");
        return 0;
    }

    n_out = nc;
    if (n_out >= sizeof(buf)) {
        overflow = 1;
        n_out = sizeof(buf) - 1;
    }

    for (int i = 0; i < n_out; i++) {
        qemu_putchar(buf[i]);
    }
    if (overflow) {
        qemu_puts("...[PRINTF OVERFLOW]\n");
    }

    return 0;
}

#else

int printf(const char *format, ...)
{
    return 0;
}

int vprintf(const char *format, va_list ap)
{
    return 0;
}

#endif
