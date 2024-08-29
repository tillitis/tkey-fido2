#include <stdint.h>
#include <string.h>
#include <stddef.h>

int memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *p1 = (const unsigned char*) s1;
    const unsigned char *p2 = (const unsigned char*) s2;

    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return (p1[i] < p2[i]) ? -1 : 1;
        }
    }
    return 0;
}

void* memcpy(void *dest, const void *src, size_t num)
{
    unsigned char *d = (unsigned char*) dest;
    const unsigned char *s = (const unsigned char*) src;

    while (num--) {
        *d++ = *s++;
    }

    return dest;
}

void* memmove(void *dest, const void *src, size_t n)
{
    unsigned char *d = (unsigned char*) dest;
    const unsigned char *s = (const unsigned char*) src;

    if (d < s) {
        // Copy forward
        for (size_t i = 0; i < n; i++) {
            d[i] = s[i];
        }
    } else {
        // Copy backward
        for (size_t i = n; i > 0; i--) {
            d[i - 1] = s[i - 1];
        }
    }

    return dest;
}

void* memset(void *ptr, int value, size_t num)
{
    unsigned char *p = (unsigned char*) ptr;
    unsigned char val = (unsigned char) value;

    while (num--) {
        *p++ = val;
    }

    return ptr;
}

int strcmp(const char *s1, const char *s2)
{
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return (unsigned char) *s1 - (unsigned char) *s2;
}

int strncmp(const char *s1, const char *s2, size_t n)
{
    while (n > 0 && *s1 && (*s1 == *s2)) {
        s1++;
        s2++;
        n--;
    }
    if (n == 0) {
        return 0; // Reached the end of comparison and strings are equal
    } else {
        return (unsigned char) *s1 - (unsigned char) *s2;
    }
}

size_t strlen(const char *s) {
    const char *p = s;
    while (*p != '\0') {
        p++;
    }
    return p - s;
}
