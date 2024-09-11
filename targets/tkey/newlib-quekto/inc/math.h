#ifndef _MATH_H
#define _MATH_H

#include <stdint.h>

/* newlib/libc/include/math.h */
#define FP_NAN         0
#define FP_INFINITE    1
#define FP_ZERO        2
#define FP_SUBNORMAL   3
#define FP_NORMAL      4

/* Glibc */
//#define FP_NAN         0x0100
//#define FP_INFINITE    0x0200
//#define FP_ZERO        0x0400
//#define FP_SUBNORMAL   0x0800
//#define FP_NORMAL      0x1000

/* newlib/libc/include/math.h */
#define HUGE_VAL (__builtin_huge_val())

#ifndef HUGE_VALL
#define HUGE_VALL __builtin_huge_vall()
#endif

//float __builtin_nanf(const char *tagp);
#define NAN (__builtin_nanf(""))

//float __builtin_huge_valf(void);
#define HUGE_VALF (__builtin_huge_valf())
#define INFINITY HUGE_VALF

double ldexp(double x, int exp);
double fabs(double x);
long double fabsl(long double x);

int __fpclassifyf(float x);
int __fpclassify(double x);
int __fpclassifyl(long double x);

#define fpclassify(x) \
    ((sizeof (x) == sizeof(float))     ? __fpclassifyf(x) : \
     (sizeof (x) == sizeof(double))    ? __fpclassify(x)  : \
     (sizeof (x) == sizeof(long double)) ? __fpclassifyl(x) : \
     -1)

#endif
