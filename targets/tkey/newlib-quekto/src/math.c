#include <math.h>

//float __builtin_huge_valf(void) {
//    union {
//        uint32_t u;
//        float f;
//    } val;
//
//    val.u = 0x7F800000;  // IEEE 754 representation of +Infinity for float
//    return val.f;
//}

//float __builtin_nanf(const char *tagp) {
//    union {
//        uint32_t u;
//        float f;
//    } val;
//
//    // Construct a quiet NaN (QNaN) for float
//    val.u = 0x7FC00000;  // IEEE 754 single-precision QNaN bit pattern
//    return val.f;
//}

int __fpclassifyf(float x) {
    union {
        float f;
        uint32_t u;
    } u;

    u.f = x;
    uint32_t exponent = (u.u >> 23) & 0xFF;
    uint32_t fraction = u.u & 0x7FFFFF;

    if (exponent == 0xFF) {
        if (fraction == 0) {
            return FP_INFINITE; // Infinity
        } else {
            return FP_NAN; // NaN
        }
    } else if (exponent == 0) {
        if (fraction == 0) {
            return FP_ZERO; // Zero
        } else {
            return FP_SUBNORMAL; // Subnormal (denormal)
        }
    } else {
        return FP_NORMAL; // Normal
    }
}

int __fpclassify(double x) {
    // Example implementation for a 32-bit RISC-V MCU

    // Check if x is NaN
    if (x != x) {
        return FP_NAN;
    }

    // Check if x is infinity
    if (x == HUGE_VAL || x == -HUGE_VAL) {
        return FP_INFINITE;
    }

    // Check if x is zero
    if (x == 0.0 || x == -0.0) {
        return FP_ZERO;
    }

    // Check if x is subnormal (denormal)
    // This may vary depending on the MCU architecture
    // Typically involves checking the exponent and mantissa bits
    // For simplicity, assuming a straightforward check here
    if (x != 0.0 && fabs(x) < __FLT_DENORM_MIN__) {
        return FP_SUBNORMAL;
    }

    // If none of the above, x is a normal number
    return FP_NORMAL;
}

int __fpclassifyl(long double x) {
    // Example implementation for a 32-bit RISC-V MCU

    // Check if x is NaN
    if (x != x) {
        return FP_NAN;
    }

    // Check if x is infinity
    if (x == HUGE_VALL || x == -HUGE_VALL) {
        return FP_INFINITE;
    }

    // Check if x is zero
    if (x == 0.0L || x == -0.0L) {
        return FP_ZERO;
    }

    // Check if x is subnormal (denormal)
    // This may vary depending on the MCU architecture and long double format
    // Typically involves checking the exponent and mantissa bits
    // For simplicity, assuming a straightforward check here
    if (x != 0.0L && fabsl(x) < __LDBL_DENORM_MIN__) {
        return FP_SUBNORMAL;
    }

    // If none of the above, x is a normal number
    return FP_NORMAL;
}

long double fabsl(long double x)
{
    // Create a union to access the bits of the long double
    union
    {
        long double d;
        struct
        {
            uint64_t low;
            uint64_t high;
        } bits;
    } value;

    value.d = x;

    // Clear the sign bit
    value.bits.high &= 0x7FFFFFFFFFFFFFFF;

    return value.d;
}
