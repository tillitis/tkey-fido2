#ifndef _ASSERT_H
#define _ASSERT_H

#include <stdint.h>

# define __ASSERT_VOID_CAST    (void)
# define assert(expr)          (__ASSERT_VOID_CAST (0))

#define static_assert_join(a, b) a##b
#define static_assert_name(line) static_assert_join(static_assertion_at_line_, line)
#define static_assert(condition, message) \
    typedef char static_assert_name(__LINE__)[(condition) ? 1 : -1]

#endif
