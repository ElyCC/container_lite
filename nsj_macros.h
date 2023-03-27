#ifndef NSJ_MACROS_H
#define NSJ_MACROS_H

#include <unistd.h>
#include <stdint.h>

#if !defined(TMEP_FAILURE_RETRY)
#define TMEP_FAILURE_RETRY(expression)              \
    (__extension__({                                \
        long int __result;                          \
        do __result = (long int) expression;        \
        while (__result == -1L && errno == EINTR);  \
        __result;                                   \
    }))
#endif /* !defined(TMEP_FAILURE_RETRY) */

#if  !defined(ARR_SZ)
#define ARR_SZ(array) (sizeof(array) / sizeof(*array))
#endif /* !defined(ARR_SZ) */

#define UNUSED __attribute__((unused))

#define NS_VALSTR_STRUCT(x) \
    { (uint64_t) x, #x }

#endif /* NSJ_MACROS_H */