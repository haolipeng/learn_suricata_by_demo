#ifndef NET_THREAT_DETECT_COMMON_H
#define NET_THREAT_DETECT_COMMON_H
#include <assert.h>
#include <string.h>

#ifndef MIN
#define MIN(x, y) (((x)<(y))?(x):(y))
#endif

#ifndef MAX
#define MAX(x, y) (((x)<(y))?(y):(x))
#endif

#define BIT_U8(n)  ((uint8_t)(1 << (n)))
#define BIT_U16(n) ((uint16_t)(1 << (n)))
#define BIT_U32(n) (1UL  << (n))
#define BIT_U64(n) (1ULL << (n))

#define BUG_ON(x) assert(!(x))
#define DEBUG_VALIDATE_BUG_ON(exp) BUG_ON((exp))

#define SCNtohl(x) (uint32_t)ntohl((x))
#define SCNtohs(x) (uint16_t)ntohs((x))

/* wrapper around memcmp to match the retvals of the SIMD implementations */
#define SCMemcmp(a,b,c) ({ \
    memcmp((a), (b), (c)) ? 1 : 0; \
})

/* swap flags if one of them is set, otherwise do nothing. */
#define SWAP_FLAGS(flags, a, b)                     \
    do {                                            \
        if (((flags) & ((a)|(b))) == (a)) {         \
            (flags) &= ~(a);                        \
            (flags) |= (b);                         \
        } else if (((flags) & ((a)|(b))) == (b)) {  \
            (flags) &= ~(b);                        \
            (flags) |= (a);                         \
        }                                           \
    } while(0)

#define SWAP_VARS(type, a, b)           \
    do {                                \
        type t = (a);                   \
        (a) = (b);                      \
        (b) = t;                        \
    } while (0)

#endif //NET_THREAT_DETECT_COMMON_H
