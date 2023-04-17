//
// Created by haolipeng on 3/28/23.
//

#ifndef NET_THREAT_DETECT_COMMON_H
#define NET_THREAT_DETECT_COMMON_H
#include <assert.h>
#include <string.h>

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

/*Error codes for the thread modules*/
typedef enum {
    TM_ECODE_OK = 0,    /**< Thread module exits OK*/
    TM_ECODE_FAILED,    /**< Thread module exits due to failure*/
    TM_ECODE_DONE,    /**< Thread module task is finished*/
} TmEcode;
#endif //NET_THREAT_DETECT_COMMON_H
