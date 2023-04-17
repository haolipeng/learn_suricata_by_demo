//
// Created by haolipeng on 3/28/23.
//

#ifndef NET_THREAT_DETECT_DECODE_IPV6_H
#define NET_THREAT_DETECT_DECODE_IPV6_H

#include <stdbool.h>

typedef struct IPV6Hdr_
{
    union {
        struct ip6_un1_ {
            uint32_t ip6_un1_flow; /* 20 bits of flow-ID */
            uint16_t ip6_un1_plen; /* payload length */
            uint8_t  ip6_un1_nxt;  /* next header */
            uint8_t  ip6_un1_hlim; /* hop limit */
        } ip6_un1;
        uint8_t ip6_un2_vfc;   /* 4 bits version, top 4 bits class */
    } ip6_hdrun;

    union {
        struct {
            uint32_t ip6_src[4];
            uint32_t ip6_dst[4];
        } ip6_un2;
        uint16_t ip6_addrs[16];
    } ip6_hdrun2;
} IPV6Hdr;

/* helper structure with parsed ipv6 info */
typedef struct IPV6Vars_
{
    uint8_t l4proto;       /**< the proto after the extension headers
                            *   store while decoding so we don't have
                            *   to loop through the exthdrs all the time */
    uint16_t exthdrs_len;  /**< length of the exthdrs */
} IPV6Vars;

typedef struct IPV6ExtHdrs_
{
    bool rh_set;
    uint8_t rh_type;

    bool fh_set;
    bool fh_more_frags_set;
    uint8_t fh_nh;

    uint8_t fh_prev_nh;
    uint16_t fh_prev_hdr_offset;

    uint16_t fh_header_offset;
    uint16_t fh_data_offset;
    uint16_t fh_data_len;

    /* In fh_offset we store the offset of this extension into the packet past
     * the ipv6 header. We use it in defrag for creating a defragmented packet
     * without the frag header */
    uint16_t fh_offset;
    uint32_t fh_id;

} IPV6ExtHdrs;

#endif //NET_THREAT_DETECT_DECODE_IPV6_H
