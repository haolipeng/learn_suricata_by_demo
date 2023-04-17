//
// Created by root on 3/28/23.
//

#ifndef NET_THREAT_DETECT_DECODE_TCP_H
#define NET_THREAT_DETECT_DECODE_TCP_H

#include <stdbool.h>
#include "base.h"

#define TCP_HEADER_LEN                       20
#define TCP_OPTLENMAX                        40
#define TCP_OPTMAX                           20 /* every opt is at least 2 bytes
                                                 * (type + len), except EOL and NOP */
/* TCP flags */

#define TH_FIN                               0x01
#define TH_SYN                               0x02
#define TH_RST                               0x04
#define TH_PUSH                              0x08
#define TH_ACK                               0x10
#define TH_URG                               0x20
/** Establish a new connection reducing window */
#define TH_ECN                               0x40
/** Echo Congestion flag */
#define TH_CWR                               0x80

/* tcp option codes */
#define TCP_OPT_EOL                          0x00
#define TCP_OPT_NOP                          0x01
#define TCP_OPT_MSS                          0x02
#define TCP_OPT_WS                           0x03
#define TCP_OPT_SACKOK                       0x04
#define TCP_OPT_SACK                         0x05
#define TCP_OPT_TS                           0x08
#define TCP_OPT_TFO                          0x22   /* TCP Fast Open */
#define TCP_OPT_EXP1                         0xfd   /* Experimental, could be TFO */
#define TCP_OPT_EXP2                         0xfe   /* Experimental, could be TFO */
#define TCP_OPT_MD5                          0x13   /* 19: RFC 2385 TCP MD5 option */
#define TCP_OPT_AO                           0x1d   /* 29: RFC 5925 TCP AO option */

#define TCP_OPT_SACKOK_LEN                   2
#define TCP_OPT_WS_LEN                       3
#define TCP_OPT_TS_LEN                       10
#define TCP_OPT_MSS_LEN                      4
#define TCP_OPT_SACK_MIN_LEN                 10 /* hdr 2, 1 pair 8 = 10 */
#define TCP_OPT_SACK_MAX_LEN                 34 /* hdr 2, 4 pair 32= 34 */
#define TCP_OPT_TFO_MIN_LEN                  4  /* kind, len, 2 bytes cookie: 4 */
#define TCP_OPT_TFO_MAX_LEN                  18 /* kind, len, 18 */

/** Max valid wscale value. */
#define TCP_WSCALE_MAX                       14

#define TCP_GET_RAW_OFFSET(tcph)             (((tcph)->th_offx2 & 0xf0) >> 4)
#define TCP_GET_RAW_X2(tcph)                 (unsigned char)((tcph)->th_offx2 & 0x0f)
#define TCP_GET_RAW_SRC_PORT(tcph)           SCNtohs((tcph)->th_sport)
#define TCP_GET_RAW_DST_PORT(tcph)           SCNtohs((tcph)->th_dport)

#define TCP_SET_RAW_TCP_OFFSET(tcph, value)  ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0x0f) | (value << 4)))
#define TCP_SET_RAW_TCP_X2(tcph, value)      ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0xf0) | (value & 0x0f)))

#define TCP_GET_RAW_SEQ(tcph)                SCNtohl((tcph)->th_seq)
#define TCP_GET_RAW_ACK(tcph)                SCNtohl((tcph)->th_ack)

#define TCP_GET_RAW_WINDOW(tcph)             SCNtohs((tcph)->th_win)
#define TCP_GET_RAW_URG_POINTER(tcph)        SCNtohs((tcph)->th_urp)
#define TCP_GET_RAW_SUM(tcph)                SCNtohs((tcph)->th_sum)

/** macro for getting the first timestamp from the packet in host order */
#define TCP_GET_TSVAL(p)                    ((p)->tcpvars.ts_val)

/** macro for getting the second timestamp from the packet in host order. */
#define TCP_GET_TSECR(p)                    ((p)->tcpvars.ts_ecr)

#define TCP_HAS_WSCALE(p)                   ((p)->tcpvars.ws.type == TCP_OPT_WS)
#define TCP_HAS_SACK(p)                     ((p)->tcpvars.sack.type == TCP_OPT_SACK)
#define TCP_HAS_SACKOK(p)                   ((p)->tcpvars.sackok.type == TCP_OPT_SACKOK)
#define TCP_HAS_TS(p)                       ((p)->tcpvars.ts_set == TRUE)
#define TCP_HAS_MSS(p)                      ((p)->tcpvars.mss.type == TCP_OPT_MSS)
#define TCP_HAS_TFO(p)                      ((p)->tcpvars.tfo.type == TCP_OPT_TFO)

/** macro for getting the wscale from the packet. */
#define TCP_GET_WSCALE(p)                    (TCP_HAS_WSCALE((p)) ? \
                                                (((*(uint8_t *)(p)->tcpvars.ws.data) <= TCP_WSCALE_MAX) ? \
                                                  (*(uint8_t *)((p)->tcpvars.ws.data)) : 0) : 0)

#define TCP_GET_SACKOK(p)                    (TCP_HAS_SACKOK((p)) ? 1 : 0)
#define TCP_GET_SACK_PTR(p)                  TCP_HAS_SACK((p)) ? (p)->tcpvars.sack.data : NULL
#define TCP_GET_SACK_CNT(p)                  (TCP_HAS_SACK((p)) ? (((p)->tcpvars.sack.len - 2) / 8) : 0)
#define TCP_GET_MSS(p)                       SCNtohs(*(uint16_t *)((p)->tcpvars.mss.data))

#define TCP_GET_OFFSET(p)                    TCP_GET_RAW_OFFSET((p)->tcph)
#define TCP_GET_X2(p)                        TCP_GET_RAW_X2((p)->tcph)
#define TCP_GET_HLEN(p)                      (TCP_GET_OFFSET((p)) << 2)
#define TCP_GET_SRC_PORT(p)                  TCP_GET_RAW_SRC_PORT((p)->tcph)
#define TCP_GET_DST_PORT(p)                  TCP_GET_RAW_DST_PORT((p)->tcph)
#define TCP_GET_SEQ(p)                       TCP_GET_RAW_SEQ((p)->tcph)
#define TCP_GET_ACK(p)                       TCP_GET_RAW_ACK((p)->tcph)
#define TCP_GET_WINDOW(p)                    TCP_GET_RAW_WINDOW((p)->tcph)
#define TCP_GET_URG_POINTER(p)               TCP_GET_RAW_URG_POINTER((p)->tcph)
#define TCP_GET_SUM(p)                       TCP_GET_RAW_SUM((p)->tcph)
#define TCP_GET_FLAGS(p)                     (p)->tcph->th_flags

#define TCP_ISSET_FLAG_FIN(p)                ((p)->tcph->th_flags & TH_FIN)
#define TCP_ISSET_FLAG_SYN(p)                ((p)->tcph->th_flags & TH_SYN)
#define TCP_ISSET_FLAG_RST(p)                ((p)->tcph->th_flags & TH_RST)
#define TCP_ISSET_FLAG_PUSH(p)               ((p)->tcph->th_flags & TH_PUSH)
#define TCP_ISSET_FLAG_ACK(p)                ((p)->tcph->th_flags & TH_ACK)
#define TCP_ISSET_FLAG_URG(p)                ((p)->tcph->th_flags & TH_URG)
#define TCP_ISSET_FLAG_RES2(p)               ((p)->tcph->th_flags & TH_RES2)
#define TCP_ISSET_FLAG_RES1(p)               ((p)->tcph->th_flags & TH_RES1)

typedef struct TCPOpt_ {
    uint8_t type;
    uint8_t len;
    const uint8_t *data;
} TCPOpt;

typedef struct TCPOptSackRecord_ {
    uint32_t le;        /**< left edge, network order */
    uint32_t re;        /**< right edge, network order */
} TCPOptSackRecord;

typedef struct TCPHdr_
{
    uint16_t th_sport;  /**< source port */
    uint16_t th_dport;  /**< destination port */
    uint32_t th_seq;    /**< sequence number */
    uint32_t th_ack;    /**< acknowledgement number */
    uint8_t th_offx2;   /**< offset and reserved */
    uint8_t th_flags;   /**< pkt flags */
    uint16_t th_win;    /**< pkt window */
    uint16_t th_sum;    /**< checksum */
    uint16_t th_urp;    /**< urgent pointer */
} __attribute__((__packed__)) TCPHdr;

typedef struct TCPVars_
{
    /* commonly used and needed opts */
    bool md5_option_present;
    bool ao_option_present;
    bool ts_set;
    uint32_t ts_val;    /* host-order */
    uint32_t ts_ecr;    /* host-order */
    TCPOpt sack;
    TCPOpt sackok;
    TCPOpt ws;
    TCPOpt mss;
    TCPOpt tfo;         /* tcp fast open */
} TCPVars;

#define CLEAR_TCP_PACKET(p) {   \
    (p)->level4_comp_csum = -1; \
    PACKET_CLEAR_L4VARS((p));   \
    (p)->tcph = NULL;           \
}

#endif //NET_THREAT_DETECT_DECODE_TCP_H
