//
// Created by haolipeng on 2/6/23.
//

#ifndef NET_THREAT_DETECT_DPI_PACKET_H
#define NET_THREAT_DETECT_DPI_PACKET_H

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#include <stdbool.h>

#include "base.h"
#include "utils/helper.h"
#include "dpi_packet.h"
#include "apis.h"
#include "decode.h"

#define DPI_PKT_FLAG_SACKOK        0x00000001
#define DPI_PKT_FLAG_TCP_TS        0x00000002
#define DPI_PKT_FLAG_CLIENT        0x00000004
#define DPI_PKT_FLAG_NEW_SESSION   0x00000008
#define DPI_PKT_FLAG_ASSEMBLED     0x00000010
#define DPI_PKT_FLAG_CACHED        0x00000020
#define DPI_PKT_FLAG_INGRESS       0x00000100
#define DPI_PKT_FLAG_FAKE_EP       0x00000200

#define DPI_PKT_FLAG_SKIP_PARSER   0x00000040

#define ETHERNET_HEADER_LEN           14
#define IPV4_HEADER_LEN           20    /**< Header length */

/*Given a packet pkt offset to the start of the ip header in a packet We determine the ip version. */
#define IP_GET_RAW_VER(pkt) ((((pkt)[0] & 0xf0) >> 4))

#define TCP_HEADER_LEN                       20
#define TCP_OPTLENMAX                        40

#endif //NET_THREAT_DETECT_DPI_PACKET_H
