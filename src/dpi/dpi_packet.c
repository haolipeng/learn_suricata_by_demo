//
// Created by haolipeng on 2/6/23.
//

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "dpi_packet.h"
#include "dpi_module.h"
#include "utils/bits.h"

#define LOG_BAD_PKT(p, format, args...) \
        dpi_threat_trigger(DPI_THRT_BAD_PACKET, p, format, ##args)

#define TCP_FLAG_MASK (TH_PUSH | TH_URG | TH_FIN | TH_ACK | TH_SYN | TH_RST)
/*static uint8_t tcp_bad_flag_list[] = {
        0,
        TH_URG,
        TH_FIN,
        TH_PUSH,
        TH_PUSH | TH_FIN,
        TH_PUSH | TH_URG,
        TH_SYN | TH_FIN,
        TH_PUSH | TH_URG | TH_FIN,
        TH_PUSH | TH_URG | TH_FIN | TH_ACK | TH_SYN,
        TH_PUSH | TH_URG | TH_FIN | TH_ACK | TH_SYN | TH_RST,
};*/
BITMASK_DEFINE(tcp_bad_flag_mask, 256);


