#include <netinet/udp.h>
#include "dpi_packet.h"
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


