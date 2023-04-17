//
// Created by haolipeng on 4/1/23.
//
#include "common.h"
#include "decode-ethernet.h"
#include "decode.h"
#include "dpi_module.h"

int DecodeEthernet(Packet *p,const uint8_t *pkt, uint32_t len)
{
    if (unlikely(len < ETHERNET_HEADER_LEN)) {
        //ENGINE_SET_INVALID_EVENT(p, ETHERNET_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    p->ethh = (EthernetHdr *)pkt;
    if (unlikely(p->ethh == NULL))
        return TM_ECODE_FAILED;

    p->eth_type = SCNtohs(p->ethh->eth_type);
    const uint8_t * data = pkt + ETHERNET_HEADER_LEN;
    uint32_t new_len = len - ETHERNET_HEADER_LEN;

    per_core_counter.pkt_id ++;
    p->id = per_core_counter.pkt_id;

    DecodeNetworkLayer(SCNtohs(p->ethh->eth_type), p,data, new_len);

    return TM_ECODE_OK;
}
