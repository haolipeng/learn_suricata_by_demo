#include <netinet/in.h>
#include "decode-ipv6.h"
#include "base.h"
#include "dpi/tm-threads-common.h"
#include "decode.h"

static int DecodeIPV6Packet (Packet *p, const uint8_t *pkt, uint16_t len)
{
    if (unlikely(len < IPV6_HEADER_LEN)) {
        return -1;
    }

    if (unlikely(IP_GET_RAW_VER(pkt) != 6)) {
        SCLogDebug("wrong ip version %d",IP_GET_RAW_VER(pkt));
        ENGINE_SET_INVALID_EVENT(p, IPV6_WRONG_IP_VER);
        return -1;
    }

    p->ip6h = (IPV6Hdr *)pkt;

    if (unlikely(len < (IPV6_HEADER_LEN + IPV6_GET_PLEN(p))))
    {
        ENGINE_SET_INVALID_EVENT(p, IPV6_TRUNC_PKT);
        return -1;
    }

    SET_IPV6_SRC_ADDR(p,&p->src);
    SET_IPV6_DST_ADDR(p,&p->dst);

    return 0;
}

int DecodeIPV6(Packet *p, const uint8_t *pkt, uint16_t len)
{
    /* do the actual decoding */
    int ret = DecodeIPV6Packet (p, pkt, len);
    if (unlikely(ret < 0)) {
        CLEAR_IPV6_PACKET(p);
        return TM_ECODE_FAILED;
    }

    /* now process the Ext headers and/or the L4 Layer */
    switch(IPV6_GET_NH(p)) {
        case IPPROTO_TCP:
            IPV6_SET_L4PROTO (p, IPPROTO_TCP);
            DecodeTCP(p, pkt + IPV6_HEADER_LEN, IPV6_GET_PLEN(p));
            return TM_ECODE_OK;
        case IPPROTO_UDP:
            IPV6_SET_L4PROTO (p, IPPROTO_UDP);
            DecodeUDP(p, pkt + IPV6_HEADER_LEN, IPV6_GET_PLEN(p));
            return TM_ECODE_OK;
        case IPPROTO_ICMPV6:
            IPV6_SET_L4PROTO (p, IPPROTO_ICMPV6);
            //DecodeICMPV6(p, pkt + IPV6_HEADER_LEN, IPV6_GET_PLEN(p));
            return TM_ECODE_OK;
        case IPPROTO_ICMP:
            ENGINE_SET_EVENT(p,IPV6_WITH_ICMPV4);
            break;
        default:
            ENGINE_SET_EVENT(p, IPV6_UNKNOWN_NEXT_HEADER);
            IPV6_SET_L4PROTO (p, IPV6_GET_NH(p));
            break;
    }
    p->proto = IPV6_GET_L4PROTO (p);

    /* Pass to defragger if a fragment. */
    //TODO:modify by haolipeng
    /*if (IPV6_EXTHDR_ISSET_FH(p)) {
        Packet *rp = Defrag(tv, dtv, p);
        if (rp != NULL) {
            PacketEnqueueNoLock(&tv->decode_pq,rp);
        }
    }*/

    return TM_ECODE_OK;
}
