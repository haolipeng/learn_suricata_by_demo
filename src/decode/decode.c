#include "decode.h"
#define DEFAULT_MTU 1500
#define DEFAULT_PACKET_SIZE (DEFAULT_MTU + ETHERNET_HEADER_LEN)
uint32_t default_packet_size = DEFAULT_PACKET_SIZE;

inline int PacketCallocExtPkt(Packet *p, int datalen)
{
  if (! p->ext_pkt) {
    p->ext_pkt = calloc(1, datalen);
    if (unlikely(p->ext_pkt == NULL)) {
      SET_PKT_LEN(p, 0);
      return -1;
    }
  }
  return 0;
}

void PacketFree(Packet *p)
{
   PACKET_DESTRUCTOR(p);
   free(p);
}

/**
 * \brief Get a malloced packet.
 *
 * \retval p packet, NULL on error
 */
Packet *PacketGetFromAlloc(void)
{
  Packet *p = malloc(SIZE_OF_PACKET);
  if (unlikely(p == NULL)) {
    return NULL;
  }

  memset(p, 0, SIZE_OF_PACKET);
  PACKET_INITIALIZE(p);//init the packet
  p->ReleasePacket = PacketFree;
  p->flags |= PKT_ALLOC;

  SCLogDebug("allocated a new packet only using alloc...");
  return p;
}
