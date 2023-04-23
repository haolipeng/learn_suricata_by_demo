#include "decode/decode.h"
#include "dpi_module.h"

dpi_thread_data_t g_dpi_thread_data[MAX_THREADS];

int dpi_recv_packet(io_ctx_t* ctx,uint8_t* ptr, int len){
    Packet* p = PacketGetFromQueueOrAlloc();
    p->datalink = LINKTYPE_ETHERNET;

    //ThreadVars *tv,
    // TmSlot *s,
    // Packet *p
    //TmThreadsSlotProcessPkt(); //TODO:
    return 0;
}