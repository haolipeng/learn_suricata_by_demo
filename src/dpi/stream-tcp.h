#ifndef NET_THREAT_DETECT_STREAM_TCP_H
#define NET_THREAT_DETECT_STREAM_TCP_H

#include "decode.h"
#include "packet-queue.h"
#include "stream-tcp-reassemble.h"

/** ------- Inline functions: ------ */
enum {
    /* stream has no segments for forced reassembly, nor for detection */
    STREAM_HAS_UNPROCESSED_SEGMENTS_NONE = 0,
    /* stream has no segments for forced reassembly, but only segments that
     * have been sent for detection, but are stuck in the detection queues */
    STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION = 1,
};

TmEcode StreamTcp (Packet *, void *, PacketQueueNoLock *);
typedef struct StreamTcpThread_ {
    int ssn_pool_id;

    /** queue for pseudo packet(s) that were created in the stream
     *  process and need further handling. Currently only used when
     *  receiving (valid) RST packets */
    PacketQueueNoLock pseudo_queue;

    uint16_t counter_tcp_sessions;
    /** sessions not picked up because memcap was reached */
    uint16_t counter_tcp_ssn_memcap;
    /** pseudo packets processed */
    uint16_t counter_tcp_pseudo;
    /** pseudo packets failed to setup */
    uint16_t counter_tcp_pseudo_failed;
    /** packets rejected because their csum is invalid */
    uint16_t counter_tcp_invalid_checksum;
    /** TCP packets with no associated flow */
    uint16_t counter_tcp_no_flow;
    /** sessions reused */
    uint16_t counter_tcp_reused_ssn;
    /** syn pkts */
    uint16_t counter_tcp_syn;
    /** syn/ack pkts */
    uint16_t counter_tcp_synack;
    /** rst pkts */
    uint16_t counter_tcp_rst;
    /** midstream pickups */
    uint16_t counter_tcp_midstream_pickups;
    /** wrong thread */
    uint16_t counter_tcp_wrong_thread;

    /** tcp reassembly thread data */
    TcpReassemblyThreadCtx *ra_ctx;
} StreamTcpThread;

#endif //NET_THREAT_DETECT_STREAM_TCP_H
