//
// Created by root on 3/28/23.
//

#ifndef NET_THREAT_DETECT_STREAM_TCP_REASSEMBLE_H
#define NET_THREAT_DETECT_STREAM_TCP_REASSEMBLE_H

#include "stream-tcp-private.h"
#include "decode.h"
#include "packet-queue.h"

enum
{
    OS_POLICY_NONE = 1,
    OS_POLICY_BSD,
    OS_POLICY_BSD_RIGHT,
    OS_POLICY_OLD_LINUX,
    OS_POLICY_LINUX,
    OS_POLICY_OLD_SOLARIS,
    OS_POLICY_SOLARIS,
    OS_POLICY_HPUX10,
    OS_POLICY_HPUX11,
    OS_POLICY_IRIX,
    OS_POLICY_MACOS,
    OS_POLICY_WINDOWS,
    OS_POLICY_VISTA,
    OS_POLICY_WINDOWS2K3,
    OS_POLICY_FIRST,
    OS_POLICY_LAST
};

enum StreamUpdateDir {
    UPDATE_DIR_PACKET,
    UPDATE_DIR_OPPOSING,
    UPDATE_DIR_BOTH,
};

typedef struct TcpReassemblyThreadCtx_ {
    void *app_tctx;

    int segment_thread_pool_id;

    /** TCP segments which are not being reassembled due to memcap was reached */
    uint16_t counter_tcp_segment_memcap;
    /** number of streams that stop reassembly because their depth is reached */
    uint16_t counter_tcp_stream_depth;
    /** count number of streams with a unrecoverable stream gap (missing pkts) */
    uint16_t counter_tcp_reass_gap;

    /** count packet data overlaps */
    uint16_t counter_tcp_reass_overlap;
    /** count overlaps with different data */
    uint16_t counter_tcp_reass_overlap_diff_data;

    uint16_t counter_tcp_reass_data_normal_fail;
    uint16_t counter_tcp_reass_data_overlap_fail;
    uint16_t counter_tcp_reass_list_fail;
} TcpReassemblyThreadCtx;

int StreamTcpReassembleHandleSegment(TcpSession *, TcpStream *, Packet *, PacketQueueNoLock *);
int StreamTcpReassembleHandleSegmentHandleData(TcpSession *ssn, TcpStream *stream, Packet *p);
int StreamTcpReassembleInsertSegment(TcpStream *, TcpSegment *, Packet *, uint32_t pkt_seq, uint8_t *pkt_data, uint16_t pkt_datalen);
#endif //NET_THREAT_DETECT_STREAM_TCP_REASSEMBLE_H
