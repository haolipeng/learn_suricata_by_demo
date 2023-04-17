//
// Created by haolipeng on 3/28/23.
//

#include <string.h>
#include "stream-tcp-reassemble.h"
#include "stream-tcp-private.h"
#include "decode.h"
#include "packet-queue.h"
#include "stream.h"

int StreamTcpReassembleHandleSegmentHandleData(TcpSession *ssn, TcpStream *stream, Packet *p);
TcpSegment *StreamTcpGetSegment();//Get a tcp segment
/** \internal
 *  \brief update app layer based on received ACK
 *
 *  \retval r 0 on success, -1 on error
 */
static int StreamTcpReassembleHandleSegmentUpdateACK (TcpSession *ssn, TcpStream *stream, Packet *p)
{
    //TODO:update app layer based on received ACK
    //TODO:modify by haolipeng
    /*if (StreamTcpReassembleAppLayer(ssn, stream, p, UPDATE_DIR_OPPOSING) < 0)
        return -1;*/

    return 0;
}

/**
 *  \internal
 *  \brief Function to Check the reassembly depth valuer against the
 *        allowed max depth of the stream reassembly for TCP streams.
 *
 *  \param stream stream direction
 *  \param seq sequence number where "size" starts
 *  \param size size of the segment that is added
 *
 *  \retval size Part of the size that fits in the depth, 0 if none
 */
static uint32_t StreamTcpReassembleCheckDepth(TcpSession *ssn, TcpStream *stream,
                                              uint32_t seq, uint32_t size)
{
    /* if the configured depth value is 0, it means there is no limit on
       reassembly depth. Otherwise carry on my boy ;) */
    if (ssn->reassembly_depth == 0) {
        return size;
    }

    /* if the final flag is set, we're not accepting anymore */
    if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) {
        return 0;
    }

    uint64_t seg_depth;
    if (SEQ_GT(stream->base_seq, seq)) {
        if (SEQ_LEQ(seq+size, stream->base_seq)) {
            //SCLogDebug("segment entirely before base_seq, weird: base %u, seq %u, re %u",
            //           stream->base_seq, seq, seq+size);
            return 0;
        }

        seg_depth = STREAM_BASE_OFFSET(stream) + size - (stream->base_seq - seq);
    } else {
        seg_depth = STREAM_BASE_OFFSET(stream) + ((seq + size) - stream->base_seq);
    }

    /* if the base_seq has moved passed the depth window we stop
     * checking and just reject the rest of the packets including
     * retransmissions. Saves us the hassle of dealing with sequence
     * wraps as well */
    /*SCLogDebug("seq + size %u, base %u, seg_depth %"PRIu64" limit %u", (seq + size),
               stream->base_seq, seg_depth,
               ssn->reassembly_depth);*/

    if (seg_depth > (uint64_t)ssn->reassembly_depth) {
        //SCLogDebug("STREAMTCP_STREAM_FLAG_DEPTH_REACHED");
        stream->flags |= STREAMTCP_STREAM_FLAG_DEPTH_REACHED;
        return 0;
    }
    //SCLogDebug("NOT STREAMTCP_STREAM_FLAG_DEPTH_REACHED");
    //SCLogDebug("%"PRIu64" <= %u", seg_depth, ssn->reassembly_depth);
#if 0
    SCLogDebug("full depth not yet reached: %"PRIu64" <= %"PRIu32,
            (stream->base_seq_offset + stream->base_seq + size),
            (stream->isn + ssn->reassembly_depth));
#endif
    if (SEQ_GEQ(seq, stream->isn) && SEQ_LT(seq, (stream->isn + ssn->reassembly_depth))) {
        /* packet (partly?) fits the depth window */

        if (SEQ_LEQ((seq + size),(stream->isn + 1 + ssn->reassembly_depth))) {
            /* complete fit */
            return size;
        } else {
            stream->flags |= STREAMTCP_STREAM_FLAG_DEPTH_REACHED;
            /* partial fit, return only what fits */
            uint32_t part = (stream->isn + 1 + ssn->reassembly_depth) - seq;
            DEBUG_VALIDATE_BUG_ON(part > size);
            if (part > size)
                part = size;
            return part;
        }
    }

    return 0;
}

/**
 *  \brief Insert a packets TCP data into the stream reassembly engine.
 *
 *  \retval 0 good segment, as far as we checked.
 *  \retval -1 badness, reason to drop in inline mode
 *
 *  If the retval is 0 the segment is inserted correctly, or overlap is handled,
 *  or it wasn't added because of reassembly depth.
 *
 */
int StreamTcpReassembleHandleSegmentHandleData(TcpSession *ssn, TcpStream *stream, Packet *p)
{
    //第一次看到数据的方向
    if (ssn->data_first_seen_dir == 0) {
        if (PKT_IS_TOSERVER(p)) {
            ssn->data_first_seen_dir = STREAM_TOSERVER;
        } else {
            ssn->data_first_seen_dir = STREAM_TOCLIENT;
        }
    }

    /* If the OS policy is not set then set the OS policy for this stream */
    if (stream->os_policy == 0) {
        //TODO:don't set os policy,add later.
        //StreamTcpSetOSPolicy(stream, p);
    }

    //同时标识session的STREAMTCP_FLAG_APP_LAYER_DISABLED和stram的STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED，
    // app and raw reassembly disable则无需重组
    if ((ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) &&
        (stream->flags & STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED)) {
        //SCLogDebug("ssn %p: both app and raw reassembly disabled, not reassembling", ssn);
        return 0;
    }

    //检测重组深度
    /* If we have reached the defined depth for either of the stream, then stop
       reassembling the TCP session */
    uint32_t size = StreamTcpReassembleCheckDepth(ssn, stream, TCP_GET_SEQ(p), p->payload_len);
    //SCLogDebug("ssn %p: check depth returned %"PRIu32, ssn, size);

    if (size == 0) {
        //SCLogDebug("ssn %p: depth reached, not reassembling", ssn);
        return 0;
    }

    DEBUG_VALIDATE_BUG_ON(size > p->payload_len);
    if (size > p->payload_len)
        size = p->payload_len;

    //获取一个TcpSegment,设置其seq序列号和payload_len
    TcpSegment *seg = StreamTcpGetSegment();
    if (seg == NULL) {
        //SCLogDebug("segment_pool is empty");
        //StreamTcpSetEvent(p, STREAM_REASSEMBLY_NO_SEGMENT);
        return -1;
    }

    TCP_SEG_LEN(seg) = size;
    seg->seq = TCP_GET_SEQ(p);

    /* HACK: for TFO SYN packets the seq for data starts at + 1 */
    if (TCP_HAS_TFO(p) && p->payload_len && p->tcph->th_flags == TH_SYN)
        seg->seq += 1;

    /* proto detection skipped, but now we do get data. Set event. */
    if (RB_EMPTY(&stream->seg_tree) &&
        stream->flags & STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_SKIPPED) {

        //TODO:modify by haolipeng
        //AppLayerDecoderEventsSetEventRaw(&p->app_layer_events,APPLAYER_PROTO_DETECTION_SKIPPED);
    }

    //tcp重组插入segment
    if (StreamTcpReassembleInsertSegment(stream, seg, p, TCP_GET_SEQ(p), p->payload, p->payload_len) != 0) {
        //SCLogDebug("StreamTcpReassembleInsertSegment failed");
        return -1;
    }
    return 0;
}

TcpSegment *StreamTcpGetSegment()
{
    //TODO:haolipeng,modify,instead of get a segment from a pool, we simple malloc it ,modify later
    //TcpSegment *seg = (TcpSegment *) PoolThreadGetById(segment_thread_pool, ra_ctx->segment_thread_pool_id);
    TcpSegment *seg = (TcpSegment*) malloc(sizeof(TcpSegment));

    //SCLogDebug("seg we return is %p", seg);
    if (seg == NULL) {
        /* Increment the counter to show that we are not able to serve the
           segment request due to memcap limit */
        //StatsIncr(tv, ra_ctx->counter_tcp_segment_memcap);
    } else {
        memset(&seg->sbseg, 0, sizeof(seg->sbseg));
    }

    return seg;
}

int StreamTcpReassembleHandleSegment(TcpSession *ssn, TcpStream *stream, Packet *p, PacketQueueNoLock *pq)
{
    DEBUG_VALIDATE_BUG_ON(p->tcph == NULL);

    /*SCLogDebug("ssn %p, stream %p, p %p, p->payload_len %"PRIu16"",
               ssn, stream, p, p->payload_len);*/

    /* default IDS: update opposing side (triggered by ACK) */
    enum StreamUpdateDir dir = UPDATE_DIR_OPPOSING;
    /* inline and stream end and flow timeout packets trigger same dir handling */
    if (p->tcph->th_flags & TH_RST) { // accepted rst
        dir = UPDATE_DIR_PACKET;
    } else if ((p->tcph->th_flags & TH_FIN) && ssn->state > TCP_TIME_WAIT) {
        if (p->tcph->th_flags & TH_ACK) {
            dir = UPDATE_DIR_BOTH;
        } else {
            dir = UPDATE_DIR_PACKET;
        }
    } else if (ssn->state == TCP_CLOSED) {
        dir = UPDATE_DIR_BOTH;
    }

    /* handle ack received */
    if ((dir == UPDATE_DIR_OPPOSING || dir == UPDATE_DIR_BOTH)) {
        /* we need to update the opposing stream in
         * StreamTcpReassembleHandleSegmentUpdateACK */
        TcpStream *opposing_stream = NULL;
        if (stream == &ssn->client) {
            opposing_stream = &ssn->server;
        } else {
            opposing_stream = &ssn->client;
        }

        //TODO:modify by haolipeng,use reversed_before_ack_handling var to compare
        //const bool reversed_before_ack_handling = (p->flow->flags & FLOW_DIR_REVERSED) != 0;

        if (StreamTcpReassembleHandleSegmentUpdateACK(ssn, opposing_stream, p) != 0) {
            //SCLogDebug("StreamTcpReassembleHandleSegmentUpdateACK error");
            return -1;
        }

        //TODO:modify by haolipeng
        /* StreamTcpReassembleHandleSegmentUpdateACK
         * may swap content of ssn->server and ssn->client structures.
         * We have to continue with initial content of the stream in such case */
        /*const bool reversed_after_ack_handling = (p->flow->flags & FLOW_DIR_REVERSED) != 0;
        if (reversed_before_ack_handling != reversed_after_ack_handling) {
            SCLogDebug("TCP streams were swapped");
            stream = opposing_stream;
        }*/
    }
    /* if this segment contains data, insert it */
    if (p->payload_len > 0 && !(stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        //SCLogDebug("calling StreamTcpReassembleHandleSegmentHandleData");

        if (StreamTcpReassembleHandleSegmentHandleData(ssn, stream, p) != 0) {
            //SCLogDebug("StreamTcpReassembleHandleSegmentHandleData error");
            return -1;
        }

        //SCLogDebug("packet %"PRIu64" set PKT_STREAM_ADD", p->pcap_cnt);
        p->flags |= PKT_STREAM_ADD;
    } else {
        /*SCLogDebug("ssn %p / stream %p: not calling StreamTcpReassembleHandleSegmentHandleData:"
                   " p->payload_len %u, STREAMTCP_STREAM_FLAG_NOREASSEMBLY %s",
                   ssn, stream, p->payload_len,
                   (stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) ? "true" : "false");*/
    }

    /* if the STREAMTCP_STREAM_FLAG_DEPTH_REACHED is set, but not the
     * STREAMTCP_STREAM_FLAG_NOREASSEMBLY flag, it means the DEPTH flag
     * was *just* set. In this case we trigger the AppLayer Truncate
     * logic, to inform the applayer no more data in this direction is
     * to be expected. */
    if ((stream->flags & (STREAMTCP_STREAM_FLAG_DEPTH_REACHED|STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) == STREAMTCP_STREAM_FLAG_DEPTH_REACHED)
    {
        //SCLogDebug("STREAMTCP_STREAM_FLAG_DEPTH_REACHED, truncate applayer");
        if (dir != UPDATE_DIR_PACKET) {
            /*SCLogDebug("override: direction now UPDATE_DIR_PACKET so we "
                       "can trigger Truncate");*/
            dir = UPDATE_DIR_PACKET;
        }
    }

    /* in stream inline mode even if we have no data we call the reassembly
     * functions to handle EOF */
    if (dir == UPDATE_DIR_PACKET || dir == UPDATE_DIR_BOTH) {
        /*SCLogDebug("inline (%s) or PKT_PSEUDO_STREAM_END (%s)",
                   StreamTcpInlineMode()?"true":"false",
                   (p->flags & PKT_PSEUDO_STREAM_END) ?"true":"false");*/
        //TODO:modify by haolipeng,need do appLayer detect
        /*if (StreamTcpReassembleAppLayer(ssn, stream, p, dir) < 0) {
            return -1;
        }*/
    }

    return 0;
}
