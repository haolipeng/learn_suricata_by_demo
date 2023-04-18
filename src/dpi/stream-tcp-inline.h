#ifndef NET_THREAT_DETECT_STREAM_TCP_INLINE_H
#define NET_THREAT_DETECT_STREAM_TCP_INLINE_H

#include "stream-tcp-private.h"
#include "decode.h"
#include "common.h"

int StreamTcpInlineSegmentCompare(const TcpStream *, const Packet *, const TcpSegment *);

#endif //NET_THREAT_DETECT_STREAM_TCP_INLINE_H
