cmake_minimum_required(VERSION 3.16)
project(net_threat_detect C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_BUILD_TYPE "debug")

#
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0 -Wall -Werror -Wno-unused-result -Wno-unused-function -fstrict-aliasing -Wstrict-aliasing")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_Release} -g -O0 -Wall -Werror -Wno-unused-result -Wno-unused-function -fstrict-aliasing -Wstrict-aliasing")

include_directories(.)
include_directories(src)
include_directories(third-party/include)
include_directories("/usr/local/include")

link_directories(third-party/lib)
link_directories("/usr/local/lib")

add_executable(net_threat_detect
        main.c
        src/packet.c src/packet.h
        src/ring.c src/ring.h
        src/pcap.c src/pcap.h
        src/debug.c src/debug.h
        src/common.h
        src/base.h
        src/apis.h

        src/dpi/dpi_module.h
        src/dpi/dpi_entry.c src/dpi/dpi_entry.h
        src/dpi/dpi_packet.c src/dpi/dpi_packet.h
        src/dpi/dpi_debug.c src/dpi/dpi_debug.h
        src/dpi/tree.h

        src/utils/helper.h
        src/utils/bits.h
        src/utils/timer_queue.c src/utils/timer_queue.h
        src/dpi/stream-tcp.c src/dpi/stream-tcp-private.h
        src/dpi/stream-tcp-list.c src/dpi/decode.h
        src/dpi/decode-ethernet.h
        src/dpi/decode-ipv4.h src/dpi/decode-ipv4.c src/dpi/decode-ipv6.h
        src/dpi/decode-tcp.h src/dpi/decode-tcp.c
        src/dpi/decode-udp.h src/dpi/decode-udp.c
        src/dpi/flow.h src/dpi/common.h  src/dpi/stream.h
        src/dpi/streaming-buffer.h src/dpi/streaming-buffer.c
        src/dpi/stream-tcp-reassemble.h src/dpi/stream-tcp-reassemble.c

        src/dpi/stream-tcp-inline.c src/dpi/stream-tcp-inline.h
        src/dpi/stream-tcp-sack.h src/dpi/stream-tcp-sack.c
        src/dpi/decode-ethernet.c
        src/dpi/packet-queue.h src/dpi/packet-queue.c src/dpi/util-debug.c src/dpi/util-debug.h src/dpi/util-error.h src/dpi/util-error.c src/dpi/util-enum.h src/dpi/util-enum.c src/dpi/flow-worker.c src/dpi/decode-events.h src/dpi/stream-tcp.h src/dpi/flow-queue.h src/dpi/flow-queue.c src/dpi/threads.h src/dpi/util-atomic.h src/dpi/util-atomic.c src/dpi/tmqh-packetpool.h src/dpi/tmqh-packetpool.c src/dpi/util-optimize.h src/dpi/flow-timeout.c src/dpi/flow.c src/dpi/flow-spare-pool.h src/dpi/flow-spare-pool.c src/dpi/address-port.h src/dpi/queue.h src/dpi/packet-define.h src/dpi/decode-thread-var.h src/dpi/threadvars.h src/dpi/decode.c)

target_link_libraries(net_threat_detect
        pthread
        pcap
        urcu
        urcu-cds)