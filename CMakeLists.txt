cmake_minimum_required(VERSION 3.16)
project(net_threat_detect C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_BUILD_TYPE "debug")

#
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0 -Wall -Werror -Wno-unused-result -Wno-unused-function -fstrict-aliasing -Wstrict-aliasing")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_Release} -g -O0 -Wall -Werror -Wno-unused-result -Wno-unused-function -fstrict-aliasing -Wstrict-aliasing")

include_directories(./src)
include_directories(third-party/include)
include_directories("/usr/local/include")

link_directories(third-party/lib)
link_directories("/usr/local/lib")

add_executable(net_threat_detect
        main.c
        src/packet.c src/packet.h
        src/ring.c src/ring.h
        src/pcap.c src/pcap.h
        src/common.h
        src/base.h
        src/apis.h

        src/dpi/dpi_module.h
        src/dpi/dpi_entry.c src/dpi/dpi_entry.h
        src/dpi/dpi_packet.c src/dpi/dpi_packet.h
        src/dpi/tree.h

        src/utils/helper.h
        src/utils/bits.h
        src/dpi/common.h
        src/dpi/stream.h

        src/utils/timer_queue.c src/utils/timer_queue.h
        src/dpi/stream-tcp.h src/dpi/stream-tcp.c src/dpi/stream-tcp-private.h
        src/dpi/stream-tcp-list.c

        src/dpi/streaming-buffer.h src/dpi/streaming-buffer.c
        src/dpi/stream-tcp-reassemble.h src/dpi/stream-tcp-reassemble.c
        src/dpi/stream-tcp-inline.c src/dpi/stream-tcp-inline.h
        src/dpi/stream-tcp-sack.h src/dpi/stream-tcp-sack.c

        src/decode/decode-ethernet.h src/decode/decode-ethernet.c
        src/decode/decode-ipv4.h src/decode/decode-ipv4.c src/decode/decode-ipv6.h
        src/decode/decode-tcp.h src/decode/decode-tcp.c
        src/decode/decode-udp.h src/decode/decode-udp.c

        src/dpi/packet-queue.h src/dpi/packet-queue.c
        src/utils/util-debug.h src/utils/util-debug.c
        src/utils/util-error.h src/utils/util-error.c
        src/utils/util-enum.h src/utils/util-enum.c
        src/utils/util-atomic.h src/utils/util-atomic.c
        src/utils/util-random.h src/utils/util-random.c
        src/utils/util-misc.h src/utils/util-misc.c
        src/utils/util-byte.h src/utils/util-byte.c

        src/flow/flow-manager.h src/flow/flow-manager.c
        src/dpi/flow-worker.c src/decode/decode-events.h
        src/flow/flow-queue.h src/flow/flow-queue.c
        src/dpi/tmqh-packetpool.h src/dpi/tmqh-packetpool.c
        src/flow/flow-timeout.h src/flow/flow-timeout.c
        src/flow/flow.h src/flow/flow.c
        src/flow/flow-spare-pool.h src/flow/flow-spare-pool.c
        src/decode/decode.c src/decode/decode.h
        src/decode/decode-thread-var.h src/decode/decode-thread-var.c
        src/app-layer/app-layer-events.h src/app-layer/app-layer-events.c
        src/app-layer/app-layer-parser.h src/app-layer/app-layer-parser.c
        src/dpi/conf.h src/dpi/conf.c
        src/utils/util-pool-thread.h src/utils/util-pool-thread.c
        src/utils/util-pool.h src/utils/util-pool.c
        src/flow/flow-util.h src/flow/flow-util.c
        src/flow/flow-hash.h src/flow/flow-hash.c
        src/utils/util-time.h src/utils/util-time.c
        src/dpi/detect.h src/dpi/address-port.h src/dpi/queue.h src/dpi/packet-define.h
        src/dpi/threadvars.h src/utils/util-optimize.h src/dpi/threads.h src/utils/util-hash-lookup3.h src/utils/util-hash-lookup3.c src/dpi/tm-threads.h src/dpi/tm-threads.c)

target_link_libraries(net_threat_detect
        pthread
        pcap
        urcu
        pcre
        urcu-cds)