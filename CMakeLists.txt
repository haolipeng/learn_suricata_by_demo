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

        /*reassemble*/
        src/reassemble/stream.h src/reassemble/tree.h
        src/reassemble/stream-tcp.h src/reassemble/stream-tcp.c
        src/reassemble/stream-tcp-private.h
        src/reassemble/stream-tcp-list.c
        src/reassemble/streaming-buffer.h src/reassemble/streaming-buffer.c
        src/reassemble/stream-tcp-reassemble.h src/reassemble/stream-tcp-reassemble.c
        src/reassemble/stream-tcp-inline.h src/reassemble/stream-tcp-inline.c
        src/reassemble/stream-tcp-sack.h src/reassemble/stream-tcp-sack.c

        /*decode*/
        src/decode/decode-ethernet.h src/decode/decode-ethernet.c
        src/decode/decode-ipv4.h src/decode/decode-ipv4.c src/decode/decode-ipv6.h
        src/decode/decode-tcp.h src/decode/decode-tcp.c
        src/decode/decode-udp.h src/decode/decode-udp.c
        src/decode/decode.c src/decode/decode.h
        src/decode/decode-thread-var.h src/decode/decode-thread-var.c
        src/decode/decode-events.h src/decode/decode-vlan.h

        /*utils*/
        src/utils/helper.h
        src/utils/bits.h
        src/utils/util-debug.h src/utils/util-debug.c
        src/utils/util-error.h src/utils/util-error.c
        src/utils/util-enum.h src/utils/util-enum.c
        src/utils/util-atomic.h src/utils/util-atomic.c
        src/utils/util-random.h src/utils/util-random.c
        src/utils/util-misc.h src/utils/util-misc.c
        src/utils/util-byte.h src/utils/util-byte.c
        src/utils/conf.h src/utils/conf.c
        src/utils/timer_queue.h src/utils/timer_queue.c
        src/utils/util-pool-thread.h src/utils/util-pool-thread.c
        src/utils/util-pool.h src/utils/util-pool.c
        src/utils/util-time.h src/utils/util-time.c
        src/utils/util-hash-lookup3.h src/utils/util-hash-lookup3.c
        src/utils/util-path.c src/utils/util-path.h
        src/utils/util-conf.h src/utils/util-conf.c
        src/utils/util-device.h src/utils/util-device.c
        src/utils/util-strlcatu.h src/utils/util-strlcatu.c
        src/utils/util-exception-policy.h src/utils/util-exception-policy.c
        src/utils/util-ioctl.h src/utils/util-ioctl.c
        src/utils/util-optimize.h src/utils/util-mem.h

        /*flow*/
        src/flow/flow-manager.h src/flow/flow-manager.c
        src/flow/flow-queue.h src/flow/flow-queue.c
        src/flow/flow-timeout.h src/flow/flow-timeout.c
        src/flow/flow.h src/flow/flow.c
        src/flow/flow-spare-pool.h src/flow/flow-spare-pool.c
        src/flow/flow-util.h src/flow/flow-util.c
        src/flow/flow-hash.h src/flow/flow-hash.c
        src/flow/flow-worker.h src/flow/flow-worker.c

        /*app-layer*/
        src/app-layer/app-layer-events.h src/app-layer/app-layer-events.c
        src/app-layer/app-layer-parser.h src/app-layer/app-layer-parser.c

        /*dpi*/
        src/dpi/dpi_module.h src/dpi/common.h src/dpi/main.h
        src/dpi/dpi_entry.c src/dpi/dpi_entry.h
        src/dpi/packet-queue.h src/dpi/packet-queue.c
        src/dpi/tmqh-packetpool.h src/dpi/tmqh-packetpool.c
        src/dpi/detect.h src/dpi/address-port.h src/dpi/queue.h src/dpi/packet-define.h
        src/dpi/threadvars.h  src/dpi/threads.h
        src/dpi/autoconf.h
        src/dpi/tm-threads.h src/dpi/tm-threads.c
        src/dpi/tm-queues.h src/dpi/tm-queues.c
        src/dpi/tm-queuehandlers.h src/dpi/tm-queuehandlers.c

        src/dpi/source-af-packet.h src/dpi/source-af-packet.c
        src/dpi/tm-modules.h src/dpi/tm-modules.c
        src/dpi/tm-threads-common.h src/dpi/runmode-af-packet.h src/dpi/runmode-af-packet.c
        src/dpi/runmodes.c src/dpi/runmodes.h
        src/dpi/runmode-pcap-file.h src/dpi/runmode-pcap-file.c
        src/dpi/conf-yaml-loader.c src/dpi/conf-yaml-loader.h
        )

target_link_libraries(net_threat_detect
        pthread
        pcap
        urcu
        pcre
        yaml
        urcu-cds)