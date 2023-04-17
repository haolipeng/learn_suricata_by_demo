//
// Created by haolipeng on 2/6/23.
//

#ifndef NET_THREAT_DETECT_DPI_MODULE_H
#define NET_THREAT_DETECT_DPI_MODULE_H
#include "apis.h"
#include "dpi_packet.h"
#include "decode.h"

typedef struct dpi_snap_ {
    uint32_t tick;
} dpi_snap_t;

// Thread data
typedef struct dpi_thread_data_ {
    Packet packet;//add by haolipeng for

    dpi_snap_t snap;
    io_counter_t counter;//statistics per thread
} dpi_thread_data_t;

extern dpi_thread_data_t g_dpi_thread_data[];
extern io_callback_t *g_io_callback;

#define per_core_packet           (g_dpi_thread_data[THREAD_ID].packet)
#define per_core_snap             (g_dpi_thread_data[THREAD_ID].snap)
#define per_core_counter          (g_dpi_thread_data[THREAD_ID].counter)
#define per_core_timer            (g_dpi_thread_data[THREAD_ID].timer)

#endif //NET_THREAT_DETECT_DPI_MODULE_H
