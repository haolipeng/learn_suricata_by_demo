//
// Created by haolipeng on 1/11/23.
//
#include <stddef.h>
#include <linux/if_ether.h>
#include <string.h>

//user header file
#include "dpi_module.h"
#include "dpi_packet.h"
#include "decode.h"

dpi_thread_data_t g_dpi_thread_data[MAX_THREADS];
io_callback_t *g_io_callback;
io_config_t *g_io_config;

// Global
void dpi_setup(io_callback_t *cb, io_config_t *cfg)
{
    g_io_callback = cb;//assign to global var
    g_io_config = cfg;
}

int dpi_recv_packet(io_ctx_t* ctx,uint8_t* ptr, int len){
    per_core_snap.tick = ctx->tick;

    memset(&per_core_packet, 0, sizeof(Packet));
    per_core_packet.datalink = LINKTYPE_ETHERNET;

    //测试解析以太网数据包
    DecodeEthernet(&per_core_packet, ptr, len);

    //TODO:基于流的分析和统计
    return 0;
}