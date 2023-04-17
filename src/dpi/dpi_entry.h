//
// Created by haolipeng on 1/11/23.
//

#ifndef NET_THREAT_DETECT_DPI_ENTRY_H
#define NET_THREAT_DETECT_DPI_ENTRY_H

void dpi_setup(io_callback_t *cb, io_config_t *cfg);
int dpi_recv_packet(io_ctx_t* ctx,uint8_t* prt, int len);

#endif //NET_THREAT_DETECT_DPI_ENTRY_H
