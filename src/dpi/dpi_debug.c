#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "dpi/dpi_module.h"
#include "debug.h"

bool debug_log_packet_filter(const Packet *p)
{
    if (p == NULL) return true;

    return true;
}

void debug_log(bool print_ts, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    g_io_callback->debug(print_ts, fmt, args);
    va_end(args);
}