//
// Created by haolipeng on 12/28/22.
//

#include <pthread.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include "apis.h"
#include "base.h"
#include "debug.h"
#include "dpi/dpi_entry.h"
#include "packet.h"
#include "pcap.h"
#include "utils/util-debug.h"

#define DEFAULT_MAX_PENDING_PACKETS 1024
intmax_t max_pending_packets = DEFAULT_MAX_PENDING_PACKETS;

extern uint32_t g_debug_levels;
io_callback_t g_callback;
io_config_t g_config;

////////////////////////////全局变量区//////////////////////////////
char *g_pcap_path = NULL;
char* g_in_iface;
char* g_virtual_iface;
int g_threads = 1; //one capture thread per nic = 1

__thread int THREAD_ID;
__thread char THREAD_NAME[32];

struct timeval g_now;

static void help(const char *prog)
{
    printf("%s:\n", prog);
    printf("  h: help\n");
    printf("  i: specify the physical interface to capture traffic\n");
    printf("  c: specify the virtual interface to capture traffic\n");
    printf("  d: debug flags(none, all, error, packet, session, timer, tcp, parser, log)\n");
    printf("  p: pcap file or directory\n");
}

void parse_cmd_line(int argc, char *argv[]){
    int arg = 0;

    while (arg != -1) {
        arg = getopt(argc, argv, "hcd:i:j:p:");

        switch (arg) {
            case -1:
                break;
            case 'd':
                //设置debug等级 info,warning,error
                if (strcasecmp(optarg, "none") == 0) {
                    g_debug_levels = 0;
                } else if (optarg[0] == '-') {
                    g_debug_levels &= ~debug_name2level(optarg + 1);
                } else {
                    g_debug_levels |= debug_name2level(optarg);
                }
                break;
            case 'i':
                g_in_iface = strdup(optarg);//设置网口
                g_config.promisc = true;
                break;
            case 'c':
                g_virtual_iface = strdup(optarg);//TODO:抓取虚拟接口
                break;
            case 'p':
                g_pcap_path = optarg;
                g_config.promisc = true;
                break;
            case 'h':
            default:
                help(argv[0]);
                exit(-2);
        }
    }
}

int main(int argc, char *argv[])
{
    //0.初始化g_config全局变量
    memset(&g_config, 0, sizeof(g_config));

    //1.解析程序命令行参数
    parse_cmd_line(argc, argv);

    //2.初始化日志系统
    SCLogInitLogModule(NULL);

    int ret = 0;
    //判断不同运行模式
    if(NULL != g_pcap_path){
        ret = pcap_run(g_pcap_path);
    }else{
        //Start capture interface
        if(g_in_iface != NULL){
            ret = net_run(g_in_iface);
        }
        if(g_virtual_iface != NULL){
            ret = net_run(g_virtual_iface);
        }
    }

    //开启flowManager线程
    //TODO:not finished haolipeng

    return ret;
}