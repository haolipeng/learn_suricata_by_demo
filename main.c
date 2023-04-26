#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <bits/types/sig_atomic_t.h>

#include "base.h"
#include "dpi/conf-yaml-loader.h"
#include "dpi/runmodes.h"
#include "dpi/source-af-packet.h"
#include "dpi/tm-modules.h"
#include "dpi/tm-queuehandlers.h"
#include "flow/flow-manager.h"
#include "flow/flow-worker.h"
#include "packet.h"
#include "pcap.h"
#include "utils/conf.h"
#include "utils/util-debug.h"
#include "utils/util-device.h"
#include "dpi/main.h"
#include "reassemble/stream-tcp.h"
#include "utils/util-misc.h"

#define DEFAULT_CONF_FILE "/etc/suricata/suricata.yaml"
#define DEFAULT_MAX_PENDING_PACKETS 1024
intmax_t max_pending_packets = DEFAULT_MAX_PENDING_PACKETS;

////////////////////////////全局变量区//////////////////////////////
char *g_pcap_path = NULL;
char* g_in_iface;
char* g_virtual_iface;
int g_threads = 1; //one capture thread per nic = 1

__thread int THREAD_ID;

struct timeval g_now;

/////////////////////////////////////////////////////////////////
volatile sig_atomic_t sigint_count = 0;
volatile sig_atomic_t sighup_count = 0;
volatile sig_atomic_t sigterm_count = 0;
volatile sig_atomic_t sigusr2_count = 0;

/*
 * Flag to indicate if the engine is at the initialization
 * or already processing packets. 3 stages: SURICATA_INIT,
 * SURICATA_RUNTIME and SURICATA_FINALIZE
 */
SC_ATOMIC_DECLARE(unsigned int, engine_stage);

/** suricata engine control flags */
volatile uint8_t suricata_ctl_flags = 0;

/** Suricata instance */
SCInstance suricata;

static void help(const char *prog)
{
    printf("%s:\n", prog);
    printf("  h: help\n");
    printf("  i: specify the physical interface to capture traffic\n");
    printf("  c: specify the virtual interface to capture traffic\n");
    printf("  d: debug flags(none, all, error, packet, session, timer, tcp, parser, log)\n");
    printf("  p: pcap file or directory\n");
}

static void SCInstanceInit(SCInstance *suri, const char *progname)
{
    memset(suri, 0x00, sizeof(*suri));

    suri->progname = progname;
    suri->run_mode = RUNMODE_UNKNOWN;

    memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
    suri->sig_file = NULL;
    suri->sig_file_exclusive = FALSE;
    suri->pid_filename = NULL;
    suri->regex_arg = NULL;

    suri->keyword_info = NULL;
    suri->runmode_custom_mode = NULL;
#ifndef OS_WIN32
    suri->user_name = NULL;
    suri->group_name = NULL;
    suri->do_setuid = FALSE;
    suri->do_setgid = FALSE;
#endif /* OS_WIN32 */
    suri->userid = 0;
    suri->groupid = 0;
    suri->delayed_detect = 0;
    suri->daemon = 0;
    suri->offline = 0;
    suri->verbose = 0;
    /* use -1 as unknown */
    suri->checksum_validation = -1;
}

static int ParseCommandLineAfpacket(SCInstance *suri, const char *in_arg)
{
  if (suri->run_mode == RUNMODE_UNKNOWN) {
      suri->run_mode = RUNMODE_AFP_DEV;
      if (in_arg) {
          LiveRegisterDeviceName(in_arg);
          memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
          strlcpy(suri->pcap_dev, in_arg, sizeof(suri->pcap_dev));
      }
  } else if (suri->run_mode == RUNMODE_AFP_DEV) {
      if (in_arg) {
          LiveRegisterDeviceName(in_arg);
      } else {
          SCLogInfo("Multiple af-packet option without interface on each is useless");
      }
  } else {
    SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode has been specified");
    return TM_ECODE_FAILED;
  }
  return TM_ECODE_OK;
}

void ParseCommandLine(int argc, char **argv,SCInstance *suri){
    int arg = 0;

    while (arg != -1) {
        arg = getopt(argc, argv, "hd:i:v:c:j:p:");

        switch (arg) {
            case -1:
                break;
            case 'd':
                //设置debug等级 info,warning,error
                if (strcasecmp(optarg, "none") == 0) {
                    //TODO:
                }
                break;
            case 'i':
                if(NULL == optarg){
                    SCLogError(SC_ERR_INITIALIZATION, "no option argument for -i");
                }
                g_in_iface = strdup(optarg);//设置网口
                if (ParseCommandLineAfpacket(&suricata, g_in_iface) != TM_ECODE_OK) {
                    SCLogError(SC_ERR_INITIALIZATION, "parse af-packet for -i interface failed!");
                }
                break;
            case 'c':
                suricata.conf_filename = strdup(optarg);
                break;
            case 'v':
                g_virtual_iface = strdup(optarg);
                break;
            case 'p':
                g_pcap_path = optarg;
                break;
            case 'h':
            default:
                //help(argv[0]);
                exit(-2);
        }
    }

    /* save the runmode from the commandline (if any) */
    suri->aux_run_mode = suri->run_mode;
}

void RegisterAllModules(void)
{
    // zero all module storage
    memset(tmm_modules, 0, TMM_SIZE * sizeof(TmModule));

    /* managers */
    TmModuleFlowManagerRegister();
    TmModuleFlowRecyclerRegister();

    /* af-packet */
    TmModuleReceiveAFPRegister();
    TmModuleDecodeAFPRegister();

    /* flow worker */
    TmModuleFlowWorkerRegister();
}

int InitGlobal(void){
    //1.初始化engine state
    SC_ATOMIC_INIT(engine_stage);

    //2.初始化日志系统
    SCLogInitLogModule(NULL);

    //3.初始化util-misc
    ParseSizeInit();

    //4.Register runmodes
    RunModeRegisterRunModes();

    //5.初始化Config系统
    ConfInit();
    return 0;
}

static TmEcode LoadYamlConfig(SCInstance *suri)
{
    if (suri->conf_filename == NULL)
        suri->conf_filename = DEFAULT_CONF_FILE;

    if (ConfYamlLoadFile(suri->conf_filename) != 0) {
        /* Error already displayed. */
        return (TM_ECODE_FAILED);
    }

    return (TM_ECODE_OK);
}

static TmEcode ParseInterfacesList(const int runmode, char *pcap_dev)
{
    /* run the selected runmode */
    if (runmode == RUNMODE_AFP_DEV) {
        /* iface has been set on command line */
        if (strlen(pcap_dev)) {
            if (ConfSetFinal("af-packet.live-interface", pcap_dev) != 1) {
                SCLogError(SC_ERR_INITIALIZATION, "Failed to set af-packet.live-interface");
                return (TM_ECODE_FAILED);
            }
        } else {
            int ret = LiveBuildDeviceList("af-packet");
            if (ret == 0) {
                SCLogError(SC_ERR_INITIALIZATION, "No interface found in config for af-packet");
                return (TM_ECODE_FAILED);
            }
        }
    }

    return (TM_ECODE_OK);
}

void PreRunInit(const int runmode)
{
    //DefragInit();
    FlowInitConfig(FLOW_QUIET);
    StreamTcpInitConfig(STREAM_VERBOSE);
}

int PostConfLoadedSetup(SCInstance *suri)
{
    //if runmod_custom_mode is not null,set it
    if (suri->runmode_custom_mode) {
        ConfSet("runmode", suri->runmode_custom_mode);
    }

    //TODO:need to do
    //if (ConfigGetCaptureValue(suri) != TM_ECODE_OK) {
    //    SCReturnInt(TM_ECODE_FAILED);
    //}

    TmqhSetup();

    RegisterAllModules();

    TmModuleRunInit();

    if(suri->disabled_detect){
        SCLogConfig("dectection engine disabled");
        (void)ConfSetFinal("stream.reassembly.raw", "false");
    }

    //TODO:need to add signal handler
    /*if (InitSignalHandler(suri) != TM_ECODE_OK)
        return TM_ECODE_FAILED;*/

    LiveDeviceFinalize();

    PreRunInit(suri->run_mode);

    return TM_ECODE_OK;
}

static void SCSetStartTime(SCInstance *suri)
{
    memset(&suri->start_time, 0, sizeof(suri->start_time));
    gettimeofday(&suri->start_time, NULL);
}

static void SuricataMainLoop(SCInstance *suri)
{
    while(1) {
        if (sigterm_count || sigint_count) {
            suricata_ctl_flags |= SURICATA_STOP;
        }

        if (suricata_ctl_flags & SURICATA_STOP) {
            SCLogNotice("Signal Received.  Stopping engine.");
            break;
        }

        TmThreadCheckThreadState();

        if (sighup_count > 0) {
            sighup_count--;
        }

        usleep(10* 1000);
    }
}

void EngineDone(void)
{
    suricata_ctl_flags |= SURICATA_DONE;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    //1.Instance init
    SCInstanceInit(&suricata, argv[0]);

    //2.Global init
    InitGlobal();

    //3.解析程序命令行参数
    ParseCommandLine(argc, argv, &suricata);

    //4.Load yaml configuration file if provided.
    if (LoadYamlConfig(&suricata) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    //5.Parser Interface
    if (ParseInterfacesList(suricata.aux_run_mode, suricata.pcap_dev) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    if (PostConfLoadedSetup(&suricata) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    SCSetStartTime(&suricata);

    RunModeDispatch(suricata.run_mode, suricata.runmode_custom_mode);

    if (TmThreadWaitOnThreadInit() == TM_ECODE_FAILED) {
        FatalError(SC_ERR_FATAL, "Engine initialization failed, "
                                 "aborting...");
    }

    SC_ATOMIC_SET(engine_stage, SURICATA_RUNTIME);

    /* Un-pause all the paused threads */
    TmThreadContinueThreads();

    SuricataMainLoop(&suricata);

    /* Update the engine stage/status flag */
    SC_ATOMIC_SET(engine_stage, SURICATA_DEINIT);

    //6.判断不同运行模式
    /*if(NULL != g_pcap_path){
        ret = pcap_run(g_pcap_path);
    }else{
        //Start capture interface
        if(g_in_iface != NULL){
            ret = net_run(g_in_iface);
        }
        if(g_virtual_iface != NULL){
            ret = net_run(g_virtual_iface);
        }
    }*/
    printf("program is almost shutdown");
    return ret;
}