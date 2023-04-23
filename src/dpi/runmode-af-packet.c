#include <stdio.h>
#include <errno.h>
#include "runmode-af-packet.h"
#include "tm-threads.h"
#include "tm-modules.h"
#include "runmodes.h"

static int RunModeSetLiveCaptureWorkersForDevice(const char *recv_mod_name,
                                                 const char *decode_mod_name, const char *thread_name,
                                                 const char *live_dev,
                                                 unsigned char single_mode)
{
    int threads_count;

    if (single_mode) {
        threads_count = 1;
    } else{
        threads_count = 1;
    }
    /* create the threads */
    for (int thread = 0; thread < threads_count; thread++) {
        char tname[TM_THREAD_NAME_MAX];
        TmModule *tm_module = NULL;
        const char *visual_devname = live_dev;
        if (single_mode) {
            snprintf(tname, sizeof(tname), "%s#01-%s", thread_name, visual_devname);
        } else {
            snprintf(tname, sizeof(tname), "%s#%02d-%s", thread_name,
                     thread+1, visual_devname);
        }
        ThreadVars *tv = TmThreadCreatePacketHandler(tname,
                                                     "packetpool", "packetpool",
                                                     "packetpool", "packetpool",
                                                     "pktacqloop");
        if (tv == NULL) {
            FatalError(SC_ERR_THREAD_CREATE, "TmThreadsCreate failed");
        }

        tm_module = TmModuleGetByName(recv_mod_name);
        if (tm_module == NULL) {
            FatalError(SC_ERR_INVALID_VALUE, "TmModuleGetByName failed for %s", recv_mod_name);
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        tm_module = TmModuleGetByName(decode_mod_name);
        if (tm_module == NULL) {
            FatalError(SC_ERR_INVALID_VALUE, "TmModuleGetByName %s failed", decode_mod_name);
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        tm_module = TmModuleGetByName("FlowWorker");
        if (tm_module == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmModuleGetByName for FlowWorker failed");
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        if (TmThreadSpawn(tv) != TM_ECODE_OK) {
            FatalError(SC_ERR_THREAD_SPAWN, "TmThreadSpawn failed");
        }
    }

    return 0;
}

int RunModeSetLiveCaptureSingle(const char *recv_mod_name,
                                const char *decode_mod_name, const char *thread_name,
                                const char *live_dev)
{
    return RunModeSetLiveCaptureWorkersForDevice(
            recv_mod_name,
            decode_mod_name,
            thread_name,
            live_dev,
            1);
}

int RunModeIdsAFPSingle(void)
{
    int ret;
    const char *live_dev = NULL;

    //TimeModeSetLive();
    const char *thread_name_single = "W";
    ret = RunModeSetLiveCaptureSingle("ReceiveAFP",
                                    "DecodeAFP", thread_name_single,
                                    live_dev);
    if (ret != 0) {
        FatalError(SC_ERR_FATAL, "Unable to start runmode");
    }

    SCLogDebug("RunModeIdsAFPSingle initialised");

    return (0);
}

void RunModeIdsAFPRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "single",
                              "Single threaded af-packet mode",
                              RunModeIdsAFPSingle);

    return;
}