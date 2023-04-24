#include "runmodes.h"
#include "base.h"
#include "utils/util-debug.h"
#include "runmode-af-packet.h"
#include "utils/conf.h"
#include "flow/flow-manager.h"
#include "runmode-pcap-file.h"
#include "utils/util-mem.h"

typedef struct RunMode_ {
    /* the runmode type */
    enum RunModes runmode;
    const char *name;
    const char *description;
    /* runmode function */
    int (*RunModeFunc)(void);
} RunMode;

typedef struct RunModes_ {
    int cnt;
    RunMode *runmodes;
} RunModes;

static RunModes runmodes[RUNMODE_USER_MAX];
static char *active_runmode;

void RunModeRegisterNewRunMode(enum RunModes runmode,
                               const char *name,
                               const char *description,
                               int (*RunModeFunc)(void))
{
    void *ptmp = realloc(runmodes[runmode].runmodes,
                           (runmodes[runmode].cnt + 1) * sizeof(RunMode));
    if (ptmp == NULL) {
        free(runmodes[runmode].runmodes);
        runmodes[runmode].runmodes = NULL;
        exit(EXIT_FAILURE);
    }
    runmodes[runmode].runmodes = ptmp;

    RunMode *mode = &runmodes[runmode].runmodes[runmodes[runmode].cnt];
    runmodes[runmode].cnt++;
    memset(mode, 0x00, sizeof(*mode));

    mode->runmode = runmode;
    mode->name = strdup(name);
    if (unlikely(mode->name == NULL)) {
        FatalError(SC_ERR_MEM_ALLOC, "Failed to allocate string");
    }
    mode->description = strdup(description);
    if (unlikely(mode->description == NULL)) {
        FatalError(SC_ERR_MEM_ALLOC, "Failed to allocate string");
    }
    mode->RunModeFunc = RunModeFunc;

    return;
}

void RunModeRegisterRunModes(void)
{
    memset(runmodes, 0, sizeof(runmodes));

    RunModeFilePcapRegister();
    RunModeIdsAFPRegister();
    return;
}

char *RunmodeGetActive(void)
{
    return active_runmode;
}

static RunMode *RunModeGetCustomMode(enum RunModes runmode, const char *custom_mode)
{
    if (runmode < RUNMODE_USER_MAX) {
        for (int i = 0; i < runmodes[runmode].cnt; i++) {
            if (strcmp(runmodes[runmode].runmodes[i].name, custom_mode) == 0)
                return &runmodes[runmode].runmodes[i];
        }
    }
    return NULL;
}

static const char *RunModeTranslateModeToName(int runmode)
{
    switch (runmode) {
        case RUNMODE_PCAP_DEV:
            return "PCAP_DEV";
        case RUNMODE_PCAP_FILE:
            return "PCAP_FILE";
        case RUNMODE_AFP_DEV:
            return "AF_PACKET_DEV";
        default:
            FatalError(SC_ERR_UNKNOWN_RUN_MODE, "Unknown runtime mode. Aborting");
    }
}

void RunModeDispatch(int runmode, const char *custom_mode)
{
    char *local_custom_mode = NULL;

    if (custom_mode == NULL) {
        const char *val = NULL;
        if (ConfGet("runmode", &val) != 1) {
            custom_mode = NULL;
        } else {
            custom_mode = val;
        }
    }

    if (custom_mode == NULL || strcmp(custom_mode, "auto") == 0) {
        switch (runmode) {
            case RUNMODE_PCAP_FILE:
                custom_mode = RunModeFilePcapGetDefaultMode();
                break;
            case RUNMODE_AFP_DEV:
                custom_mode = RunModeAFPGetDefaultMode();
                break;
            default:
                FatalError(SC_ERR_FATAL, "Unknown runtime mode. Aborting");
        }
    } else { /* if (custom_mode == NULL) */
        /* Add compability with old 'worker' name */
        if (!strcmp("worker", custom_mode)) {
            SCLogWarning(SC_ERR_RUNMODE, "'worker' mode have been renamed "
                                         "to 'workers', please modify your setup.");
            local_custom_mode = SCStrdup("workers");
            if (unlikely(local_custom_mode == NULL)) {
                FatalError(SC_ERR_FATAL, "Unable to dup custom mode");
            }
            custom_mode = local_custom_mode;
        }
    }

    RunMode *mode = RunModeGetCustomMode(runmode, custom_mode);
    if (mode == NULL) {
        SCLogError(SC_ERR_RUNMODE, "The custom type \"%s\" doesn't exist "
                                   "for this runmode type \"%s\".  Please use --list-runmodes to "
                                   "see available custom types for this runmode",
                   custom_mode, RunModeTranslateModeToName(runmode));
        exit(EXIT_FAILURE);
    }

    /* Export the custom mode */
    if (active_runmode) {
        SCFree(active_runmode);
    }
    active_runmode = SCStrdup(custom_mode);
    if (unlikely(active_runmode == NULL)) {
        FatalError(SC_ERR_FATAL, "Unable to dup active mode");
    }

    /*if (strcasecmp(active_runmode, "autofp") == 0) {
        TmqhFlowPrintAutofpHandler();
    }*/

    mode->RunModeFunc();

    if (local_custom_mode != NULL)
        SCFree(local_custom_mode);

    /* Check if the alloted queues have at least 1 reader and writer */
    //TmValidateQueueState();

    if (runmode != RUNMODE_UNIX_SOCKET) {
        /* spawn management threads */
        FlowManagerThreadSpawn();
        FlowRecyclerThreadSpawn();
    }
}
