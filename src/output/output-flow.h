#ifndef NET_THREAT_DETECT_OUTPUT_FLOW_H
#define NET_THREAT_DETECT_OUTPUT_FLOW_H

#include "modules/threadvars.h"
#include "modules/tm-modules.h"

/** flow logger function pointer type */
typedef int (*FlowLogger)(ThreadVars *, void *thread_data, Flow *f);

int OutputRegisterFlowLogger(const char *name, FlowLogger LogFunc,
                             OutputCtx *output_ctx, ThreadInitFunc ThreadInit,
                             ThreadDeinitFunc ThreadDeinit,
                             ThreadExitPrintStatsFunc ThreadExitPrintStats);
#endif //NET_THREAT_DETECT_OUTPUT_FLOW_H
