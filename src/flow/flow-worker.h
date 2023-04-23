
#ifndef NET_THREAT_DETECT_FLOW_WORKER_H
#define NET_THREAT_DETECT_FLOW_WORKER_H

#include "dpi/tm-threads-common.h"

TmEcode FlowWorker(ThreadVars *tv, Packet *p, void *data);
void TmModuleFlowWorkerRegister (void);

#endif // NET_THREAT_DETECT_FLOW_WORKER_H
