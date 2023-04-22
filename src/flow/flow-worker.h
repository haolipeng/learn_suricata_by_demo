
#ifndef NET_THREAT_DETECT_FLOW_WORKER_H
#define NET_THREAT_DETECT_FLOW_WORKER_H

#include "dpi/common.h"
#include "dpi/threadvars.h"
TmEcode FlowWorker(ThreadVars *tv, Packet *p, void *data);

#endif // NET_THREAT_DETECT_FLOW_WORKER_H
