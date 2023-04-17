#include "flow.h"
#include "flow-private.h"

FlowProtoFreeFunc flow_freefuncs[FLOW_PROTO_MAX];

int FlowClearMemory(Flow* f, uint8_t proto_map)
{
    if (unlikely(f->flags & FLOW_HAS_EXPECTATION)) {
        //AppLayerExpectationClean(f);//TODO:
    }

    /* call the protocol specific free function if we have one */
    if (flow_freefuncs[proto_map].Freefunc != NULL) {
        flow_freefuncs[proto_map].Freefunc(f->protoctx);
    }

    FLOW_RECYCLE(f);

    return 1;
}
