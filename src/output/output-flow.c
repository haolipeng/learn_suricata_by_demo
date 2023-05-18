#include "output-flow.h"

typedef struct OutputFlowLogger_ {
    FlowLogger LogFunc;
    OutputCtx *output_ctx;
    struct OutputFlowLogger_ *next;
    const char *name;
    TmEcode (*ThreadInit)(ThreadVars *, const void *, void **);
    TmEcode (*ThreadDeinit)(ThreadVars *, void *);
    void (*ThreadExitPrintStats)(ThreadVars *, void *);
} OutputFlowLogger;

static OutputFlowLogger *list = NULL;

int OutputRegisterFlowLogger(const char *name, FlowLogger LogFunc,
                             OutputCtx *output_ctx, ThreadInitFunc ThreadInit,
                             ThreadDeinitFunc ThreadDeinit,
                             ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    OutputFlowLogger *op = malloc(sizeof(*op));
    if (op == NULL)
        return -1;
    memset(op, 0x00, sizeof(*op));

    op->LogFunc = LogFunc;
    op->output_ctx = output_ctx;
    op->name = name;
    op->ThreadInit = ThreadInit;
    op->ThreadDeinit = ThreadDeinit;
    op->ThreadExitPrintStats = ThreadExitPrintStats;

    if (list == NULL)
        list = op;
    else {
        OutputFlowLogger *t = list;
        while (t->next)
            t = t->next;
        t->next = op;
    }

    SCLogDebug("OutputRegisterFlowLogger happy");
    return 0;
}
