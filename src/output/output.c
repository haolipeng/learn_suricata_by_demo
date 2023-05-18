#include "output.h"
#include "utils/util-mem.h"

typedef struct RootLogger_ {
    OutputLogFunc LogFunc;
    ThreadInitFunc ThreadInit;
    ThreadDeinitFunc ThreadDeinit;
    ThreadExitPrintStatsFunc ThreadExitPrintStats;
    OutputGetActiveCountFunc ActiveCntFunc;

    TAILQ_ENTRY(RootLogger_) entries;
} RootLogger;

/* List of registered root loggers. These are registered at start up and
 * are independent of configuration. Later we will build a list of active
 * loggers based on configuration. */
static TAILQ_HEAD(, RootLogger_) registered_loggers =
        TAILQ_HEAD_INITIALIZER(registered_loggers);

/* List of active root loggers. This means that at least one logger is enabled
 * for each root logger type in the config. */
static TAILQ_HEAD(, RootLogger_) active_loggers =
        TAILQ_HEAD_INITIALIZER(active_loggers);

typedef struct LoggerThreadStoreNode_ {
    void *thread_data;
    TAILQ_ENTRY(LoggerThreadStoreNode_) entries;
} LoggerThreadStoreNode;

typedef TAILQ_HEAD(LoggerThreadStore_, LoggerThreadStoreNode_) LoggerThreadStore;

/**
 * The list of all registered (known) output modules.
 */
OutputModuleList output_modules = TAILQ_HEAD_INITIALIZER(output_modules);

static void OutputRegisterActiveLogger(RootLogger *reg)
{
    RootLogger *logger = calloc(1, sizeof(*logger));
    if (logger == NULL) {
        FatalError(SC_ERR_MEM_ALLOC, "failed to alloc root logger");
    }
    logger->ThreadInit = reg->ThreadInit;
    logger->ThreadDeinit = reg->ThreadDeinit;
    logger->ThreadExitPrintStats = reg->ThreadExitPrintStats;
    logger->LogFunc = reg->LogFunc;
    logger->ActiveCntFunc = reg->ActiveCntFunc;
    TAILQ_INSERT_TAIL(&active_loggers, logger, entries);
}

void OutputSetupActiveLoggers(void)
{
    RootLogger *logger = TAILQ_FIRST(&registered_loggers);
    while (logger) {
        uint32_t cnt = logger->ActiveCntFunc();
        if (cnt) {
            OutputRegisterActiveLogger(logger);
        }

        logger = TAILQ_NEXT(logger, entries);
    }
}

TmEcode OutputLoggerThreadDeinit(ThreadVars *tv, void *thread_data)
{
    if (thread_data == NULL)
        return TM_ECODE_FAILED;

    LoggerThreadStore *thread_store = (LoggerThreadStore *)thread_data;
    RootLogger *logger = TAILQ_FIRST(&active_loggers);
    LoggerThreadStoreNode *thread_store_node = TAILQ_FIRST(thread_store);
    while (logger && thread_store_node) {
        if (logger->ThreadDeinit != NULL) {
            logger->ThreadDeinit(tv, thread_store_node->thread_data);
        }
        logger = TAILQ_NEXT(logger, entries);
        thread_store_node = TAILQ_NEXT(thread_store_node, entries);
    }

    /* Free the thread store. */
    while ((thread_store_node = TAILQ_FIRST(thread_store)) != NULL) {
        TAILQ_REMOVE(thread_store, thread_store_node, entries);
        SCFree(thread_store_node);
    }
    SCFree(thread_store);

    return TM_ECODE_OK;
}