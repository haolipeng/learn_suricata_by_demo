#include "output.h"

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