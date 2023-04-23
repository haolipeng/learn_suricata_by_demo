#ifndef NET_THREAT_DETECT_TM_MODULES_H
#define NET_THREAT_DETECT_TM_MODULES_H

#include "tm-threads-common.h"
#include "threadvars.h"

#define TM_FLAG_RECEIVE_TM      0x01
#define TM_FLAG_DECODE_TM       0x02
#define TM_FLAG_STREAM_TM       0x04
#define TM_FLAG_DETECT_TM       0x08
#define TM_FLAG_LOGAPI_TM       0x10
#define TM_FLAG_MANAGEMENT_TM   0x20
#define TM_FLAG_COMMAND_TM      0x40

typedef struct TmModule_ {
    const char *name;

    TmEcode (*ThreadInit)(ThreadVars *, const void *, void **);
    TmEcode (*ThreadDeinit)(ThreadVars *, void *);

    /** the packet processing function */
    TmEcode (*Func)(ThreadVars *, Packet *, void *);

    TmEcode (*PktAcqLoop)(ThreadVars *, void *, void *);

    /** terminates the capture loop in PktAcqLoop */
    TmEcode (*PktAcqBreakLoop)(ThreadVars *, void *);

    TmEcode (*Management)(ThreadVars *, void *);
    uint8_t flags;
} TmModule;

extern TmModule tmm_modules[TMM_SIZE];

//extern function
TmModule *TmModuleGetByName(const char *name);
int TmModuleGetIDForTM(TmModule *tm);

#endif //NET_THREAT_DETECT_TM_MODULES_H
