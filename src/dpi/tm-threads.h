#ifndef NET_THREAT_DETECT_TM_THREADS_H
#define NET_THREAT_DETECT_TM_THREADS_H

#include "threadvars.h"
#include "utils/util-atomic.h"

#define TM_QUEUE_NAME_MAX 16
#define TM_THREAD_NAME_MAX 16

//typedef TmEcode (*TmSlotFunc)(ThreadVars *, Packet *, void *);

/*typedef struct TmSlot_ {
    *//* function pointers *//*
    union {
        TmSlotFunc SlotFunc;
        TmEcode (*PktAcqLoop)(ThreadVars *, void *, void *);
        TmEcode (*Management)(ThreadVars *, void *);
    };
    *//** linked list of slots, used when a pipeline has multiple slots
     *  in a single thread. *//*
    struct TmSlot_ *slot_next;

    SC_ATOMIC_DECLARE(void *, slot_data);

    TmEcode (*SlotThreadInit)(ThreadVars *, const void *, void **);
    void (*SlotThreadExitPrintStats)(ThreadVars *, void *);
    TmEcode (*SlotThreadDeinit)(ThreadVars *, void *);

    *//* data storage *//*
    const void *slot_initdata;
    *//* store the thread module id *//*

    int tm_id;

}TmSlot;*/

enum {
  TVT_PPT,
  TVT_MGMT,
  TVT_CMD,
  TVT_MAX,
};

extern ThreadVars *tv_root[TVT_MAX];
extern SCMutex tv_root_lock;

int TmThreadsCheckFlag(ThreadVars *, uint32_t);
void TmThreadsSetFlag(ThreadVars *tv, uint32_t flag);
void TmThreadTestThreadUnPaused(ThreadVars *tv);
void TmThreadsUnsetFlag(ThreadVars *, uint32_t);

ThreadVars *TmThreadCreate(const char *name, const char *inq_name, const char *inqh_name,
                           const char *outq_name, const char *outqh_name, const char *slots,
                           void * (*fn_p)(void *), int mucond);
ThreadVars *TmThreadCreatePacketHandler(const char *, const char *, const char *, const char *, const char *,
                                        const char *);

typedef struct TmModule_ TmModule;
void TmSlotSetFuncAppend(ThreadVars *tv, TmModule *tm, const void *data);
#endif // NET_THREAT_DETECT_TM_THREADS_H
