#include "tm-threads.h"
#include "dpi/tm-queuehandlers.h"
#include "tm-queues.h"
#include "utils/conf.h"
#include "tm-modules.h"
#include <unistd.h>

/* root of the threadvars list */
ThreadVars *tv_root[TVT_MAX] = { NULL };

/* lock to protect tv_root */
SCMutex tv_root_lock = SCMUTEX_INITIALIZER;

int TmThreadsCheckFlag(ThreadVars *tv, uint32_t flag)
{
  return (SC_ATOMIC_GET(tv->flags) & flag) ? 1 : 0;
}

void TmThreadsSetFlag(ThreadVars *tv, uint32_t flag)
{
  SC_ATOMIC_OR(tv->flags, flag);
}

void TmThreadsUnsetFlag(ThreadVars *tv, uint32_t flag)
{
  SC_ATOMIC_AND(tv->flags, ~flag);
}

void TmThreadTestThreadUnPaused(ThreadVars *tv)
{
  while (TmThreadsCheckFlag(tv, THV_PAUSE)) {
    usleep(100);

    if (TmThreadsCheckFlag(tv, THV_KILL))
      break;
  }

  return;
}


ThreadVars *TmThreadCreate(const char *name, const char *inq_name, const char *inqh_name,
                           const char *outq_name, const char *outqh_name, const char *slots,
                           void * (*fn_p)(void *), int mucond)
{
    ThreadVars *tv = NULL;
    Tmq *tmq = NULL;
    Tmqh *tmqh = NULL;

    SCLogDebug("creating thread \"%s\"...", name);

    /* XXX create separate function for this: allocate a thread container */
    tv = malloc(sizeof(ThreadVars));
    if (unlikely(tv == NULL))
        goto error;
    memset(tv, 0, sizeof(ThreadVars));

    SC_ATOMIC_INIT(tv->flags);

    strlcpy(tv->name, name, sizeof(tv->name));

    /* default state for every newly created thread */
    TmThreadsSetFlag(tv, THV_PAUSE);
    TmThreadsSetFlag(tv, THV_USE);

    /* set the incoming queue */
    if (inq_name != NULL && strcmp(inq_name, "packetpool") != 0) {
        SCLogDebug("inq_name \"%s\"", inq_name);

        tmq = TmqGetQueueByName(inq_name);
        if (tmq == NULL) {
            tmq = TmqCreateQueue(inq_name);
            if (tmq == NULL)
                goto error;
        }
        SCLogDebug("tmq %p", tmq);

        tv->inq = tmq;
        tv->inq->reader_cnt++;
        SCLogDebug("tv->inq %p", tv->inq);
    }
    if (inqh_name != NULL) {
        SCLogDebug("inqh_name \"%s\"", inqh_name);

        int id = TmqhNameToID(inqh_name);
        if (id <= 0) {
            goto error;
        }
        tmqh = TmqhGetQueueHandlerByName(inqh_name);
        if (tmqh == NULL)
            goto error;

        tv->tmqh_in = tmqh->InHandler;
        tv->inq_id = (uint8_t)id;
        SCLogDebug("tv->tmqh_in %p", tv->tmqh_in);
    }

    /* set the outgoing queue */
    if (outqh_name != NULL) {
        SCLogDebug("outqh_name \"%s\"", outqh_name);

        int id = TmqhNameToID(outqh_name);
        if (id <= 0) {
            goto error;
        }

        tmqh = TmqhGetQueueHandlerByName(outqh_name);
        if (tmqh == NULL)
            goto error;

        tv->tmqh_out = tmqh->OutHandler;
        tv->outq_id = (uint8_t)id;

        if (outq_name != NULL && strcmp(outq_name, "packetpool") != 0) {
            SCLogDebug("outq_name \"%s\"", outq_name);

            if (tmqh->OutHandlerCtxSetup != NULL) {
                tv->outctx = tmqh->OutHandlerCtxSetup(outq_name);
                if (tv->outctx == NULL)
                    goto error;
                tv->outq = NULL;
            } else {
                tmq = TmqGetQueueByName(outq_name);
                if (tmq == NULL) {
                    tmq = TmqCreateQueue(outq_name);
                    if (tmq == NULL)
                        goto error;
                }
                SCLogDebug("tmq %p", tmq);

                tv->outq = tmq;
                tv->outctx = NULL;
                tv->outq->writer_cnt++;
            }
        }
    }

    /*if (TmThreadSetSlots(tv, slots, fn_p) != TM_ECODE_OK) {
        goto error;
    }*/

    return tv;

error:
    SCLogError(SC_ERR_THREAD_CREATE, "failed to setup a thread");

    if (tv != NULL)
        free(tv);
    return NULL;
}

ThreadVars *TmThreadCreatePacketHandler(const char *name, const char *inq_name,
                                        const char *inqh_name, const char *outq_name,
                                        const char *outqh_name, const char *slots)
{
  ThreadVars *tv = NULL;

  tv = TmThreadCreate(name, inq_name, inqh_name, outq_name, outqh_name,
                      slots, NULL, 0);

  if (tv != NULL) {
    tv->type = TVT_PPT;
    //tv->id = TmThreadsRegisterThread(tv, tv->type);//not need
  }


  return tv;
}

#if 0
void TmSlotSetFuncAppend(ThreadVars *tv, TmModule *tm, const void *data)
{
    TmSlot *slot = malloc(sizeof(TmSlot));
    if (unlikely(slot == NULL))
        return;
    memset(slot, 0, sizeof(TmSlot));
    SC_ATOMIC_INITPTR(slot->slot_data);
    slot->SlotThreadInit = tm->ThreadInit;
    slot->slot_initdata = data;
    if (tm->Func) {
        slot->SlotFunc = tm->Func;
    } else if (tm->PktAcqLoop) {
        slot->PktAcqLoop = tm->PktAcqLoop;
        if (tm->PktAcqBreakLoop) {
            tv->break_loop = true;
        }
    } else if (tm->Management) {
        slot->Management = tm->Management;
    }
    slot->SlotThreadDeinit = tm->ThreadDeinit;
    /* we don't have to check for the return value "-1".  We wouldn't have
     * received a TM as arg, if it didn't exist */
    slot->tm_id = TmModuleGetIDForTM(tm);

    tv->tmm_flags |= tm->flags;

    if (tv->tm_slots == NULL) {
        tv->tm_slots = slot;
    } else {
        TmSlot *a = (TmSlot *)tv->tm_slots, *b = NULL;

        /* get the last slot */
        for ( ; a != NULL; a = a->slot_next) {
            b = a;
        }
        /* append the new slot */
        if (b != NULL) {
            b->slot_next = slot;
        }
    }
    return;
}
#endif