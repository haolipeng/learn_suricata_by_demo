#ifndef NET_THREAT_DETECT_TM_THREADS_H
#define NET_THREAT_DETECT_TM_THREADS_H

#include "threadvars.h"

#define TM_QUEUE_NAME_MAX 16
#define TM_THREAD_NAME_MAX 16

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
#endif // NET_THREAT_DETECT_TM_THREADS_H
