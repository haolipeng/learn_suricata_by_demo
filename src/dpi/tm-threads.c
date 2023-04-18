#include "tm-threads.h"
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