#include "threads.h"
#include "util-debug.h"
#include "modules/tm-threads.h"
#include <stdbool.h>
#include <sys/time.h>

// static SCMutex current_time_mutex = SCMUTEX_INITIALIZER;
static SCSpinlock current_time_spinlock;
static bool live_time_tracking = true;

void TimeInit(void)
{
    SCSpinInit(&current_time_spinlock, 0);

    /* Initialize Time Zone settings. */
    tzset();
}

void TimeDeinit(void)
{
    SCSpinDestroy(&current_time_spinlock);
}

void TimeModeSetLive(void)
{
    live_time_tracking = true;
    SCLogDebug("live time mode enabled");
}

bool TimeModeIsReady(void)
{
    if (live_time_tracking)
        return true;
    return TmThreadsTimeSubsysIsReady();
}

bool TimeModeIsLive(void)
{
    return live_time_tracking;
}

void TimeGet(struct timeval *tv) {
  if (tv == NULL)
    return;

  if(live_time_tracking){
    gettimeofday(tv, NULL);
  }

  SCLogDebug("time we got is %" PRIuMAX " sec, %" PRIuMAX " usec",
             (uintmax_t)tv->tv_sec, (uintmax_t)tv->tv_usec);
}

struct tm *SCLocalTime(time_t timep, struct tm *result)
{
    return localtime_r(&timep, result);
}

void TimeSetByThread(const int thread_id, const struct timeval *tv)
{
    if (live_time_tracking)
        return;

    TmThreadsSetThreadTimestamp(thread_id, tv);
}

void TimeModeSetOffline (void)
{
    live_time_tracking = false;
    SCLogDebug("offline time mode enabled");
}