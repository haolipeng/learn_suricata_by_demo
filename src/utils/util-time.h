#ifndef __UTIL_TIME_H__
#define __UTIL_TIME_H__

#include <sys/time.h>
#include <stdint.h>

void TimeInit(void);
void TimeDeinit(void);

void TimeSetByThread(const int thread_id, const struct timeval *tv);
void TimeGet(struct timeval *);
void TimeModeSetOffline (void);

/** \brief intialize a 'struct timespec' from a 'struct timeval'. */
#define FROM_TIMEVAL(timev) { .tv_sec = (timev).tv_sec, .tv_nsec = (timev).tv_usec * 1000 }

static inline struct timeval TimevalWithSeconds(const struct timeval *ts, const time_t sec_add)
{
#ifdef timeradd
    struct timeval add = { .tv_sec = sec_add, .tv_usec = 0 };
    struct timeval result;
    timeradd(ts, &add, &result);
    return result;
#else
    const time_t sec = ts->tv_sec + sec_add;
    struct timeval result = { .tv_sec = sec, .tv_usec = ts->tv_usec };
    return result;
#endif
}

/** \brief compare two 'struct timeval' and return if the first is earlier than the second */
static inline bool TimevalEarlier(struct timeval *first, struct timeval *second)
{
    /* from man timercmp on Linux: "Some systems (but not Linux/glibc), have a broken timercmp()
     * implementation, in which CMP of >=, <=, and == do not work; portable applications can instead
     * use ... !timercmp(..., >) */
    return !timercmp(first, second, >);
}

#ifndef timeradd
#define timeradd(a, b, r)                                                                          \
    do {                                                                                           \
        (r)->tv_sec = (a)->tv_sec + (b)->tv_sec;                                                   \
        (r)->tv_usec = (a)->tv_usec + (b)->tv_usec;                                                \
        if ((r)->tv_usec >= 1000000) {                                                             \
            (r)->tv_sec++;                                                                         \
            (r)->tv_usec -= 1000000;                                                               \
        }                                                                                          \
    } while (0)
#endif

#ifdef UNITTESTS
void TimeSet(struct timeval *);
void TimeSetToCurrentTime(void);
void TimeSetIncrementTime(uint32_t);
#endif

bool TimeModeIsReady(void);
void TimeModeSetLive(void);
bool TimeModeIsLive(void);

struct tm *SCLocalTime(time_t timep, struct tm *result);
#endif /* __UTIL_TIME_H__ */

