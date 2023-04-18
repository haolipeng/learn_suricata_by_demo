#ifndef NET_THREAT_DETECT_THREADVARS_H
#define NET_THREAT_DETECT_THREADVARS_H

#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>

#include "packet-queue.h"
#include "util-atomic.h"

typedef struct ThreadVars_ {
  pthread_t t;
  /** function pointer to the function that runs the packet pipeline for
     *  this thread. It is passed directly to pthread_create(), hence the
     *  void pointers in and out. */
  void *(*tm_func)(void *);

  char name[16];
  char *printable_name;
  char *thread_group_name;

  uint8_t thread_setup_flags;

  /** the type of thread as defined in tm-threads.h (TVT_PPT, TVT_MGMT) */
  uint8_t type;

  uint16_t cpu_affinity; /** cpu or core number to set affinity to */
  int thread_priority; /** priority (real time) for this thread. Look at threads.h */


  /** TmModule::flags for each module part of this thread */
  uint8_t tmm_flags;

  uint8_t cap_flags; /**< Flags to indicate the capabilities of all the
                          TmModules resgitered under this thread */

  /** local id */
  int id;


  SC_ATOMIC_DECLARE(uint32_t, flags);

  /** queue for decoders to temporarily store extra packets they
     *  generate. */
  PacketQueueNoLock decode_pq;

  /** Stream packet queue for flow time out injection. Either a pointer to the
     *  workers input queue or to stream_pq_local */
  //struct PacketQueue_ *stream_pq;
  //struct PacketQueue_ *stream_pq_local;

  /* counters */

  /** private counter store: counter updates modify this */
  //StatsPrivateThreadContext perf_private_ctx;

  /** pointer to the next thread */
  struct ThreadVars_ *next;

  /** public counter store: counter syncs update this */
  //StatsPublicThreadContext perf_public_ctx;

  /* mutex and condition used by management threads */

  //SCCtrlMutex *ctrl_mutex;
  //SCCtrlCondT *ctrl_cond;

  struct FlowQueue_ *flow_queue;
  bool break_loop;

} ThreadVars;

#endif // NET_THREAT_DETECT_THREADVARS_H
