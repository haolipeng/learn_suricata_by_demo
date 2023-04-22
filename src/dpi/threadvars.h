#ifndef NET_THREAT_DETECT_THREADVARS_H
#define NET_THREAT_DETECT_THREADVARS_H

#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>

#include "packet-queue.h"
#include "tm-queues.h"
#include "utils/util-atomic.h"

#define THV_USE                 BIT_U32(0)  /** thread is in use */
#define THV_INIT_DONE           BIT_U32(1)  /** thread initialization done */
#define THV_PAUSE               BIT_U32(2)  /** signal thread to pause itself */
#define THV_PAUSED              BIT_U32(3)  /** the thread is paused atm */
#define THV_KILL                BIT_U32(4)  /** thread has been asked to cleanup and exit */
#define THV_FAILED              BIT_U32(5)  /** thread has encountered an error and failed */
#define THV_CLOSED              BIT_U32(6)  /** thread done, should be joinable */
#define THV_DEINIT              BIT_U32(7)
#define THV_RUNNING_DONE        BIT_U32(8)

typedef struct ThreadVars_ {
  pthread_t t;
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

  uint8_t inq_id;
  uint8_t outq_id;

  /** local id */
  int id;

  /** incoming queue and handler */
  Tmq *inq;
  struct Packet_ * (*tmqh_in)(struct ThreadVars_ *);

  SC_ATOMIC_DECLARE(uint32_t, flags);

  /** outgoing queue and handler */
  Tmq *outq;
  void *outctx;
  void (*tmqh_out)(struct ThreadVars_ *, struct Packet_ *);

  /** queue for decoders to temporarily store extra packets they
     *  generate. */
  PacketQueueNoLock decode_pq;

  /** Stream packet queue for flow time out injection. Either a pointer to the
     *  workers input queue or to stream_pq_local */
  //struct PacketQueue_ *stream_pq;
  //struct PacketQueue_ *stream_pq_local;

  /** pointer to the next thread */
  struct ThreadVars_ *next;

  /* mutex and condition used by management threads */

  //SCCtrlMutex *ctrl_mutex;
  //SCCtrlCondT *ctrl_cond;

  struct FlowQueue_ *flow_queue;
  bool break_loop;

}ThreadVars;

#endif // NET_THREAT_DETECT_THREADVARS_H
