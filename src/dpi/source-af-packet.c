#include "source-af-packet.h"
#include "tm-threads-common.h"
#include "tm-modules.h"

TmEcode ReceiveAFPThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        return TM_ECODE_FAILED;

    *data = (void *)dtv;
    return TM_ECODE_OK;
}

TmEcode ReceiveAFPLoop(ThreadVars *tv, void *data, void *slot)
{
    AFPThreadVars *ptv = (AFPThreadVars *)data;
    struct pollfd fds;
    int r;
    TmSlot *s = (TmSlot *)slot;
    time_t last_dump = 0;
    time_t current_time;
    int (*AFPReadFunc) (AFPThreadVars *);
    uint64_t discarded_pkts = 0;

    ptv->slot = s->slot_next;

    if (ptv->flags & AFP_RING_MODE) {
        if (ptv->flags & AFP_TPACKET_V3) {
            AFPReadFunc = AFPReadFromRingV3;
        } else {
            AFPReadFunc = AFPReadFromRing;
        }
    } else {
        AFPReadFunc = AFPRead;
    }

    if (ptv->afp_state == AFP_STATE_DOWN) {
        /* Wait for our turn, threads before us must have opened the socket */
        while (AFPPeersListWaitTurn(ptv->mpeer)) {
            usleep(1000);
            if (suricata_ctl_flags != 0) {
                break;
            }
        }
        r = AFPCreateSocket(ptv, ptv->iface, 1);
        if (r < 0) {
            switch (-r) {
                case AFP_FATAL_ERROR:
                    SCLogError(SC_ERR_AFP_CREATE, "Couldn't init AF_PACKET socket, fatal error");
                    SCReturnInt(TM_ECODE_FAILED);
                case AFP_RECOVERABLE_ERROR:
                    SCLogWarning(SC_ERR_AFP_CREATE, "Couldn't init AF_PACKET socket, retrying soon");
            }
        }
        AFPPeersListReachedInc();
    }
    if (ptv->afp_state == AFP_STATE_UP) {
        SCLogDebug("Thread %s using socket %d", tv->name, ptv->socket);
        AFPSynchronizeStart(ptv, &discarded_pkts);
        /* let's reset counter as we will start the capture at the
         * next function call */
    }

    fds.fd = ptv->socket;
    fds.events = POLLIN;

    while (1) {
        /* Start by checking the state of our interface */
        if (unlikely(ptv->afp_state == AFP_STATE_DOWN)) {
            int dbreak = 0;

            do {
                usleep(AFP_RECONNECT_TIMEOUT);
                r = AFPTryReopen(ptv);
                fds.fd = ptv->socket;
            } while (r < 0);
            if (dbreak == 1)
                break;
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        PacketPoolWait();

        r = poll(&fds, 1, POLL_TIMEOUT);

        if (suricata_ctl_flags != 0) {
            break;
        }

        if (r > 0 &&
            (fds.revents & (POLLHUP|POLLRDHUP|POLLERR|POLLNVAL))) {
            if (fds.revents & (POLLHUP | POLLRDHUP)) {
                AFPSwitchState(ptv, AFP_STATE_DOWN);
                continue;
            } else if (fds.revents & POLLERR) {
                char c;
                /* Do a recv to get errno */
                if (recv(ptv->socket, &c, sizeof c, MSG_PEEK) != -1)
                    continue; /* what, no error? */
                SCLogError(SC_ERR_AFP_READ,
                           "Error reading data from iface '%s': (%d) %s",
                           ptv->iface, errno, strerror(errno));
                AFPSwitchState(ptv, AFP_STATE_DOWN);
                continue;
            } else if (fds.revents & POLLNVAL) {
                SCLogError(SC_ERR_AFP_READ, "Invalid polling request");
                AFPSwitchState(ptv, AFP_STATE_DOWN);
                continue;
            }
        } else if (r > 0) {
            r = AFPReadFunc(ptv);
            switch (r) {
                case AFP_READ_OK:
                    /* Trigger one dump of stats every second */
                    current_time = time(NULL);
                    if (current_time != last_dump) {
                        AFPDumpCounters(ptv);
                        last_dump = current_time;
                    }
                    break;
                case AFP_READ_FAILURE:
                    /* AFPRead in error: best to reset the socket */
                    SCLogError(SC_ERR_AFP_READ,
                               "AFPRead error reading data from iface '%s': (%d) %s",
                               ptv->iface, errno, strerror(errno));
                    AFPSwitchState(ptv, AFP_STATE_DOWN);
                    continue;
                case AFP_SURI_FAILURE:
                    StatsIncr(ptv->tv, ptv->capture_errors);
                    break;
                case AFP_KERNEL_DROP:
                    AFPDumpCounters(ptv);
                    break;
            }
        } else if (unlikely(r == 0)) {
            /* Trigger one dump of stats every second */
            current_time = time(NULL);
            if (current_time != last_dump) {
                AFPDumpCounters(ptv);
                last_dump = current_time;
            }
            /* poll timed out, lets see handle our timeout path */
            TmThreadsCaptureHandleTimeout(tv, NULL);

        } else if ((r < 0) && (errno != EINTR)) {
            SCLogError(SC_ERR_AFP_READ, "Error reading data from iface '%s': (%d) %s",
                       ptv->iface,
                       errno, strerror(errno));
            AFPSwitchState(ptv, AFP_STATE_DOWN);
            continue;
        }
    }

    return TM_ECODE_OK;
}

TmEcode ReceiveAFPThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    return TM_ECODE_OK;
}

void TmModuleReceiveAFPRegister (void)
{
    tmm_modules[TMM_RECEIVEAFP].name = "ReceiveAFP";
    tmm_modules[TMM_RECEIVEAFP].ThreadInit = ReceiveAFPThreadInit;
    tmm_modules[TMM_RECEIVEAFP].Func = NULL;
    tmm_modules[TMM_RECEIVEAFP].PktAcqLoop = ReceiveAFPLoop;//TODO
    tmm_modules[TMM_RECEIVEAFP].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVEAFP].ThreadDeinit = ReceiveAFPThreadDeinit;
}

TmEcode DecodeAFP(ThreadVars *tv, Packet *p, void *data)
{
    //DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* call the decoder */
    if(LINKTYPE_ETHERNET == p->datalink){
        DecodeEthernet(p, GET_PKT_DATA(p), GET_PKT_LEN(p));
    }

    return TM_ECODE_OK;
}

TmEcode DecodeAFPThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        return TM_ECODE_FAILED;

    *data = (void *)dtv;

    return TM_ECODE_OK;
}

TmEcode DecodeAFPThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    return TM_ECODE_OK;
}

void TmModuleDecodeAFPRegister (void)
{
    tmm_modules[TMM_DECODEAFP].name = "DecodeAFP";
    tmm_modules[TMM_DECODEAFP].ThreadInit = DecodeAFPThreadInit;
    tmm_modules[TMM_DECODEAFP].Func = DecodeAFP;
    tmm_modules[TMM_DECODEAFP].ThreadDeinit = DecodeAFPThreadDeinit;
    tmm_modules[TMM_DECODEAFP].flags = TM_FLAG_DECODE_TM;
}