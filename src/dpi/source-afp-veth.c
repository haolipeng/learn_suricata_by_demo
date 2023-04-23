#include "source-afp-veth.h"
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
    //TODO:haolipeng not finished
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