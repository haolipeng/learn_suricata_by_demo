#ifndef __UTIL_VAR_H__
#define __UTIL_VAR_H__

#include "queue.h"

enum VarTypes {
    VAR_TYPE_NOT_SET,

    VAR_TYPE_PKT_BIT,
    VAR_TYPE_PKT_INT,
    VAR_TYPE_PKT_VAR,
    VAR_TYPE_PKT_VAR_KV, // key-value

    VAR_TYPE_FLOW_BIT,
    VAR_TYPE_FLOW_INT,
    VAR_TYPE_FLOW_VAR,

    VAR_TYPE_HOST_BIT,
    VAR_TYPE_HOST_INT,
    VAR_TYPE_HOST_VAR,

    VAR_TYPE_IPPAIR_BIT,
    VAR_TYPE_IPPAIR_INT,
    VAR_TYPE_IPPAIR_VAR,
};

typedef struct GenericVar_ {
    uint8_t type;
    uint8_t pad[3];
    uint32_t idx;
    struct GenericVar_ *next;
} GenericVar;

typedef struct XBit_ {
    uint8_t type;       /* type, DETECT_XBITS in this case */
    uint8_t pad[3];
    uint32_t idx;       /* name idx */
    GenericVar *next;
    uint32_t expire;
} XBit;

void XBitFree(XBit *);

// A list of variables we try to resolve while parsing configuration file.
// Helps to detect recursive declarations.
typedef struct ResolvedVariable_ {
    char var_name[256];
    TAILQ_ENTRY(ResolvedVariable_) next;
} ResolvedVariable;

typedef TAILQ_HEAD(, ResolvedVariable_) ResolvedVariablesList;

void GenericVarFree(GenericVar *);
void GenericVarAppend(GenericVar **, GenericVar *);
void GenericVarRemove(GenericVar **, GenericVar *);

int AddVariableToResolveList(ResolvedVariablesList *list, const char *var);
void CleanVariableResolveList(ResolvedVariablesList *var_list);

#endif /* __UTIL_VAR_H__ */

