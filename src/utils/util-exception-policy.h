#ifndef __UTIL_EXCEPTION_POLICY_H__
#define __UTIL_EXCEPTION_POLICY_H__

#include "common/packet-define.h"

enum ExceptionPolicy {
    EXCEPTION_POLICY_IGNORE = 0,
    EXCEPTION_POLICY_PASS_PACKET,
    EXCEPTION_POLICY_PASS_FLOW,
    EXCEPTION_POLICY_BYPASS_FLOW,
    EXCEPTION_POLICY_DROP_PACKET,
    EXCEPTION_POLICY_DROP_FLOW,
    EXCEPTION_POLICY_REJECT,
};
enum ExceptionPolicy ExceptionPolicyParse(const char *option, const bool support_flow);

int ExceptionSimulationCommandlineParser(const char *name, const char *arg);

#endif
