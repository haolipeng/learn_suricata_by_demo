#include "util-exception-policy.h"
#include "util-misc.h"
#include "conf.h"
#include "util-debug.h"

enum ExceptionPolicy ExceptionPolicyParse(const char *option, const bool support_flow)
{
    enum ExceptionPolicy policy = EXCEPTION_POLICY_IGNORE;
    const char *value_str = NULL;
    if ((ConfGet(option, &value_str)) == 1 && value_str != NULL) {
        if (strcmp(value_str, "drop-flow") == 0) {
            policy = EXCEPTION_POLICY_DROP_FLOW;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "pass-flow") == 0) {
            policy = EXCEPTION_POLICY_PASS_FLOW;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "bypass") == 0) {
            policy = EXCEPTION_POLICY_BYPASS_FLOW;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "drop-packet") == 0) {
            policy = EXCEPTION_POLICY_DROP_PACKET;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "pass-packet") == 0) {
            policy = EXCEPTION_POLICY_PASS_PACKET;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "reject") == 0) {
            policy = EXCEPTION_POLICY_REJECT;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "ignore") == 0) { // TODO name?
            policy = EXCEPTION_POLICY_IGNORE;
            SCLogConfig("%s: %s", option, value_str);
        } else {
            FatalErrorOnInit(SC_ERR_INVALID_ARGUMENT,
                    "\"%s\" is not a valid exception policy value. Valid options are drop-flow, "
                    "pass-flow, bypass, drop-packet, pass-packet or ignore.",
                    value_str);
        }

        if (!support_flow) {
            if (policy == EXCEPTION_POLICY_DROP_FLOW || policy == EXCEPTION_POLICY_PASS_FLOW ||
                    policy == EXCEPTION_POLICY_BYPASS_FLOW) {
                SCLogWarning(SC_WARN_COMPATIBILITY,
                        "flow actions not supported for %s, defaulting to \"ignore\"", option);
                policy = EXCEPTION_POLICY_IGNORE;
            }
        }

    } else {
        SCLogConfig("%s: ignore", option);
    }
    return policy;
}

int ExceptionSimulationCommandlineParser(const char *name, const char *arg)
{
    return 0;
}
