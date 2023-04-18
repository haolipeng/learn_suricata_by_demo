#ifndef NET_THREAT_DETECT_CONF_H
#define NET_THREAT_DETECT_CONF_H
#include "queue.h"
#include <stddef.h>
#include <stdint.h>

/**
 * Structure of a configuration parameter.
 */
typedef struct ConfNode_ {
  char *name;
  char *val;

  int is_seq;

  /**< Flag that sets this nodes value as final. */
  int final;

  struct ConfNode_ *parent;
  TAILQ_HEAD(, ConfNode_) head;
  TAILQ_ENTRY(ConfNode_) next;
} ConfNode;

ConfNode *ConfGetNode(const char *name);
int ConfGet(const char *name, const char **vptr);
int ConfGetInt(const char *name, intmax_t *val);
ConfNode *ConfNodeLookupChild(const ConfNode *node, const char *key);
const char *ConfNodeLookupChildValue(const ConfNode *node, const char *key);

#endif // NET_THREAT_DETECT_CONF_H
