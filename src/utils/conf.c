#include "conf.h"
#include "utils/util-debug.h"
#include <errno.h>
#include <inttypes.h>
#include <string.h>

/** Maximum size of a complete domain name. */
#define NODE_NAME_MAX 1024

static ConfNode *root = NULL;

size_t strlcpy(char *dst, const char *src, size_t siz)
{
  register char *d = dst;
  register const char *s = src;
  register size_t n = siz;

  /* Copy as many bytes as will fit */
  if (n != 0 && --n != 0) {
    do {
      if ((*d++ = *s++) == 0)
        break;
    } while (--n != 0);
  }

  /* Not enough room in dst, add NUL and traverse rest of src */
  if (n == 0) {
    if (siz != 0)
      *d = '\0'; /* NUL-terminate dst */
    while (*s++)
      ;
  }

  return(s - src - 1); /* count does not include NUL */
}

ConfNode *ConfGetNode(const char *name)
{
  ConfNode *node = root;
  char node_name[NODE_NAME_MAX];
  char *key;
  char *next;

  if (strlcpy(node_name, name, sizeof(node_name)) >= sizeof(node_name)) {
    SCLogError(SC_ERR_CONF_NAME_TOO_LONG,
               "Configuration name too long: %s", name);
    return NULL;
  }

  key = node_name;
  do {
    if ((next = strchr(key, '.')) != NULL)
      *next++ = '\0';
    node = ConfNodeLookupChild(node, key);
    key = next;
  } while (next != NULL && node != NULL);

  return node;
}

int ConfGet(const char *name, const char **vptr)
{
  ConfNode *node = ConfGetNode(name);
  if (node == NULL) {
    SCLogDebug("failed to lookup configuration parameter '%s'", name);
    return 0;
  }
  else {
    *vptr = node->val;
    return 1;
  }
}

int ConfGetInt(const char *name, intmax_t *val)
{
  const char *strval = NULL;
  intmax_t tmpint;
  char *endptr;

  if (ConfGet(name, &strval) == 0)
    return 0;

  if (strval == NULL) {
    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "malformed integer value "
                                               "for %s: NULL", name);
    return 0;
  }

  errno = 0;
  tmpint = strtoimax(strval, &endptr, 0);
  if (strval[0] == '\0' || *endptr != '\0') {
    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "malformed integer value "
                                               "for %s: '%s'", name, strval);
    return 0;
  }
  if (errno == ERANGE && (tmpint == INTMAX_MAX || tmpint == INTMAX_MIN)) {
    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "integer value for %s out "
                                               "of range: '%s'", name, strval);
    return 0;
  }

  *val = tmpint;
  return 1;
}

ConfNode *ConfNodeLookupChild(const ConfNode *node, const char *name)
{
  ConfNode *child;

  if (node == NULL || name == NULL) {
    return NULL;
  }

  TAILQ_FOREACH(child, &node->head, next) {
    if (child->name != NULL && strcmp(child->name, name) == 0)
      return child;
  }

  return NULL;
}

const char *ConfNodeLookupChildValue(const ConfNode *node, const char *name)
{
  ConfNode *child;

  child = ConfNodeLookupChild(node, name);
  if (child != NULL)
    return child->val;

  return NULL;
}