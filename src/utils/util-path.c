#include <string.h>
#include "util-path.h"

int PathIsAbsolute(const char *path)
{
    if (strlen(path) > 1 && path[0] == '/') {
        return 1;
    }

    return 0;
}