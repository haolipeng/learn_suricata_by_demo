#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "util-ioctl.h"
#include "conf.h"
#include "util-debug.h"

int GetIfaceMTU(const char *pcap_dev)
{
#if defined SIOCGIFMTU
    struct ifreq ifr;
    int fd;

    (void)strlcpy(ifr.ifr_name, pcap_dev, sizeof(ifr.ifr_name));
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return -1;
    }

    if (ioctl(fd, SIOCGIFMTU, (char *)&ifr) < 0) {
        SCLogWarning(SC_ERR_SYSCALL,
                "Failure when trying to get MTU via ioctl for '%s': %s (%d)",
                pcap_dev, strerror(errno), errno);
        close(fd);
        return -1;
    }
    close(fd);
    SCLogInfo("Found an MTU of %d for '%s'", ifr.ifr_mtu,
            pcap_dev);
    return ifr.ifr_mtu;
#else
    /* ioctl is not defined, let's pretend returning 0 is ok */
    return 0;
#endif
}
