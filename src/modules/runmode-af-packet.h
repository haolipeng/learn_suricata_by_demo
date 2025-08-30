#ifndef NET_THREAT_DETECT_RUNMODE_AF_PACKET_H
#define NET_THREAT_DETECT_RUNMODE_AF_PACKET_H

typedef void *(*ConfigIfaceParserFunc) (const char *);
typedef int (*ConfigIfaceThreadsCountFunc) (void *);

int RunModeIdsAFPSingle(void);
void RunModeIdsAFPRegister(void);

const char *RunModeAFPGetDefaultMode(void);

int RunModeSetLiveCaptureWorkers(ConfigIfaceParserFunc configparser,
    ConfigIfaceThreadsCountFunc ModThreadsCount,
    const char *recv_mod_name,
    const char *decode_mod_name, const char *thread_name,
    const char *live_dev);

#endif //NET_THREAT_DETECT_RUNMODE_AF_PACKET_H
