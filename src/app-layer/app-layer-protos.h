#ifndef __APP_LAYER_PROTOS_H__
#define __APP_LAYER_PROTOS_H__
#include <stdint.h>
#include <stdbool.h>

enum AppProtoEnum {
    ALPROTO_UNKNOWN = 0,
    ALPROTO_HTTP,
    ALPROTO_SMB,
    ALPROTO_DCERPC,
    ALPROTO_HTTP2,

    /* used by the probing parser when alproto detection fails
     * permanently for that particular stream */
    ALPROTO_FAILED,
    /* keep last */
    ALPROTO_MAX,
};
// NOTE: if ALPROTO's get >= 256, update SignatureNonPrefilterStore

/* not using the enum as that is a unsigned int, so 4 bytes */
typedef uint16_t AppProto;

static inline bool AppProtoIsValid(AppProto a)
{
    return ((a > ALPROTO_UNKNOWN && a < ALPROTO_FAILED));
}

extern bool g_config_http1keywords_http2traffic;

// wether a signature AppProto matches a flow (or signature) AppProto
static inline bool AppProtoEquals(AppProto sigproto, AppProto alproto)
{
    if (alproto == ALPROTO_HTTP2 && g_config_http1keywords_http2traffic &&
            sigproto == ALPROTO_HTTP) {
        return true;
    } else if (sigproto == ALPROTO_DCERPC) {
        return (alproto == ALPROTO_DCERPC || alproto == ALPROTO_SMB);
    }
    return (sigproto == alproto);
}

/**
 * \brief Maps the ALPROTO_*, to its string equivalent.
 *
 * \param alproto App layer protocol id.
 *
 * \retval String equivalent for the alproto.
 */
const char *AppProtoToString(AppProto alproto);

/**
 * \brief Maps a string to its ALPROTO_* equivalent.
 *
 * \param String equivalent for the alproto.
 *
 * \retval alproto App layer protocol id, or ALPROTO_UNKNOWN.
 */
AppProto StringToAppProto(const char *proto_name);

#endif /* __APP_LAYER_PROTOS_H__ */
