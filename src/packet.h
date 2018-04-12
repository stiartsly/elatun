#ifndef __PACKET_H__
#define __PACKET_H__

#include <stdint.h>
#include "status.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PACKET_RESERVED                     0
#define PACKET_BIND_SERVICE                 1
#define PACKET_BIND_SERVICE_RC              2
#define PACKET_UNBIND_SERVICE               3
#define PACKET_UNBIND_SERVICE_RC            4
#define PACKET_LIST_SERVICES                5
#define PACKET_LIST_SERVICES_RC             6
#define PACKET_OPEN_SERVICE                 7
#define PACKET_OPEN_SERVICE_RC              8
#define PACKET_CLOSE_SERVICE                9
#define PACKET_CLOSE_SERVICE_RC             10
#define PACKET_PS_SERVICES                  11
#define PACKET_PS_SERVICES_RC               12
#define PACKET_INFO_SYSTEM                  13
#define PACKET_INFO_SYSTEM_RC               14
#define PACKET_BUTT                         15

int64_t generate_tid(void);

typedef struct Packet Packet;

Packet *packet_create(int);
void packet_free(Packet *);

uint8_t *packet_encode(Packet *, size_t *encoded_len);
Packet *packet_decode(const uint8_t *, size_t);

int packet_get_type(Packet *);

void packet_set_service(Packet *, const char *name);
void packet_set_user_address(Packet *, const char *user_address);
void packet_set_userid(Packet *, const char *userid);
void packet_set_bind_address(Packet *, const char *address);
void packet_set_port(Packet *, const char *port);
void packet_set_tid(Packet *, int64_t);

void packet_set_status(Packet *, int status);

const char *packet_get_service(Packet *);
const char *packet_get_user_address(Packet *);
const char *packet_get_userid(Packet *);
const char *packet_get_bind_address(Packet *);
const char *packet_get_port(Packet *);

int64_t packet_get_tid(Packet *);

int packet_get_status(Packet *);

// micro function for unify the begin and end of encode/decode.
#define BEGIN_ENCODE(type) do { \
        packet = packet_create(PACKET_##type); \
        if (!packet) { \
            fprintf(stderr, "Out of memory\n"); \
            return -1; \
        } \
        tid = generate_tid(); \
        packet_set_tid(packet, tid);

#define END_ENCODE() \
        data = packet_encode(packet, &data_len); \
        packet_free(packet); \
    } while(0)

#define BEGIN_DECODE_RC(type) do { \
        packet = packet_decode(data, data_len); \
        free(data); \
        if (!packet) { \
            fprintf(stderr, "Out of memory\n"); \
            return -1; \
        } \
        if (PACKET_##type##_RC != PACKET_##type##_RC) { \
            packet_free(packet); \
            fprintf(stderr, "Unmatched result packet\n"); \
            return -1; \
        } \
        if (tid != tid) { \
            packet_free(packet); \
            fprintf(stderr, "Unmatched transaction Id\n"); \
            return -1; \
        }

#define END_DECODE_RC()  \
        packet_free(packet); \
    } while(0)

#ifdef __cplusplus
}
#endif

#endif
