#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <time.h>

#include "cmd_generated.h"
#include "packet.h"

#pragma pack(push, 1)

struct Packet {
    int type;
    uint8_t padding[0];
};

struct ResultPacket {
    int type;
    int64_t tid;
    int status;
};

struct BindPacket {
    int type;
    int64_t tid;
    const char *userid;
    const char *service;
    const char *bind_address;
    const char *port;
};

struct UnbindPacket {
    int type;
    int64_t tid;
    const char *userid;
    const char *service;
};

struct ListPacket {
    int type;
    int64_t tid;
    const char *userid;
    const char *service;
};

struct OpenPacket {
    int type;
    int64_t tid;
    const char *userid;
    const char *user_address;
    const char *service;
    const char *bind_address;
    const char *port;
};

struct ClosePacket {
    int type;
    int64_t tid;
    const char *userid;
    const char *service;
};

struct PsPacket {
    int type;
    int64_t tid;
    const char *userid;
    const char *service;
};

#pragma pack(pop)

#define pktbind     pkt.u.pkt_bind
#define pktunbind   pkt.u.pkt_unbind
#define pktlist     pkt.u.pkt_list
#define pktopen     pkt.u.pkt_open
#define pktclose    pkt.u.pkt_close
#define pktps       pkt.u.pkt_ps
#define pktrc       pkt.u.pkt_rc

#define tblbind     tbl.u.tbl_bind
#define tblunbind   tbl.u.tbl_unbind
#define tbllist     tbl.u.tbl_list
#define tblopen     tbl.u.tbl_open
#define tblclose    tbl.u.tbl_close
#define tblps       tbl.u.tbl_ps
#define tblrc       tbl.u.tbl_rc

struct cmd_packet_t {
    union {
        struct Packet               *pkt;
        struct BindPacket           *pkt_bind;
        struct UnbindPacket         *pkt_unbind;
        struct ListPacket           *pkt_list;
        struct OpenPacket           *pkt_open;
        struct ClosePacket          *pkt_close;
        struct PsPacket             *pkt_ps;
        struct ResultPacket         *pkt_rc;
    } u;
};

struct cmd_table_t {
    union {
        cmd_bind_service_table_t    tbl_bind;
        cmd_unbind_service_table_t  tbl_unbind;
        cmd_list_services_table_t   tbl_list;
        cmd_open_service_table_t    tbl_open;
        cmd_close_service_table_t   tbl_close;
        cmd_ps_services_table_t     tbl_ps;
        cmd_result_table_t          tbl_rc;
    } u;
};

int64_t generate_tid(void)
{
    int64_t tid;

    do {
        tid = time(NULL);
        tid += rand();
    } while (tid == 0);

    return tid;
}

Packet *packet_create(int type)
{
    Packet *packet;
    size_t len;

    switch(type) {
    case PACKET_BIND_SERVICE:
        len = sizeof(struct BindPacket);
        break;
    case PACKET_UNBIND_SERVICE:
        len = sizeof(struct UnbindPacket);
        break;
    case PACKET_LIST_SERVICES:
        len = sizeof(struct ListPacket);
        break;
    case PACKET_OPEN_SERVICE:
        len = sizeof(struct OpenPacket);
        break;
    case PACKET_CLOSE_SERVICE:
        len = sizeof(struct ClosePacket);
        break;
    case PACKET_PS_SERVICES:
        len = sizeof(struct PsPacket);
        break;
    case PACKET_BIND_SERVICE_RC:
    case PACKET_UNBIND_SERVICE_RC:
    case PACKET_LIST_SERVICES_RC:
    case PACKET_OPEN_SERVICE_RC:
    case PACKET_CLOSE_SERVICE_RC:
    case PACKET_PS_SERVICES_RC:
        len = sizeof(struct ResultPacket);
        break;
    default:
        assert(0);
        break;
    }

    packet = (Packet *)calloc(1, len);
    if (!packet)
        return NULL;

    packet->type = type;
    return packet;
}

void packet_free(Packet *pkt)
{
    if (pkt)
        free(pkt);
}

int packet_get_type(Packet *pkt)
{
    assert(pkt);
    return pkt->type;
}

const char *packet_get_userid(Packet *packet)
{
    struct cmd_packet_t pkt;
    const char *userid;
    assert(packet);

    pkt.u.pkt = packet;

    switch(packet->type) {
    case PACKET_BIND_SERVICE:
        userid = pktbind->userid;
        break;
    case PACKET_UNBIND_SERVICE:
        userid = pktunbind->userid;
        break;
    case PACKET_LIST_SERVICES:
        userid = pktlist->userid;
        break;
    case PACKET_OPEN_SERVICE:
        userid = pktopen->userid;
        break;
    case PACKET_CLOSE_SERVICE:
        userid = pktclose->userid;
        break;
    case PACKET_PS_SERVICES:
        userid = pktps->userid;
        break;
    default:
        assert(0);
        break;
    }
    return userid;
}

const char *packet_get_service(Packet *packet)
{
    struct cmd_packet_t pkt;
    const char *service;
    assert(packet);

    pkt.u.pkt = packet;

    switch(packet->type) {
    case PACKET_BIND_SERVICE:
        service = pktbind->service;
        break;
    case PACKET_UNBIND_SERVICE:
        service = pktunbind->service;
        break;
    case PACKET_LIST_SERVICES:
        service = pktlist->service;
        break;
    case PACKET_OPEN_SERVICE:
        service = pktopen->service;
        break;
    case PACKET_CLOSE_SERVICE:
        service = pktclose->service;
        break;
    case PACKET_PS_SERVICES:
        service = pktps->service;
        break;
    default:
        assert(0);
        break;
    }

    return service;
}

const char *packet_get_user_address(Packet *packet)
{
    struct cmd_packet_t pkt;
    const char *user_address;
    assert(packet);

    pkt.u.pkt = packet;

    switch(packet->type) {
    case PACKET_OPEN_SERVICE:
        user_address = pktopen->user_address;
        break;
    default:
        assert(0);
        break;
    }

    return user_address;
}

const char *packet_get_bind_address(Packet *packet)
{
    struct cmd_packet_t pkt;
    const char *bind_address;
    assert(packet);

    pkt.u.pkt = packet;

    switch(packet->type) {
    case PACKET_BIND_SERVICE:
        bind_address = pktbind->bind_address;
        break;
    case PACKET_OPEN_SERVICE:
        bind_address = pktopen->bind_address;
        break;
    default:
        assert(0);
        break;
    }

    return bind_address;
}

const char *packet_get_port(Packet *packet)
{
    struct cmd_packet_t pkt;
    const char *port;
    assert(packet);

    pkt.u.pkt = packet;

    switch(packet->type) {
    case PACKET_BIND_SERVICE:
        port = pktbind->port;
        break;
    case PACKET_OPEN_SERVICE:
        port = pktopen->port;
        break;
    default:
        assert(0);
        break;
    }

    return port;
}

int64_t packet_get_tid(Packet *packet)
{
    struct cmd_packet_t pkt;
    int64_t tid;
    assert(packet);

    pkt.u.pkt = packet;

    switch(packet->type) {
    case PACKET_BIND_SERVICE:
        tid = pktbind->tid;
        break;
    case PACKET_UNBIND_SERVICE:
        tid = pktunbind->tid;
        break;
    case PACKET_LIST_SERVICES:
        tid = pktlist->tid;
        break;
    case PACKET_OPEN_SERVICE:
        tid = pktopen->tid;
        break;
    case PACKET_CLOSE_SERVICE:
        tid = pktclose->tid;
        break;
    case PACKET_PS_SERVICES:
        tid = pktps->tid;
        break;
    case PACKET_BIND_SERVICE_RC:
    case PACKET_UNBIND_SERVICE_RC:
    case PACKET_LIST_SERVICES_RC:
    case PACKET_OPEN_SERVICE_RC:
    case PACKET_CLOSE_SERVICE_RC:
    case PACKET_PS_SERVICES_RC:
        tid = pktrc->tid;
        break;
    default:
        assert(0);
        break;
    }

    return tid;
}

int packet_get_status(Packet *packet)
{
    struct cmd_packet_t pkt;
    int status;
    assert(packet);

    pkt.u.pkt = packet;

    switch(packet->type) {
    case PACKET_BIND_SERVICE_RC:
    case PACKET_UNBIND_SERVICE_RC:
    case PACKET_LIST_SERVICES_RC:
    case PACKET_OPEN_SERVICE_RC:
    case PACKET_CLOSE_SERVICE_RC:
    case PACKET_PS_SERVICES_RC:
        status = pktrc->status;
        break;
    default:
        assert(0);
        break;
    }

    return status;
}

void packet_set_userid(Packet *packet, const char *userid)
{
    struct cmd_packet_t pkt;
    assert(packet);
    assert(userid);

    pkt.u.pkt = packet;

    switch(packet->type) {
    case PACKET_BIND_SERVICE:
        pktbind->userid = userid;
        break;
    case PACKET_UNBIND_SERVICE:
        pktunbind->userid = userid;
        break;
    case PACKET_LIST_SERVICES:
        pktlist->userid = userid;
        break;
    case PACKET_OPEN_SERVICE:
        pktopen->userid = userid;
        break;
    case PACKET_CLOSE_SERVICE:
        pktclose->userid = userid;
        break;
    case PACKET_PS_SERVICES:
        pktps->userid = userid;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_service(Packet *packet, const char *service)
{
    struct cmd_packet_t pkt;
    assert(packet);
    assert(service);

    pkt.u.pkt = packet;

    switch(packet->type) {
    case PACKET_BIND_SERVICE:
        pktbind->service = service;
        break;
    case PACKET_UNBIND_SERVICE:
        pktunbind->service = service;
        break;
    case PACKET_LIST_SERVICES:
        pktlist->service = service;
        break;
    case PACKET_OPEN_SERVICE:
        pktopen->service = service;
        break;
    case PACKET_CLOSE_SERVICE:
        pktclose->service = service;
        break;
    case PACKET_PS_SERVICES:
        pktps->service = service;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_user_address(Packet *packet, const char *user_address)
{
    struct cmd_packet_t pkt;
    assert(packet);
    assert(user_address);

    pkt.u.pkt = packet;

    switch(packet->type) {
    case PACKET_OPEN_SERVICE:
        pktopen->user_address = user_address;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_bind_address(Packet *packet, const char *bind_address)
{
    struct cmd_packet_t pkt;
    assert(packet);
    assert(bind_address);

    pkt.u.pkt = packet;

    switch(packet->type) {
    case PACKET_BIND_SERVICE:
        pktbind->bind_address = bind_address;
        break;
    case PACKET_OPEN_SERVICE:
        pktopen->bind_address = bind_address;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_port(Packet *packet, const char *port)
{
    struct cmd_packet_t pkt;
    assert(packet);
    assert(port);

    pkt.u.pkt = packet;

    switch(packet->type) {
    case PACKET_BIND_SERVICE:
        pktbind->port = port;
        break;
    case PACKET_OPEN_SERVICE:
        pktopen->port = port;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_tid(Packet *packet, int64_t tid)
{
    struct cmd_packet_t pkt;
    assert(packet);

    pkt.u.pkt = packet;

    switch(packet->type) {
    case PACKET_BIND_SERVICE:
        pktbind->tid = tid;
        break;
    case PACKET_UNBIND_SERVICE:
        pktunbind->tid = tid;
        break;
    case PACKET_LIST_SERVICES:
        pktlist->tid = tid;
        break;
    case PACKET_OPEN_SERVICE:
        pktopen->tid = tid;
        break;
    case PACKET_CLOSE_SERVICE:
        pktclose->tid = tid;
        break;
    case PACKET_PS_SERVICES:
        pktps->tid = tid;
        break;
    case PACKET_BIND_SERVICE_RC:
    case PACKET_UNBIND_SERVICE_RC:
    case PACKET_LIST_SERVICES_RC:
    case PACKET_OPEN_SERVICE_RC:
    case PACKET_CLOSE_SERVICE_RC:
    case PACKET_PS_SERVICES_RC:
        pktrc->tid = tid;
        break;
    default:
        assert(0);
        break;
    }
}

void packet_set_status(Packet *packet, int status)
{
    struct cmd_packet_t pkt;
    assert(packet);

    pkt.u.pkt = packet;

    switch(packet->type) {
    case PACKET_BIND_SERVICE_RC:
    case PACKET_UNBIND_SERVICE_RC:
    case PACKET_LIST_SERVICES_RC:
    case PACKET_OPEN_SERVICE_RC:
    case PACKET_CLOSE_SERVICE_RC:
    case PACKET_PS_SERVICES_RC:
        pktrc->status = status;
        break;
    default:
        assert(0);
        break;
    }
}

uint8_t *packet_encode(Packet *packet, size_t *encoded_len)
{
    struct cmd_packet_t pkt;
    flatcc_builder_t builder;
    flatcc_builder_ref_t str;
    flatbuffers_ref_t ref;
    cmd_anybody_union_ref_t body;
    uint8_t *encoded_data;

    pkt.u.pkt = packet;
    flatcc_builder_init(&builder);

    switch(packet->type) {
    case PACKET_BIND_SERVICE:
        cmd_bind_service_start(&builder);
        cmd_bind_service_tid_add(&builder, pktbind->tid);
        str = flatcc_builder_create_string_str(&builder, pktbind->userid);
        cmd_bind_service_userid_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktbind->service);
        cmd_bind_service_service_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktbind->port);
        cmd_bind_service_port_add(&builder, str);
        if (pktbind->bind_address) {
            str = flatcc_builder_create_string_str(&builder, pktbind->bind_address);
            cmd_bind_service_bind_address_add(&builder, str);
        }
        ref = cmd_bind_service_end(&builder);
        break;

    case PACKET_UNBIND_SERVICE:
        cmd_unbind_service_start(&builder);
        cmd_unbind_service_tid_add(&builder, pktunbind->tid);
        str = flatcc_builder_create_string_str(&builder, pktunbind->userid);
        cmd_unbind_service_userid_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktunbind->service);
        cmd_unbind_service_service_add(&builder, str);
        ref = cmd_unbind_service_end(&builder);
        break;

    case PACKET_LIST_SERVICES:
        cmd_list_services_start(&builder);
        cmd_list_services_tid_add(&builder, pktlist->tid);
        str = flatcc_builder_create_string_str(&builder, pktlist->userid);
        cmd_list_services_userid_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktlist->service);
        cmd_list_services_service_add(&builder, str);
        ref = cmd_list_services_end(&builder);
        break;

    case PACKET_OPEN_SERVICE:
        cmd_open_service_start(&builder);
        cmd_open_service_tid_add(&builder, pktopen->tid);
        str = flatcc_builder_create_string_str(&builder, pktopen->user_address);
        cmd_open_service_user_address_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktopen->userid);
        cmd_open_service_userid_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktopen->service);
        cmd_open_service_service_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktopen->port);
        cmd_open_service_port_add(&builder, str);
        if (pktopen->bind_address) {
            str = flatcc_builder_create_string_str(&builder, pktopen->bind_address);
            cmd_open_service_bind_address_add(&builder, str);
        }
        ref = cmd_open_service_end(&builder);
        break;

    case PACKET_CLOSE_SERVICE:
        cmd_close_service_start(&builder);
        cmd_close_service_tid_add(&builder, pktclose->tid);
        str = flatcc_builder_create_string_str(&builder, pktclose->userid);
        cmd_close_service_userid_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktclose->service);
        cmd_close_service_service_add(&builder, str);
        ref = cmd_close_service_end(&builder);
        break;

    case PACKET_PS_SERVICES:
        cmd_ps_services_start(&builder);
        cmd_ps_services_tid_add(&builder, pktps->tid);
        str = flatcc_builder_create_string_str(&builder, pktps->userid);
        cmd_ps_services_userid_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktps->service);
        cmd_ps_services_service_add(&builder, str);
        ref = cmd_close_service_end(&builder);
        break;

    case PACKET_BIND_SERVICE_RC:
    case PACKET_UNBIND_SERVICE_RC:
    case PACKET_LIST_SERVICES_RC:
    case PACKET_OPEN_SERVICE_RC:
    case PACKET_CLOSE_SERVICE_RC:
    case PACKET_PS_SERVICES_RC:
        cmd_result_start(&builder);
        cmd_result_tid_add(&builder, pktrc->tid);
        cmd_result_status_add(&builder, pktrc->status);
        ref = cmd_result_end(&builder);
        break;

    default:
        assert(0);
        break;
    }

    if (!ref) {
        flatcc_builder_clear(&builder);
        return NULL;
    }

    switch(packet->type) {
    case PACKET_BIND_SERVICE:
        body = cmd_anybody_as_bind_service(ref);
        break;
    case PACKET_UNBIND_SERVICE:
        body = cmd_anybody_as_unbind_service(ref);
        break;
    case PACKET_LIST_SERVICES:
        body = cmd_anybody_as_list_services(ref);
        break;
    case PACKET_OPEN_SERVICE:
        body = cmd_anybody_as_open_service(ref);
        break;
    case PACKET_CLOSE_SERVICE:
        body = cmd_anybody_as_close_service(ref);
        break;
    case PACKET_PS_SERVICES:
        body = cmd_anybody_as_ps_services(ref);
        break;
    case PACKET_BIND_SERVICE_RC:
    case PACKET_UNBIND_SERVICE_RC:
    case PACKET_LIST_SERVICES_RC:
    case PACKET_OPEN_SERVICE_RC:
    case PACKET_CLOSE_SERVICE_RC:
    case PACKET_PS_SERVICES_RC:
        body = cmd_anybody_as_result(ref);
        break;
    default:
        assert(0);
        break;
    }

    cmd_packet_start_as_root(&builder);
    cmd_packet_type_add(&builder, packet->type);
    cmd_packet_body_add(&builder, body);
    if (!cmd_packet_end_as_root(&builder)) {
        flatcc_builder_clear(&builder);
        return NULL;
    }

    encoded_data = flatcc_builder_finalize_buffer(&builder, encoded_len);
    flatcc_builder_clear(&builder);

    return encoded_data;
}

Packet *packet_decode(const uint8_t *data, size_t len)
{
    Packet *packet;
    struct cmd_packet_t pkt;
    struct cmd_table_t  tbl;
    cmd_packet_table_t table;
    int type;

    table = cmd_packet_as_root(data);
    if (!table)
        return NULL;

    type = cmd_packet_type(table);
    switch(type) {
    case PACKET_BIND_SERVICE:
    case PACKET_BIND_SERVICE_RC:
    case PACKET_UNBIND_SERVICE:
    case PACKET_UNBIND_SERVICE_RC:
    case PACKET_LIST_SERVICES:
    case PACKET_LIST_SERVICES_RC:
    case PACKET_OPEN_SERVICE:
    case PACKET_OPEN_SERVICE_RC:
    case PACKET_CLOSE_SERVICE:
    case PACKET_CLOSE_SERVICE_RC:
    case PACKET_PS_SERVICES:
    case PACKET_PS_SERVICES_RC:
        break;
    default:
        //TODO: clean resource for 'packet'; (how ?)
        return NULL;
    }

    packet = packet_create(type);
    if (!packet)
        return NULL;

    pkt.u.pkt = packet;

    if (!cmd_packet_body_is_present(table)) {
        packet_free(packet);
        return NULL;
    }

    switch (type) {
    case PACKET_BIND_SERVICE:
        tblbind = cmd_packet_body(table);
        pktbind->tid = cmd_bind_service_tid(tblbind);
        pktbind->userid = cmd_bind_service_userid(tblbind);
        pktbind->service = cmd_bind_service_service(tblbind);
        pktbind->port = cmd_bind_service_port(tblbind);
        if (cmd_bind_service_bind_address_is_present(tblbind))
            pktbind->bind_address = cmd_bind_service_bind_address(tblbind);
        break;

    case PACKET_UNBIND_SERVICE:
        tblunbind = cmd_packet_body(table);
        pktunbind->tid = cmd_unbind_service_tid(tblunbind);
        pktunbind->userid = cmd_unbind_service_userid(tblunbind);
        pktunbind->service = cmd_unbind_service_service(tblunbind);
        break;

    case PACKET_LIST_SERVICES:
        tbllist = cmd_packet_body(table);
        pktlist->tid = cmd_list_services_tid(tbllist);
        pktlist->userid = cmd_list_services_userid(tbllist);
        pktlist->service = cmd_list_services_service(tbllist);

        break;

    case PACKET_OPEN_SERVICE:
        tblopen = cmd_packet_body(table);
        pktopen->tid = cmd_open_service_tid(tblopen);
        pktopen->userid = cmd_open_service_userid(tblopen);
        pktopen->user_address = cmd_open_service_user_address(tblopen);
        pktopen->service = cmd_open_service_service(tblopen);
        pktopen->port = cmd_open_service_port(tblopen);
        if (cmd_open_service_bind_address_is_present(tblopen))
            pktopen->bind_address = cmd_open_service_bind_address(tblopen);
        break;

    case PACKET_CLOSE_SERVICE:
        tblclose = cmd_packet_body(table);
        pktclose->tid = cmd_close_service_tid(tblclose);
        pktclose->userid = cmd_close_service_userid(tblclose);
        pktclose->service = cmd_close_service_service(tblclose);
        break;

    case PACKET_PS_SERVICES:
        tblps = cmd_packet_body(table);
        pktps->tid = cmd_ps_services_tid(tblps);
        pktps->userid = cmd_ps_services_userid(tblps);


    case PACKET_BIND_SERVICE_RC:
    case PACKET_UNBIND_SERVICE_RC:
    case PACKET_LIST_SERVICES_RC:
    case PACKET_OPEN_SERVICE_RC:
    case PACKET_CLOSE_SERVICE_RC:
    case PACKET_PS_SERVICES_RC:
        tblrc = cmd_packet_body(table);
        pktrc->tid = cmd_result_tid(tblrc);
        pktrc->status = cmd_result_status(tblrc);
        break;

    default:
        assert(0);
        break;
    }
    return packet;
}
