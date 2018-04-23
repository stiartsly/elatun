#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linkedhashtable.h>
#include <linkedlist.h>
#include <rc_mem.h>
#include <vlog.h>
#include <ela_carrier.h>
#include <ela_session.h>

#include "config.h"
#include "status.h"
#include "packet.h"
#include "socket.h"
#include "agents.h"
#include "shadows.h"

extern const char *prog_name;
static const char *tunnel_version = "secure-tunnel/0.1/c";

typedef enum {
    ShadowState_created = 0,
    ShadowState_working,
    ShadowState_error
} ShadowState;

typedef enum {
    AgentState_created = 0,
    AgentState_friend_added,
    AgentState_stream_added,
    AgentState_session_request_sent,
    AgentState_stream_connected,
    AgentState_error
} AgentState;

typedef struct Tunnel {
    Config *cfg;
    ElaCarrier *w;
    char userid[ELA_MAX_ID_LEN + 1];

    Hashtable *clients; // client agent connects to server agent of another tunnel.
    Hashtable *servers;

    SOCKET socket;      // the socket to communicate with command client.

    // to store the received data.
    uint8_t recv_buf[1024];

    // to store data to send after decoding packet.
    uint8_t *send_data;
    size_t send_data_len;
} Tunnel;

static Tunnel *secure_tunnel = NULL;

static void agent_destroy(void *p)
{
    Agent *agent = (Agent *)p;
    assert(agent);

    if (agent->session)
        ela_session_close(agent->session);

    if (agent->shadows)
        deref(agent->shadows);

    if (agent->userid)
        free(agent->userid);

    if (agent->user_address)
        free(agent->user_address);

    if (agent->priv)
        free(agent->priv);
}

static void shadow_destroy(void *p)
{
    Shadow *shadow = (Shadow *)p;
    assert(shadow);

    if (shadow->service)
        free(shadow->service);

    if (shadow->bind_address)
        free(shadow->bind_address);

    if (shadow->port)
        free(shadow->port);
}

static int do_bind_service(Tunnel *tunnel,
                           const char *userid, const char *service,
                           const char *bind_address, const char *port)
{
    Shadow *shadow;
    Agent  *agent;
    int rc;

    if (strcmp(userid, tunnel->userid) == 0) {
        vlogE("Not allowed to bind service %s for self user (%s), ignored",
              service, userid);
        return STATUS_ERR;
    }

    agent = agents_get(tunnel->servers, userid);
    if (!agent) {
        agent = rc_zalloc(sizeof(Agent), agent_destroy);
        if (!agent) {
            vlogE("Out of memory");
            return STATUS_OUT_OF_MEMORY;
        }

        agent->shadows = hashtable_create(8, 1, NULL, NULL);
        if (!agent->shadows) {
            vlogE("Out of memory");
            deref(agent);
            return STATUS_OUT_OF_MEMORY;
        }

        agent->userid = strdup(userid);
        agent->session = NULL;
        agent->stream_id = -1;
        agent->state = AgentState_created;

        vlogD("Added new server agent with userid %s", userid);
        agents_put(tunnel->servers, agent);
    }

    shadow = shadows_get(agent->shadows, service);
    if (shadow) {
        vlogW("Service %s for %s already binding on tcp://%s:%s, ignored",
              service, userid,
              shadow->bind_address ? shadow->bind_address : "",
              shadow->port);
        deref(agent);
        deref(shadow);
        return STATUS_ALREADY_EXIST;
    }
    else {
        shadow = rc_zalloc(sizeof(Shadow), shadow_destroy);
        if (!shadow) {
            vlogE("Out of memory");
            deref(agent);
            return STATUS_OUT_OF_MEMORY;
        }

        shadow->service = strdup(service);
        shadow->bind_address = bind_address ? strdup(bind_address) : NULL;
        shadow->port = strdup(port);
        shadow->state = ShadowState_created;

        vlogD("Added new service (%s) shadow to bind on tcp://%s:%s",
              service, bind_address ? bind_address : "", port);

        shadows_put(agent->shadows, shadow);
    }

    if (!agent->session) { // wait for session_request callback to invoke to
                           // create session.
        deref(shadow);
        deref(agent);
        vlogD("Added Service %s for %s to bind on tcp://%s:%s, waiting for "
              "session request from %s", service, userid,
              bind_address ? bind_address : "", port, userid);
        return STATUS_OK;
    }

    rc = ela_session_add_service(agent->session, shadow->service,
                                 PortForwardingProtocol_TCP,
                                 shadow->bind_address, shadow->port);
    if (rc < 0) {
        vlogE("Add service %s for %s binding on tcp://%s:%s error (0x%08X)",
              shadow->service, agent->userid,
              shadow->bind_address ? shadow->bind_address : "", shadow->port,
              ela_get_error());

        deref(shadows_remove(agent->shadows, service));
        rc = STATUS_ERR;
    }
    else {
        vlogI("Service %s for %s was bound on tcp://%s:%s successfully",
              shadow->service, agent->userid,
              shadow->bind_address ? shadow->bind_address : "", shadow->port);
        shadow->state = ShadowState_working;
    }

    deref(shadow);
    deref(agent);
    return rc;
}

static void bind_service(Tunnel *tunnel, Packet *pkt)
{
    const char *service;
    const char *userid;
    const char *address;
    const char *port;
    Packet *rpkt;
    uint8_t *data;
    size_t data_len;
    int rc;

    userid  = packet_get_userid(pkt);
    service = packet_get_service(pkt);
    address = packet_get_bind_address(pkt);
    port    = packet_get_port(pkt);

    vlogD("Received command -- bind %s:%s:%s:%s", userid, service,
          address ? address : "", port);

    rc = do_bind_service(tunnel, userid, service, address, port);

    rpkt = packet_create(PACKET_BIND_SERVICE_RC);
    if (!rpkt) {
        vlogE("Out of memory");
        return;
    }

    packet_set_tid(rpkt, packet_get_tid(pkt));
    packet_set_status(rpkt, rc);

    data = packet_encode(rpkt, &data_len);
    packet_free(rpkt);

    if (!data) {
        vlogE("Decode packet error");
        return;
    }

    tunnel->send_data = data;
    tunnel->send_data_len = data_len;
}

static
int do_unbind_service(Tunnel *tunnel, const char *userid, const char *service)
{
    Shadow *shadow;
    Agent *agent;

    if (strcmp(userid, tunnel->userid) == 0) {
        vlogE("Not allowed to unbind service %s for self user (%d), ignored",
              service, userid);
        return STATUS_ERR;
    }

    agent = agents_get(tunnel->servers, userid);
    if (!agent) {
        vlogW("User %s not found to be allowed use service %s, ignored",
              userid, service);
        return STATUS_NOT_EXIST;
    }

    shadow = shadows_remove(agent->shadows, service);
    if (!shadow) {
        vlogW("Service %s not found to be allowed to used by user %s, ignored",
              service, userid);
        deref(agent);
        return STATUS_NOT_EXIST;
    }

    switch(shadow->state) {
    case ShadowState_created:
    case ShadowState_error:
        break;

    case ShadowState_working:
        assert(agent->session);
        ela_session_remove_service(agent->session, shadow->service);
        break;

    default:
        assert(0);
        break;
    }

    vlogI("Service %s binding on tcp://%s:%s used by %s was unbound successfully",
          service, userid, shadow->bind_address ? shadow->bind_address : "",
          shadow->port);

    deref(shadow);
    deref(agent);

    return STATUS_OK;
}

static void unbind_service(Tunnel *tunnel, Packet *pkt)
{
    const char *service;
    const char *userid;
    Packet *rpkt;
    uint8_t *data;
    size_t data_len;
    int rc;

    userid  = packet_get_userid(pkt);
    service = packet_get_service(pkt);

    vlogD("Received command -- unbind %s:%s", userid, service);

    rc = do_unbind_service(tunnel, userid, service);

    rpkt = packet_create(PACKET_UNBIND_SERVICE_RC);
    if (!rpkt) {
        vlogE("Out of memory");
        return;
    }

    packet_set_tid(rpkt, packet_get_tid(pkt));
    packet_set_status(rpkt, rc);

    data = packet_encode(rpkt, &data_len);
    packet_free(rpkt);

    if (!data) {
        vlogE("Decode packet error");
        return;
    }

    tunnel->send_data = data;
    tunnel->send_data_len = data_len;
}

static int do_list_services(Tunnel *tunnel, const char *userid, const char *service)
{
    HashtableIterator it;
    char buf[2048];
    int pos = 0;
    int rc;

    rc = sprintf(buf, "%s", "Total allowed users:\n");
    pos += rc;
    agents_iterate(tunnel->servers, &it);
    while (agents_iterator_has_next(&it)) {
        HashtableIterator iit;
        Agent *agent;

        rc = agents_iterator_next(&it, &agent);
        if (rc == 0 || rc == -1)
            break;

        rc = sprintf(buf + pos, "\tuserid:\t%s, allowed services:", agent->userid);
        pos += rc;

        shadows_iterate(agent->shadows, &iit);
        while (shadows_iterator_has_next(&iit)) {
            Shadow *shadow;

            rc = shadows_iterator_next(&iit, &shadow);
            if (rc == 0 || rc == -1)
                break;

            rc = sprintf(buf + pos, "(%s:%s:%s)", shadow->service,
                         shadow->bind_address ? shadow->bind_address : "",
                         shadow->port);
            pos += rc;

            deref(shadow);
        }

        rc = sprintf(buf + pos, "\n");
        pos += rc;

        deref(agent);
    }

    vlogI("%s", buf);
    return STATUS_OK;
}

static void list_services(Tunnel *tunnel, Packet *pkt)
{
    const char *service;
    const char *userid;
    Packet *rpkt;
    uint8_t *data;
    size_t data_len;
    int rc;

    userid  = packet_get_userid(pkt);
    service = packet_get_service(pkt);

    vlogD("Received command - services %s:%s", userid ? userid: "",
          service ? service : "");

    rc = do_list_services(tunnel, userid, service);

    rpkt = packet_create(PACKET_LIST_SERVICES_RC);
    if (!rpkt) {
        vlogE("Out of memory");
        return;
    }

    packet_set_tid(rpkt, packet_get_tid(pkt));
    packet_set_status(rpkt, rc);

    data = packet_encode(rpkt, &data_len);
    packet_free(rpkt);

    if (!data) {
        vlogE("Decode packet error");
        return;
    }

    tunnel->send_data = data;
    tunnel->send_data_len = data_len;
}

const char *stream_state_name[] = {
    "raw",
    "initialized",
    "transport ready",
    "connecting",
    "connected",
    "deactived",
    "closed",
    "error"
};

static void session_request_complete(ElaSession *ws, int status,
                const char *reason, const char *sdp, size_t len, void *context)
{
    Tunnel *tunnel = (Tunnel *)context;
    ElaStreamState state;
    Agent *agent;
    int rc;

    agent = agents_get_by_session(tunnel->clients, ws);
    assert(agent);

    if (status != 0) {
        vlogE("Session request complete with error(%d:%s).", status, reason);
        agent->state = AgentState_error;
        deref(agent);
        return;
    }

    rc = ela_stream_get_state(ws, agent->stream_id, &state);
    while (rc == 0 && state < ElaStreamState_transport_ready) {
        usleep(100);
        rc = ela_stream_get_state(ws, agent->stream_id, &state);
    }

    if (rc < 0) {
        vlogE("Acquire stream state in session failed(%08X).", ela_get_error());
        ela_session_close(agent->session);
        agent->session = NULL;
        agent->stream_id = -1;
        agent->state = AgentState_error;
        deref(agent);
        return;
    }

    if (state != ElaStreamState_transport_ready) {
        vlogE("Session stream state wrong %s.", stream_state_name[state]);
        ela_session_close(agent->session);
        agent->session = NULL;
        agent->stream_id = -1;
        agent->state = AgentState_error;
        deref(agent);
        return;
    }

    rc = ela_session_start(ws, sdp, len);
    if (rc < 0) {
        vlogE("Start session to %s error(%08X).", agent->userid, ela_get_error());
        ela_session_close(agent->session);
        agent->session = NULL;
        agent->stream_id = -1;
        agent->state = AgentState_error;
        deref(agent);
        return;
    } else
        vlogI("Start session to %s succeeded", agent->userid);

    deref(agent);
}

static void stream_state_changed_cb(ElaSession *ws, int stream,
                                    ElaStreamState state, void *context)
{
    Tunnel *tunnel = (Tunnel *)context;
    Agent *agent = NULL;
    bool client = false;
    int rc;

    vlogD("Stream (%d) state changed to %s", stream, stream_state_name[state]);

    if (!agent) {
        agent = agents_get_by_stream(tunnel->clients, stream);
        client = true;
    }
    if (!agent) {
        agent = agents_get_by_stream(tunnel->servers, stream);
        client = false;
    }
    assert(agent);

    if (state == ElaStreamState_failed) {
        ela_session_close(ws);
        agent->session = NULL;
        agent->stream_id = -1;
        agent->state = AgentState_error;
        deref(agent);
        return;
    }

    if (client) {
        if (state == ElaStreamState_initialized) {
            rc = ela_session_request(ws, session_request_complete, tunnel);
            if (rc < 0) {
                vlogE("Session request to %s error (0x%08X)", agent->userid,
                      ela_get_error());
                ela_session_close(ws);
                agent->session = NULL;
                agent->stream_id = -1;
                agent->state = AgentState_error;
            } else {
                vlogI("Session request to %s seucceeded", agent->userid);
            }
        } else if (state == ElaStreamState_transport_ready) {
            //empty;
        } else if (state == ElaStreamState_connected) {
            HashtableIterator it;

            hashtable_iterate(agent->shadows, &it);
            while (hashtable_iterator_has_next(&it)) {
                Shadow *shadow;

                shadows_iterator_next(&it, &shadow);
                vlogD("Opening service %s forwarding to user %s on tcp://%s:%s",
                        shadow->service, agent->userid,
                        shadow->bind_address ? shadow->bind_address : "", shadow->port);

                rc = ela_stream_open_port_forwarding(ws, stream, shadow->service,
                            PortForwardingProtocol_TCP, shadow->bind_address, shadow->port);
                if (rc < 0) {
                    vlogE("Open service %s forwarding to user %s on tcp://%s:%s error (0x%08X)",
                          shadow->service, agent->userid,
                          shadow->bind_address ? shadow->bind_address : "",
                          shadow->port, ela_get_error());
                    agents_iterator_remove(&it);
                } else {
                    vlogI("Open service %s forwarding to user %s on tcp://%s:%s successfully",
                          shadow->service, agent->userid,
                          shadow->bind_address ? shadow->bind_address : "",
                          shadow->port);
                }
                deref(shadow);
            }
        }
    } else {
        if (state == ElaStreamState_initialized) {
            rc = ela_session_reply_request(ws, 0, NULL);
            if (rc < 0) {
                vlogE("Reply session request from %s error (0x%08X)", agent->userid,
                      ela_get_error());
                ela_session_close(ws);
                agent->session = NULL;
                agent->stream_id = -1;
                free(agent->priv);
                agent->priv = NULL;
                agent->state = AgentState_error;
            } else {
                vlogI("Accepted session request from %s successfully", agent->userid);
            }
        } else if (state == ElaStreamState_transport_ready) {
            const char *sdp = (const char *)agent->priv;
            rc = ela_session_start(ws, sdp, strlen(sdp));
            free(agent->priv);
            agent->priv = NULL;

            if (rc < 0) {
                vlogE("Start session to %s failed(%08X).", agent->userid,
                      ela_get_error());
                ela_session_close(ws);
                agent->session = NULL;
                agent->stream_id = -1;
                agent->state = AgentState_error;
            } else
                vlogI("Start session to %s succeeded.", agent->userid);
        }
    }
}

static int agent_prepare(ElaCarrier *w, Agent *agent, void *context)
{
    ElaSession *ws;
    ElaStreamCallbacks callbacks;

    ws = ela_session_new(w, agent->userid);
    if (!ws) {
        vlogE("Create session to %s error (0x%08X)", agent->userid,
               ela_get_error());
        return -1;
    }

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.state_changed = stream_state_changed_cb;

    agent->session = ws;
    agent->stream_id = ela_session_add_stream(ws, ElaStreamType_application,
                ELA_STREAM_RELIABLE | ELA_STREAM_MULTIPLEXING | ELA_STREAM_PORT_FORWARDING,
                &callbacks, context);
    if (agent->stream_id < 0) {
        vlogE("Add stream to session error (0x%08X)", ela_get_error());
        ela_session_close(ws);
        agent->session = NULL;
        agent->state = AgentState_error;
        return -1;
    }

    vlogD("Add stream to session successfully, waiting for stream (%d) state "
          "to be initalized", agent->stream_id);
    return 0;
}

static int do_open_service(Tunnel *tunnel,
                           const char *user_address, const char *userid,
                           const char *service,
                           const char *bind_address, const char *port,
                           bool reverse)
{
    ElaFriendInfo fi;
    Shadow *shadow;
    Agent *agent;
    int rc;

    agent = agents_get(tunnel->clients, userid);
    if (!agent) {
        agent = rc_zalloc(sizeof(Agent), agent_destroy);
        if (!agent) {
            vlogE("Out of memory");
            return STATUS_OUT_OF_MEMORY;
        }

        agent->shadows = hashtable_create(8, 1, NULL, NULL);
        if (!agent->shadows) {
            vlogE("Out of memory");
            deref(agent);
            return STATUS_OUT_OF_MEMORY;
        }

        agent->userid = strdup(userid);
        agent->user_address = strdup(user_address);
        agent->stream_id = -1;
        agent->state = AgentState_created;

        vlogD("Added new client agent with userid %s", userid);

        agents_put(tunnel->clients, agent);
    }

    shadow = shadows_get(agent->shadows, service);
    if (!shadow) {
        shadow = rc_zalloc(sizeof(Shadow), shadow_destroy);
        if (!shadow) {
            vlogE("Out of memory");
            deref(agent);
            return STATUS_OUT_OF_MEMORY;
        }

        //TODO: open service forwrding with reverse mode.
        shadow->service = strdup(service);
        shadow->bind_address = bind_address ? strdup(bind_address) : NULL;
        shadow->port = strdup(port);
        shadow->state = ShadowState_created;

        vlogD("Added new server sevice (%s) shadow to bind on tcp://%s:%s",
              service, bind_address ? bind_address : "", port);

        shadows_put(agent->shadows, shadow);
    }

    if (!ela_is_friend(tunnel->w, userid)) {
        assert(agent->state == AgentState_created);

        rc = ela_add_friend(tunnel->w, user_address, tunnel_version);
        if (rc < 0) {
            vlogE("Add user %s as friend error (0x%08X)", userid,
                  ela_get_error());

            agent->state = AgentState_error;
            deref(shadow);
            deref(agent);
            return STATUS_ERR;
        }

        vlogD("Add user %s as friend successfully", userid);
        agent->state = AgentState_friend_added;
    }

    rc = ela_get_friend_info(tunnel->w, userid, &fi);
    if (rc < 0) {
        vlogE("Get friend %s info error (0x%08X)", userid, ela_get_error());

        // remove current service, should not affect other services.
        deref(shadows_remove(agent->shadows, service));
        deref(shadow);
        deref(agent);
        return STATUS_ERR;
    }

    if (fi.status != ElaConnectionStatus_Connected) {
        vlogD("Friend %s is being disconnected, wait for friend's connection",
              userid);

        // wait for friend conneted callback to invoke.
        deref(shadow);
        deref(agent);
        return STATUS_OK;
    } else {
        vlogD("Friend %s is being connected now", userid);
    }

    if (!agent->session) {
        vlogD("Creating forwarding stream to friend %s", userid);
        rc = agent_prepare(tunnel->w, agent, tunnel);
        if (rc < 0) {
            deref(shadow);
            deref(agent);
            return STATUS_ERR;
        }
    }

    if (agent->state != AgentState_stream_connected) {
        deref(shadow);
        deref(agent);
        return STATUS_OK;
    }

    if (shadow->state == ShadowState_working) {
        vlogE("Service %s to %s already being forwarded on tcp://%s:%s, ignored",
              service, userid, bind_address ? bind_address : "", port);

        rc = STATUS_ALREADY_EXIST;
    } else {
        vlogD("Opening service %s forwarding to user %s on tcp://%s:%s",
              service, userid, bind_address ? bind_address : "", port);

        rc = ela_stream_open_port_forwarding(agent->session, agent->stream_id,
                        service, PortForwardingProtocol_TCP, bind_address, port);
        if (rc < 0) {
            vlogE("Open service %s forwarding to user %s on tcp://%s:%s error (0x%08X)",
                  service, userid, bind_address ? bind_address : "", port,
                  ela_get_error());
            rc = STATUS_ERR;
        } else {
            vlogI("Open service %s forwarding to user %s on tcp://%s:%s successfully",
                  service, userid, bind_address ? bind_address : "", port);
            rc = STATUS_OK;
        }
    }

    deref(shadow);
    deref(agent);
    return rc;
}

static void open_service(Tunnel *tunnel, Packet *pkt)
{
    const char *user_address;
    const char *userid;
    const char *service;
    const char *bind_address;
    const char *port;
    bool reversed = true;
    Packet *rpkt;
    uint8_t *data;
    size_t data_len;
    int rc;

    user_address = packet_get_user_address(pkt);
    userid = packet_get_userid(pkt);
    service = packet_get_service(pkt);
    bind_address = packet_get_bind_address(pkt);
    port = packet_get_port(pkt);

    vlogD("Received command: open %s:%s:%s:%s:%s", user_address, userid,
          service, bind_address ? bind_address : "", port);

    rc = do_open_service(tunnel, user_address, userid, service,
                         bind_address, port, reversed);

    rpkt = packet_create(PACKET_OPEN_SERVICE_RC);
    if (!rpkt) {
        vlogE("Out of memory");
        return;
    }

    packet_set_tid(rpkt, packet_get_tid(pkt));
    packet_set_status(rpkt, rc);

    data = packet_encode(rpkt, &data_len);
    packet_free(rpkt);

    if (!data) {
        vlogE("Encode packet error");
        return ;
    }

    tunnel->send_data = data;
    tunnel->send_data_len = data_len;
}

static int do_close_service(Tunnel *tunnel, const char *userid,
                            const char *service)
{
    Shadow *shadow;
    Agent *agent;

    agent = agents_get(tunnel->clients, userid);
    if (!agent) {
        vlogE("User %s not found to forward service %s, ignored",
              userid, service);
        return STATUS_NOT_EXIST;
    }

    shadow = shadows_remove(agent->shadows, service);
    if (!shadow) {
        vlogE("Service %s not found used by user %s to forward, ignored",
              service, userid);
        deref(agent);
        return STATUS_NOT_EXIST;
    }

    switch(shadow->state) {
    case ShadowState_created:
        break;

    case ShadowState_working:
        ela_stream_close_port_forwarding(agent->session, agent->stream_id,
                                         shadow->port_forwarding);
        break;

    default:
        assert(0);
        break;
    }

    deref(shadow);
    deref(agent);
    return STATUS_OK;
}

static void close_service(Tunnel *tunnel, Packet *pkt)
{
    const char *service;
    const char *userid;
    Packet *rpkt;
    uint8_t *data;
    size_t data_len;
    int rc;

    service = packet_get_service(pkt);
    userid  = packet_get_userid(pkt);

    vlogD("Received command: close %s:%s", userid, service);

    rc = do_close_service(tunnel, userid, service);

    rpkt = packet_create(PACKET_CLOSE_SERVICE_RC);
    if (!rpkt) {
        vlogE("Out of memory");
        return;
    }

    packet_set_tid(rpkt, packet_get_tid(pkt));
    packet_set_status(rpkt, rc);

    data = packet_encode(rpkt, &data_len);
    packet_free(rpkt);

    if (!data) {
        vlogE("Encode packet error");
        return;
    }

    tunnel->send_data = data;
    tunnel->send_data_len = data_len;
}

static void ps_services(Tunnel *tunnel, Packet *pkt)
{
    //TODO
}

static void get_info(Tunnel *tunnel, Packet *pkt)
{
    //TODO;
}

static void (*handle_packet[])(Tunnel *, Packet *) = {
    NULL,
    bind_service,
    NULL,
    unbind_service,
    NULL,
    list_services,
    NULL,
    open_service,
    NULL,
    close_service,
    NULL,
    ps_services,
    NULL,
    get_info,
    NULL
};

static void agents_recycle(Hashtable *agents)
{
    HashtableIterator it;
    Agent *agent;

recycle_agents:
    agents_iterate(agents, &it);
    while (agents_iterator_has_next(&it)) {
        int rc;

        rc = agents_iterator_next(&it, &agent);
        if (rc == 0)
            break;

        if (rc == -1)
            goto recycle_agents;

        if (agent->state == AgentState_error || shadows_is_empty(agent->shadows)) {
            ela_session_close(agent->session);
            agent->session = NULL;
            agent->stream_id = -1;
            agents_iterator_remove(&it);
        }

        deref(agent);
    }
}

static void carrier_idle(ElaCarrier *w, void *context)
{
    Tunnel *tunnel = (Tunnel *)context;
    struct sockaddr_storage from;
    socklen_t socklen = sizeof(from);
    Packet *pkt;
    ssize_t rc;
    int type;

    errno = 0;
    rc = recvfrom(tunnel->socket,
                  tunnel->recv_buf, sizeof(tunnel->recv_buf),
                  0, (struct sockaddr *)&from, &socklen);
    if (rc < 0 && errno == EAGAIN)
        return;
        
    if (rc < 0) {
        vlogE("Receive packet error");
        return;
    }

    vlogD("Received %d bytes packet from %s", (int)rc, "<TODO>");

    pkt = packet_decode(tunnel->recv_buf, (size_t)rc);
    if (!pkt) {
        vlogE("Decode packet error");
        return;
    }

    type = packet_get_type(pkt);
    if (type < 0 || type >= PACKET_BUTT) {
        vlogE("Unrecogized packet, ignored");
        packet_free(pkt);
        return;
    }

    if (!handle_packet[type]) {
        vlogE("Unhandlable packet, ignored");
        packet_free(pkt);
        return;
    }

    handle_packet[type](tunnel, pkt);
    packet_free(pkt);

    if (!tunnel->send_data)
        return;

    rc = sendto(tunnel->socket, tunnel->send_data, tunnel->send_data_len,
                0, (struct sockaddr *)&from, socklen);

    free(tunnel->send_data);
    tunnel->send_data = NULL;
    tunnel->send_data_len = 0;

    if (rc < 0) {
        vlogE("Sendback result error");
        return;
    }

    agents_recycle(tunnel->servers);
    agents_recycle(tunnel->clients);
}

static void carrier_ready(ElaCarrier *w, void *context)
{
    Tunnel *tunnel = (Tunnel *)context;
    char address[ELA_MAX_ADDRESS_LEN + 1];

    vlogI("Secure tunnel is ready now.");
    vlogI("User ID: %s", tunnel->userid);
    vlogI("Address: %s", ela_get_address(w, address, sizeof(address)));
}

static const char *connection_name[] = {
    "Connected",
    "Disconnected"
};

static void friend_connection(ElaCarrier *w, const char *friendid,
                        ElaConnectionStatus status, void *context)
{
    Tunnel *tunnel = (Tunnel *)context;
    Agent *agent;

    vlogD("Friend %s connection changed to %s", friendid, connection_name[status]);

    if (status != ElaConnectionStatus_Connected)
        return;

    agent = agents_get(tunnel->clients, friendid);
    if (!agent) {
        vlogW("User %s not found to be allowed use service, ignored", friendid);
        return ;
    }
    if (shadows_is_empty(agent->shadows)) {
        deref(agent);
        return;
    }

    if (!agent->session)
        agent_prepare(w, agent, context);

    deref(agent);
}

static void friend_request(ElaCarrier *w, const char *userid,
            const ElaUserInfo *info, const char *hello, void *context)
{
    Tunnel *tunnel = (Tunnel *)context;
    int rc;

    if (strcmp(hello, tunnel_version) != 0) {
        vlogE("Received friend request from user %s with wrong hello %s, "
              "ignored", userid, hello);
        return;
    } else {
        vlogD("Received friend request from user %s", userid);
    }

    rc = hashtable_exist(tunnel->servers, userid, strlen(userid));
    if (rc) {
        vlogE("Accepting friend request from %s", userid);

        rc = ela_accept_friend(tunnel->w, userid);
        if (rc < 0) {
            vlogE("Accpet friend request error (0x%08X)", ela_get_error());
        } else {
            vlogI("Accpeted user %s to be friend", userid);
        }
    } else {
        vlogI("Refused unauthorized friend request from %s", userid);
    }
}

static void session_request_callback(ElaCarrier *w, const char *from,
                            const char *sdp, size_t len, void *context)
{
    Tunnel *tunnel = (Tunnel *)context;
    Agent *agent;
    ElaSession *ws;
    ElaStreamCallbacks callbacks;
    HashtableIterator it;
    int rc;

    vlogD("Received session request from %s", from);

    ws = ela_session_new(w, from);
    if (!ws) {
        vlogE("Create session to %s error (0x%08X), ignore session request",
              from, ela_get_error());
        return;
    }

    agent = agents_get(tunnel->servers, from);
    if (!agent) {
        vlogE("Refused unauthorized session request from %s", from);
        ela_session_reply_request(ws, -1, "Refuse");
        ela_session_close(ws);
        return;
    }

    if (shadows_is_empty(agent->shadows)) {
        vlogE("Refused unauthrized session request from %s because no services "
              "allowed to forward",from);
        ela_session_reply_request(ws, -1, "Refuse");
        ela_session_close(ws);
        return;
    }

    if (agent->session) {
        ela_session_close(agent->session);
        agent->session = NULL;
    }

rebind_service:
    shadows_iterate(agent->shadows, &it);
    while (shadows_iterator_has_next(&it)) {
        Shadow *shadow;

        rc = shadows_iterator_next(&it, &shadow);
        if (rc == 0)
            break;

        if (rc == -1)
            goto rebind_service;

        rc = ela_session_add_service(ws, shadow->service, PortForwardingProtocol_TCP,
                                     shadow->bind_address, shadow->port);
        if (rc < 0) {
            vlogE("Add service %s for %s binding on tcp://%s:%s error (0x%08X)",
                  shadow->service, agent->userid,
                  shadow->bind_address ? shadow->bind_address : "", shadow->port,
                  ela_get_error());

            shadows_iterator_remove(&it);
        } else {
            vlogD("Bind service %s for %s on tcp://%s:%s successfully",
                  shadow->service, agent->userid,
                  shadow->bind_address ? shadow->bind_address : "", shadow->port);
            shadow->state = ShadowState_working;
        }

        deref(shadow);
    }

    if (agent->priv)
        free(agent->priv);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.state_changed = stream_state_changed_cb;

    agent->priv = strdup(sdp);
    agent->session = ws;
    agent->stream_id = ela_session_add_stream(ws, ElaStreamType_application,
                ELA_STREAM_RELIABLE | ELA_STREAM_MULTIPLEXING | ELA_STREAM_PORT_FORWARDING,
                &callbacks, tunnel);
    if (agent->stream_id < 0) {
        vlogE("Add stream to sesion with %s error (0x%08X)", from,
              ela_get_error());

        ela_session_reply_request(ws, -1, "Error");
        ela_session_close(ws);
        agent->session = NULL;
        agent->state = AgentState_error;

        if (agent->priv) {
            free(agent->priv);
            agent->priv = NULL;
        }
    } else {
        vlogD("Added stream to session with %s successfully", from);
    }

    deref(agent);
}

static void tunnel_kill(void)
{
    if (secure_tunnel)
        deref(secure_tunnel);
}

static void tunnel_destroy(void *p)
{
    Tunnel *tunnel = (Tunnel *)p;
    assert(tunnel);

    if (tunnel->socket > 0)
        socket_close(tunnel->socket);

    if (tunnel->send_data)
        free(tunnel->send_data);

    if (tunnel->servers)
        deref(tunnel->servers);

    if (tunnel->clients)
        deref(tunnel->clients);

    if (tunnel->w) {
        ela_session_cleanup(tunnel->w);
        ela_kill(tunnel->w);
    }

    if (tunnel->cfg)
        deref(tunnel->cfg);
}

static void daemonize(const char *pid_file_path)
{
    FILE *fp;
    pid_t pid;

    // Check if the PID file exists
    if ((fp = fopen(pid_file_path, "r"))) {
        vlogW("Another instance of tunnel daemon is already running,"
              "PID file %s exists. Exiting.\n", pid_file_path);
        fclose(fp);
        exit(1);
    }

    // Open the PID file for writing
    fp = fopen(pid_file_path, "w+");
    if (!fp) {
        vlogE("Couldn't open the PID file for writing: %s. Exiting.\n",
              pid_file_path);
        exit(1);
    }

    pid = fork();

    if (pid > 0) {
        fprintf(fp, "%d", pid);
        fclose(fp);
        vlogD("Forking succeeded: PID: %d.\n", pid);
        exit(0);
    } else {
        fclose(fp);
    }

    if (pid < 0) {
        vlogE("Forking failed. Exiting");
        exit(1);
    }

    if (setsid() < 0) {
        vlogE("SID creation failed. Exiting.\n");
        exit(1);
    }
}

static void signal_handler(int signum)
{
    tunnel_kill();
}

static void show_usage()
{
    fprintf(stdout,
            "Usage: %s [OPTIONS] [COMMAND] \n"
            "A secure tunnel program to forward services over carrier network\n"
            "Options:\n"
            "  -c, --config=string       Location of config file.\n"
            "                            Default: ./tunnel.conf\n"
            "                                     ~/.elatun/tunnel.conf\n"
            "                                     /etc/elatun/tunnel.conf\n"
            "                                     /usr/local/etc/elatun/tunnel.conf\n"
            "  -d, --daemon[=foreground] Run as tunnel daemon. If foreground is specified,\n"
            "                            it will running in foreground, default is running\n"
            "                            as a background daemon.\n"
            "  -h, --help                Print this help usage and quit\n"
            "  -v, --version             Print version information and quit\n"
            "\n",
            prog_name);
}

int tunnel_main(int argc, char *argv[])
{
    Tunnel *tunnel;
    Config *config;
    char *config_file;
    ElaOptions opts;
    ElaCallbacks cbs;
    ListIterator it;
    int run_as_deamon = 0;
    int cur = 0;
    int rc;
    int opt;
    int idx;

    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGTERM, signal_handler);

    struct option options[] = {
        { "config",         required_argument,  NULL, 'c' },
        { "daemon",         no_argument,        NULL, 'D' },
        { NULL,             0,                  NULL,  0  }
    };

    while ((opt = getopt_long(argc, argv, "c:D", options, &idx)) != -1) {
        switch (opt) {
        case 'c':
            config_file = optarg;
            break;

        case 'D':
            run_as_deamon = 1;
            break;

        case '?':
        default:
            show_usage();
            exit(0);
            break;
        }
    }

    config = load_config(config_file);
    if (!config)
        return -1;

    if (run_as_deamon)
        daemonize(config->pidfile);

    // Initialize carrier options.
    memset(&opts, 0, sizeof(opts));

    opts.udp_enabled = config->udp_enabled;
    opts.persistent_location = config->datadir;
    opts.bootstraps_size = list_size(config->bootstraps);
    opts.bootstraps = (BootstrapNode *)calloc(1, sizeof(BootstrapNode) * opts.bootstraps_size);

    if (!opts.bootstraps) {
        fprintf(stderr, "out of memory.");
        deref(config);
        return -1;
    }

    list_iterate(config->bootstraps, &it);
    while (list_iterator_has_next(&it) && cur < opts.bootstraps_size) {
        BootstrapItem *item;
        BootstrapNode *node;

        rc = list_iterator_next(&it, (void **)&item);
        assert(rc != -1);

        if (rc == 0)
            break;

        node = &opts.bootstraps[cur];
        node->ipv4 = item->node.ipv4;
        node->ipv6 = item->node.ipv6;
        node->port = item->node.port;
        node->public_key = item->node.public_key;

        cur++;
    }

    memset(&cbs, 0, sizeof(cbs));
    cbs.idle = carrier_idle;
    cbs.ready = carrier_ready;
    cbs.friend_connection = friend_connection;
    cbs.friend_request = friend_request;

    ela_log_init(config->loglevel, config->logfile, NULL);

    tunnel = rc_zalloc(sizeof(Tunnel), tunnel_destroy);
    if (!tunnel) {
        fprintf(stderr, "Out of memory");
        deref(config);
        return -1;
    }

    tunnel->cfg = config; // config's ref pass to tunnel object!!!
    tunnel->socket = socket_create(config->ctrl_uri);
    if (tunnel->socket < 0) {
        deref(tunnel);
        return -1;
    }

    tunnel->clients = hashtable_create(8, 1, NULL, NULL);
    if (!tunnel->clients) {
        vlogE("Out of memory");
        deref(tunnel);
        return -1;
    }

    tunnel->servers = hashtable_create(8, 1, NULL, NULL);
    if (!tunnel->servers) {
        vlogE("Out of memory");
        deref(tunnel);
        return -1;
    }

    tunnel->w = ela_new(&opts, &cbs, tunnel);
    free(opts.bootstraps);

    if (!tunnel->w) {
        vlogE("Can not create tunnel carrier instance (0x08X)",
              ela_get_error());
        deref(tunnel);
        return -1;
    }

    rc = ela_session_init(tunnel->w, session_request_callback, tunnel);
    if (rc < 0) {
        vlogE("Can not initialize tunnel session (0x%08X)",
              ela_get_error());
        deref(tunnel);
        return -1;
    }

    ela_get_userid(tunnel->w, tunnel->userid, sizeof(tunnel->userid));
    secure_tunnel = tunnel;
    rc = ela_run(tunnel->w, 500);
    if (rc < 0)
        vlogE("Can not start tunnel carrier");

    vlogI("Tunnel exited!!!");
    return rc;
}
