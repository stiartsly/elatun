#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <getopt.h>
#include <sys/socket.h>

#include <ela_carrier.h>

#include "socket.h"
#include "packet.h"
#include "status.h"

extern const char *prog_name;
extern void wait_for_debug(void);
extern void show_hint(const char *);

static int bind_service(SOCKET fd,
                        const char *userid, const char *service,
                        const char *bind_address, const char *port)
{
    Packet *packet;
    int64_t tid;
    uint8_t *data;
    size_t data_len;
    int status = 0;
    ssize_t rc;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    BEGIN_ENCODE(BIND_SERVICE) {
        packet_set_service(packet, service);
        packet_set_userid(packet, userid);
        packet_set_bind_address(packet, bind_address);
        packet_set_port(packet, port);
    } END_ENCODE();

    socket_address("udp://127.0.0.1:33568", (struct sockaddr *)&addr, &addrlen);
    rc = sendto(fd, data, data_len, 0, (const struct sockaddr *)&addr, addrlen);
    free(data);
    if (rc != (ssize_t)data_len) {
        fprintf(stderr, "sendto error (%d)\n", socket_errno());
        return -1;
    }

    data_len = 1024;
    data = calloc(1, data_len);
    if (!data) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }

    rc = recvfrom(fd, data, data_len, 0, (struct sockaddr *)&addr,
                  &addrlen);
    if (rc < 0) {
        fprintf(stderr, "recvfrom error (%d)\n", socket_errno());
        free(data);
        return -1;
    }
    data_len = (size_t)rc;

    BEGIN_DECODE_RC(BIND_SERVICE) {
        status = packet_get_status(packet);
    } END_DECODE_RC();

    if (status == 0)
        fprintf(stdout, "Command excuted succeeded.\n");
    else
        fprintf(stderr, "Command excuted error with reason: %d\n", status);

    return 0;
}

static int check_format(char *format, char **bind_address, char **port)
{
    char *pos = format;

    *bind_address = pos;
    pos = strchr(pos, ':');
    if (!pos)
        return -1;

    *pos = '\0';
    *port = pos + 1;

    //TODO: check for host and port.
    return 0;
}

static int check_arguments(int index, int argc, char **argv, int *no_options)
{
    if (index == 1 && argc == 2) {
        *no_options = true;
        return true;
    }
    else if (index < argc) {
        int i;

        fprintf(stdout, "Invalid options: '%s ", argv[index]);
        for (i = index + 1; i < argc; i++) {
            fprintf(stdout, " %s", argv[i]);
        }
        fprintf(stdout, "'\n");
        fprintf(stdout, "See \'%s bind -h\'\n", prog_name);
        return false;
    }
    else {
        return true;
    }
}

static void parse_arguments(const char *args, char *userid, size_t userid_buflen,
                            char *service, size_t service_buflen,
                            char *format, size_t format_buflen)
{
    const char *prev = args;
    char *pos;

    pos = strchr(prev, ':');  // find userid option
    if (!pos) {
        if (strlen(args) >= userid_buflen) {
            strncpy(userid, prev, userid_buflen - 1);
            userid[userid_buflen - 1] = '\0';
        } else {
            strcpy(userid, prev);
        }
        return;
    }

    if (pos - prev >= userid_buflen) {
        strncpy(userid, prev, userid_buflen - 1);
        userid[userid_buflen - 1] = '\0';
    } else {
        strncpy(userid, prev, pos - prev);
        userid[pos - prev ] = '\0';
    }

    prev =  pos + 1; // skipped ':'

    pos = strchr(prev, ':');  // find service option
    if (!pos) {
        if (strlen(args) >= service_buflen) {
            strncpy(service, prev, service_buflen - 1);
            service[service_buflen - 1] = '\0';
        } else {
            strcpy(service, prev);
        }
        return;
    }

    if (pos - prev >= service_buflen) {
        strncpy(service, prev, service_buflen - 1);
        service[service_buflen - 1] = '\0';
    } else {
        strncpy(service, prev, pos - prev);
        service[pos - prev] = '\0';
    }

    prev = pos + 1; // skipped ':'

    if (strlen(prev) >= format_buflen) {
        strncpy(format, prev, format_buflen - 1);
        format[format_buflen - 1] = '\0';
    } else {
        strcpy(format, prev);
    }
}

static void show_usage(void)
{
    fprintf(stdout,
            "Usage: %s bind userid:servcie:[bind_address]:port\n"
            "       %s bind [OPTIONS]\n"
            "\n"
            "Bind service\n"
            "\n"
            "Options:\n"
            "  -u, --userid=string      User id to bind service for\n"
            "  -s, --service=string     Service name to bind\n"
            "  -f, --format=string      Bind a service with format of \'[bind_address]:port\'\n"
            "  -h, --help               Display command usage\n"
            "\n",
            prog_name, prog_name);
}

static SOCKET socket_fd = INVALID_SOCKET;
static void reclaim_socket(void)
{
    socket_close(socket_fd);
}

int bind_cmd(int argc, char **argv)
{
    char format[256]  = { 0 };
    char service[128] = { 0 };
    char userid[ELA_MAX_ID_LEN + 1] = { 0 };
    int no_options = 0;
    int opt;
    int idx;
    char *bind_address;
    char *port;

    struct option options[] = {
        { "format",         required_argument,  NULL,   'f' },
        { "userid",         required_argument,  NULL,   'u' },
        { "service",        required_argument,  NULL,   's' },
        { "debug",          no_argument,        NULL,    1  },
        { "help",           no_argument,        NULL,   'h' },
        { NULL,             0,                  NULL,    0  }
    };

    while ((opt = getopt_long(argc, argv, "u:s:f:h", options, &idx)) != -1) {
        switch (opt) {
        case 'u':
            if (strlen(optarg) >= sizeof(userid))
                strncpy(userid, optarg, sizeof(userid) - 1);
            else
                strcpy(userid, optarg);
            break;

        case 's':
            if (strlen(optarg) >= sizeof(service))
                strncpy(service, optarg, sizeof(service) - 1);
            else
                strcpy(service, optarg);
            break;

        case 'f':
            if (strlen(optarg) >= sizeof(format))
                strncpy(format, optarg, sizeof(format) - 1);
            else
                strcpy(format, optarg);
            break;

        case 1:
            wait_for_debug();
            break;

        case 'h':
            show_usage();
            return 0;
            
        default:
            show_hint(argv[0]);
            return 1;
        }
    }

    if (!check_arguments(optind, argc, argv, &no_options))
        return 1;

    if (no_options)
        parse_arguments(argv[1], userid, sizeof(userid), service,
                        sizeof(service), format, sizeof(format));

    if (!*userid) {
        fprintf(stderr, "Missing command options\n");
        show_hint(argv[1]);
        return 1;
    }

    if (!*service) {
        fprintf(stderr, "Missing command options\n");
        show_hint(argv[1]);
        return 1;
    }

    if (!*format) {
        fprintf(stderr, "Missing command options\n");
        show_hint(argv[1]);
        return 1;
    }

    if (check_format(format, &bind_address, &port)) {
        fprintf(stderr, "Format syntax \'%s\' invlaid\n", format);
        return 1;
    }

    if (!ela_id_is_valid(userid)) {
        fprintf(stderr, "Userid \'%s\' invalid\n", userid);
        return 1;
    }

    socket_fd = socket_create(0);
    if (socket_fd < 0)
        return -1;
    else
        atexit(reclaim_socket);

    return bind_service(socket_fd, userid, service, bind_address, port);
}
