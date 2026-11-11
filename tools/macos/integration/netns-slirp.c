// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0
//
// A macOS network for upstream's integration tests: what `ip netns add` plus
// `ip tuntap add` and an address on the TAP give the tests on Linux. A
// network is a directory of endpoints (the jailer's --netns, WICK_NETNS):
// Firecracker binds its interface `<name>` there (vmm::platform::net), and
// behind each one this process is the host, a user-space IP stack (libslirp)
// whose address is the one the test gives its TAP (`ifconfig tap0
// 192.168.0.1/30 up`), bound at `.host-<name>` next to it. It attaches to
// the endpoint (an empty datagram) whenever one is bound there anew. The
// test reaches the guest through a forward: what `ip netns exec <ns> ssh
// <guest>` does on Linux, a Unix socket here that leads to <guest>:<port>.
//
//   netns-slirp NETWORK CONTROL FORWARDS
//
// NETWORK is the network's directory, CONTROL the socket this process takes
// requests on, FORWARDS where it makes forwards. Requests (one line each;
// a reply is a 32-bit errno, a 16-bit length and that much text):
//   hello                           "netns-slirp 1"
//   add <name> [<address>/<prefix>] an interface, with the host's address
//   fwd <guest ip> <port>           a forward; the reply is its socket path
//   used <name>                     "1" while a VMM has the interface bound
// It prints "ready" once CONTROL listens, and ends when its stdin closes
// (the harness's end of a pipe: the network lives as long as its owner).
//
// A program on the host cannot run inside this network (`ip netns exec`
// does that on Linux); only ssh and scp reach the guest, through forwards.
//
// Build: cc -O2 netns-slirp.c $(pkg-config --cflags --libs slirp)
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <libslirp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define MAX_IFACES 256 // a Linux namespace keeps every TAP a test adds
#define MAX_CONNS 32
#define MAX_POLL 8192

struct timer {
    SlirpTimerId id;
    void *cb_opaque;
    int64_t expire_ms; // -1: not armed
    struct iface *iface;
};

struct iface {
    char name[16];
    struct in_addr host, mask;
    Slirp *slirp;
    int fd;                  // the host's socket, bound at .host-<name>
    struct sockaddr_un vmm;  // the VMM's endpoint, <name>
    ino_t attached;          // the endpoint attached to (its inode), 0: none
    struct timer timers[4];
    int ntimers;
};

static struct iface ifaces[MAX_IFACES];
static int nifaces;
static int conns[MAX_CONNS];
static int nconns;
static char net[1024];
static const char *dir;
static struct pollfd pfds[MAX_POLL];
static int npfds;

static int64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static slirp_ssize_t send_packet(const void *buf, size_t len, void *opaque) {
    struct iface *i = opaque;
    if (!i->attached)
        return (slirp_ssize_t)len; // no VMM: dropped, as on a TAP no one reads
    ssize_t n = sendto(i->fd, buf, len, 0, (struct sockaddr *)&i->vmm, sizeof i->vmm);
    if (n < 0 && (errno == EAGAIN || errno == ENOBUFS))
        return (slirp_ssize_t)len; // TCP retransmits
    if (n < 0 && (errno == ECONNREFUSED || errno == ENOENT)) {
        i->attached = 0; // the VMM went away: dropped
        return (slirp_ssize_t)len;
    }
    return n < 0 ? -1 : n;
}

static void guest_error(const char *msg, void *opaque) {
    fprintf(stderr, "netns-slirp %s: guest error: %s\n", ((struct iface *)opaque)->name, msg);
}

static int64_t clock_get_ns(void *opaque) { (void)opaque; return now_ns(); }

static void *timer_new_opaque(SlirpTimerId id, void *cb_opaque, void *opaque) {
    struct iface *i = opaque;
    if (i->ntimers == 4) {
        fprintf(stderr, "netns-slirp: too many timers\n");
        exit(1);
    }
    struct timer *t = &i->timers[i->ntimers++];
    t->id = id;
    t->cb_opaque = cb_opaque;
    t->expire_ms = -1;
    t->iface = i;
    return t;
}

static void timer_free(void *timer, void *opaque) { (void)opaque; ((struct timer *)timer)->expire_ms = -1; }
static void timer_mod(void *timer, int64_t expire, void *opaque) { (void)opaque; ((struct timer *)timer)->expire_ms = expire; }
static void register_poll_socket(slirp_os_socket s, void *opaque) { (void)s; (void)opaque; }
static void unregister_poll_socket(slirp_os_socket s, void *opaque) { (void)s; (void)opaque; }
static void notify(void *opaque) { (void)opaque; }

static const SlirpCb callbacks = {
    .send_packet = send_packet,
    .guest_error = guest_error,
    .clock_get_ns = clock_get_ns,
    .timer_free = timer_free,
    .timer_mod = timer_mod,
    .notify = notify,
    .timer_new_opaque = timer_new_opaque,
    .register_poll_socket = register_poll_socket,
    .unregister_poll_socket = unregister_poll_socket,
};

static int add_poll(slirp_os_socket fd, int events, void *opaque) {
    (void)opaque;
    if (npfds == MAX_POLL) {
        fprintf(stderr, "netns-slirp: too many sockets\n");
        exit(1);
    }
    short ev = 0;
    if (events & SLIRP_POLL_IN) ev |= POLLIN;
    if (events & SLIRP_POLL_OUT) ev |= POLLOUT;
    if (events & SLIRP_POLL_PRI) ev |= POLLPRI;
    pfds[npfds].fd = fd;
    pfds[npfds].events = ev;
    pfds[npfds].revents = 0;
    return npfds++;
}

static int get_revents(int idx, void *opaque) {
    (void)opaque;
    short r = pfds[idx].revents;
    int ev = 0;
    if (r & POLLIN) ev |= SLIRP_POLL_IN;
    if (r & POLLOUT) ev |= SLIRP_POLL_OUT;
    if (r & POLLPRI) ev |= SLIRP_POLL_PRI;
    if (r & POLLERR) ev |= SLIRP_POLL_ERR;
    if (r & POLLHUP) ev |= SLIRP_POLL_HUP;
    return ev;
}

static struct iface *find(const char *name) {
    for (int k = 0; k < nifaces; k++)
        if (strcmp(ifaces[k].name, name) == 0)
            return &ifaces[k];
    return NULL;
}

static void reply(int conn, int err, const char *text) {
    uint8_t head[6];
    int32_t e = err;
    uint16_t len = text ? (uint16_t)strlen(text) : 0;
    memcpy(head, &e, 4);
    memcpy(head + 4, &len, 2);
    if (write(conn, head, sizeof head) != (ssize_t)sizeof head || (len && write(conn, text, len) != len))
        fprintf(stderr, "netns-slirp: reply: %s\n", strerror(errno));
}

static uint8_t frame[65536];

// Passes the VMM's frames on: those from the interface's endpoint only,
// which names itself by its path or, made through the network's directory,
// by its name in it.
static void drain(struct iface *i) {
    for (;;) {
        struct sockaddr_un from;
        socklen_t flen = sizeof from;
        memset(&from, 0, sizeof from);
        ssize_t n = recvfrom(i->fd, frame, sizeof frame, MSG_DONTWAIT, (struct sockaddr *)&from, &flen);
        if (n < 0) return;
        if (n > 0 && i->slirp && (strcmp(from.sun_path, i->vmm.sun_path) == 0 || strcmp(from.sun_path, i->name) == 0))
            slirp_input(i->slirp, frame, (int)n);
    }
}

// Whether a VMM has the endpoint bound: a socket file someone receives on.
static int bound(struct iface *i) {
    int probe = socket(AF_UNIX, SOCK_DGRAM, 0);
    int ok = connect(probe, (struct sockaddr *)&i->vmm, sizeof i->vmm) == 0;
    close(probe);
    return ok;
}

// Attaches to the endpoint when one is bound there anew (a VMM's first, or
// one bound again after an update of the device or a restore): the VMM
// sends its frames to whoever sent it a datagram.
static void attach(struct iface *i) {
    struct stat st;
    if (stat(i->vmm.sun_path, &st) != 0) {
        i->attached = 0;
        return;
    }
    if (st.st_ino == i->attached) return;
    if (sendto(i->fd, "", 0, 0, (struct sockaddr *)&i->vmm, sizeof i->vmm) == 0)
        i->attached = st.st_ino;
}

static void request(int conn, char *line) {
    char verb[16], a[64], b[64], c[16];
    int n = sscanf(line, "%15s %63s %63s %15s", verb, a, b, c);
    if (n >= 1 && strcmp(verb, "hello") == 0) {
        reply(conn, 0, "netns-slirp 1");
    } else if ((n == 2 || n == 3) && strcmp(verb, "add") == 0) {
        struct in_addr host = {0};
        int prefix = 0;
        if (n == 3) {
            char *slash = strchr(b, '/');
            prefix = slash ? atoi(slash + 1) : -1;
            if (slash) *slash = 0;
            if (prefix < 1 || prefix > 30 || inet_pton(AF_INET, b, &host) != 1) {
                reply(conn, EINVAL, NULL);
                return;
            }
        }
        if (strlen(a) >= 16) {
            reply(conn, EINVAL, NULL);
            return;
        }
        if (find(a)) {
            reply(conn, EEXIST, NULL);
            return;
        }
        if (nifaces == MAX_IFACES) {
            reply(conn, ENOSPC, NULL);
            return;
        }
        struct iface *i = &ifaces[nifaces];
        memset(i, 0, sizeof *i);
        strcpy(i->name, a);
        i->host = host;
        i->vmm.sun_len = sizeof i->vmm;
        i->vmm.sun_family = AF_UNIX;
        struct sockaddr_un h = {.sun_len = sizeof h, .sun_family = AF_UNIX};
        if ((size_t)snprintf(i->vmm.sun_path, sizeof i->vmm.sun_path, "%s/%s", net, a) >= sizeof i->vmm.sun_path ||
            (size_t)snprintf(h.sun_path, sizeof h.sun_path, "%s/.host-%s", net, a) >= sizeof h.sun_path) {
            reply(conn, ENAMETOOLONG, NULL);
            return;
        }
        i->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        int size = 4 << 20;
        setsockopt(i->fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof size);
        setsockopt(i->fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof size);
        fcntl(i->fd, F_SETFL, O_NONBLOCK);
        unlink(h.sun_path);
        if (bind(i->fd, (struct sockaddr *)&h, sizeof h) != 0) {
            int e = errno;
            close(i->fd);
            reply(conn, e, NULL);
            return;
        }
        if (n == 2) {
            // A TAP without an address: frames go nowhere.
            nifaces++;
            reply(conn, 0, NULL);
            return;
        }
        i->mask.s_addr = htonl(~0u << (32 - prefix));
        SlirpConfig cfg = {0};
        cfg.version = 6; // register_poll_socket, disable_dhcp
        cfg.in_enabled = true;
        cfg.vnetwork.s_addr = host.s_addr & i->mask.s_addr;
        cfg.vnetmask = i->mask;
        cfg.vhost = host;
        cfg.vdhcp_start.s_addr = htonl(ntohl(host.s_addr) + 1);
        cfg.vnameserver = host;
        cfg.disable_dns = true;
        cfg.disable_dhcp = true;
        // Linux's netns has no route anywhere but the TAP's subnet: neither
        // does this one (no host loopback, nothing beyond).
        cfg.restricted = 1;
        cfg.disable_host_loopback = true;
        i->slirp = slirp_new(&cfg, &callbacks, i);
        if (!i->slirp) {
            reply(conn, EINVAL, NULL);
            return;
        }
        nifaces++;
        reply(conn, 0, NULL);
    } else if (n == 3 && strcmp(verb, "fwd") == 0) {
        // The interface is the one whose subnet holds the guest's address,
        // as the route in a Linux namespace picks the TAP.
        struct sockaddr_in g = {.sin_len = sizeof g, .sin_family = AF_INET, .sin_port = htons(atoi(b))};
        struct iface *i = NULL;
        if (inet_pton(AF_INET, a, &g.sin_addr) == 1)
            for (int k = 0; k < nifaces; k++)
                if (ifaces[k].slirp &&
                    (g.sin_addr.s_addr & ifaces[k].mask.s_addr) == (ifaces[k].host.s_addr & ifaces[k].mask.s_addr))
                    i = &ifaces[k];
        if (!i) {
            reply(conn, ENETUNREACH, NULL);
            return;
        }
        struct sockaddr_un h = {.sun_family = AF_UNIX};
        snprintf(h.sun_path, sizeof h.sun_path, "%s/%s-%s", dir, a, b);
        if (access(h.sun_path, F_OK) != 0 &&
            slirp_add_hostxfwd(i->slirp, (struct sockaddr *)&h, sizeof h, (struct sockaddr *)&g, sizeof g, 0) != 0) {
            reply(conn, errno ? errno : EINVAL, NULL);
            return;
        }
        reply(conn, 0, h.sun_path);
    } else if (n == 2 && strcmp(verb, "used") == 0) {
        struct iface *i = find(a);
        reply(conn, i ? 0 : ENODEV, i && bound(i) ? "1" : "0");
    } else {
        reply(conn, EINVAL, NULL);
    }
}

static void serve_conn(int k) {
    char line[256];
    ssize_t n = recv(conns[k], line, sizeof line - 1, 0);
    if (n <= 0) {
        close(conns[k]);
        conns[k] = conns[--nconns];
        return;
    }
    line[n] = 0;
    // One request per line; a client sends one and waits for the reply.
    for (char *p = line, *nl; (nl = strchr(p, '\n')); p = nl + 1) {
        *nl = 0;
        request(conns[k], p);
    }
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s NETWORK CONTROL FORWARDS\n", argv[0]);
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    // By its real path: the name a jailed VMM knows the network by
    // (vmm::platform::net reaches a peer that names itself by it).
    if (!realpath(argv[1], net)) {
        fprintf(stderr, "netns-slirp: %s: %s\n", argv[1], strerror(errno));
        return 1;
    }
    dir = argv[3];
    int lst = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    if (strlen(argv[2]) >= sizeof a.sun_path) {
        fprintf(stderr, "netns-slirp: %s: path too long\n", argv[2]);
        return 1;
    }
    strcpy(a.sun_path, argv[2]);
    unlink(argv[2]);
    if (bind(lst, (struct sockaddr *)&a, sizeof a) != 0 || listen(lst, 16) != 0) {
        fprintf(stderr, "netns-slirp: %s: %s\n", argv[2], strerror(errno));
        return 1;
    }
    printf("ready\n");
    fflush(stdout);
    for (;;) {
        npfds = 0;
        // A VMM's endpoint is looked for every 50 ms.
        uint32_t timeout = 50;
        for (int k = 0; k < nifaces; k++) attach(&ifaces[k]);
        add_poll(0, SLIRP_POLL_IN, NULL); // the parent: its end closes ours
        add_poll(lst, SLIRP_POLL_IN, NULL);
        int conn0 = npfds;
        for (int k = 0; k < nconns; k++) add_poll(conns[k], SLIRP_POLL_IN, NULL);
        int if0 = npfds;
        for (int k = 0; k < nifaces; k++) add_poll(ifaces[k].fd, SLIRP_POLL_IN, NULL);
        int64_t now_ms = now_ns() / 1000000;
        for (int k = 0; k < nifaces; k++) {
            if (!ifaces[k].slirp) continue;
            slirp_pollfds_fill_socket(ifaces[k].slirp, &timeout, add_poll, NULL);
            for (int t = 0; t < ifaces[k].ntimers; t++) {
                int64_t e = ifaces[k].timers[t].expire_ms;
                if (e >= 0) timeout = e <= now_ms ? 0 : (uint32_t)(e - now_ms) < timeout ? (uint32_t)(e - now_ms) : timeout;
            }
        }
        int r = poll(pfds, npfds, (int)timeout);
        if (r < 0 && errno != EINTR) {
            perror("netns-slirp: poll");
            return 1;
        }
        if (pfds[0].revents)
            return 0;
        // Each instance's slirp_pollfds_poll walks only its own indexes.
        for (int k = 0; k < nifaces; k++)
            if (ifaces[k].slirp) slirp_pollfds_poll(ifaces[k].slirp, r < 0, get_revents, NULL);
        now_ms = now_ns() / 1000000;
        for (int k = 0; k < nifaces; k++)
            for (int t = 0; t < ifaces[k].ntimers; t++) {
                struct timer *tm = &ifaces[k].timers[t];
                if (tm->expire_ms >= 0 && tm->expire_ms <= now_ms) {
                    tm->expire_ms = -1;
                    slirp_handle_timer(ifaces[k].slirp, tm->id, tm->cb_opaque);
                }
            }
        for (int k = 0; k < nifaces; k++) {
            struct iface *i = &ifaces[k];
            if (pfds[if0 + k].revents) drain(i);
        }
        for (int k = nconns - 1; k >= 0; k--)
            if (pfds[conn0 + k].revents) serve_conn(k);
        if (pfds[1].revents & POLLIN) {
            int c = accept(lst, NULL, NULL);
            if (c >= 0) {
                if (nconns == MAX_CONNS) close(c);
                else conns[nconns++] = c;
            }
        }
    }
}
