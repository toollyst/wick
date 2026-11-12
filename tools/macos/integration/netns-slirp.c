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
//   gfwd <host ip> <port> <path>    the host's programs: a TCP listener
//                                   at <host ip>:<port> (0.0.0.0: every
//                                   interface's), which is the Unix socket
//                                   <path>; EADDRINUSE while another
//                                   listener there accepts
//   ungfwd <host ip> <port>         that listener gone
//   ufwd <guest ip> <port>          a UDP forward to <guest ip>:<port>; the
//                                   reply is the 127.0.0.1:<port> it is at.
//                                   This process forwards it (libslirp's own
//                                   UDP forward does not take the guest's
//                                   answers in a restricted network: its
//                                   udp_input drops all of the guest's UDP):
//                                   a datagram to that port reaches the
//                                   guest from <host address>:<the sender's
//                                   port>, and what the guest sends from
//                                   <guest ip>:<port> back there reaches
//                                   the sender, from that loopback port
//
// A program on the host "in the network" (`ip netns exec` on Linux) runs
// with tools/macos/integration/netns-preload.c, which makes its IPv4
// sockets this network's through these requests. A guest's connection to
// a listener of the host's goes to a second slirp instance of the
// interface (its "programs" stack): libslirp forwards a guest's connection
// to a Unix socket only at an address that is not its own host address
// (slirp_add_unix refuses the virtual host's: measured), so that stack has
// the interface's subnet widened to a /24 and its own host address at the
// subnet's .254, with the listeners at the interface's host address. The
// guest's frames for a listener's address and port go to it, the rest to
// the interface's stack, which answers ARP and ICMP for the host address
// as before; the programs stack is told the guest's link-layer address from
// the guest's own frames (a gratuitous ARP), as a host learns it on Linux.
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

#define MAX_LISTENERS 16 // per interface

struct timer {
    SlirpTimerId id;
    void *cb_opaque;
    int64_t expire_ms; // -1: not armed
};

struct iface;

// One libslirp instance and its timers.
struct stack {
    Slirp *slirp;
    struct iface *iface;
    struct timer timers[4];
    int ntimers;
};

struct listener {
    uint16_t port; // 0: free slot
    char path[104];
};

struct iface {
    char name[16];
    struct in_addr host, mask;
    struct stack net;        // the interface: the host address, forwards
    struct stack progs;      // the host's programs' listeners (lazily made)
    struct listener listeners[MAX_LISTENERS];
    uint8_t guest_mac[6];    // last told to the programs stack
    struct in_addr guest_ip;
    uint8_t seen_mac[6];     // the guest's, from its last frame (0: none yet)
    int fd;                  // the host's socket, bound at .host-<name>
    struct sockaddr_un vmm;  // the VMM's endpoint, <name>
    ino_t attached;          // the endpoint attached to (its inode), 0: none
};

#define MAX_UFWDS 64

// A UDP forward: a loopback socket of this process and the guest's address.
struct ufwd {
    struct iface *iface;
    int fd;
    struct in_addr guest;
    uint16_t port;
    struct sockaddr_in sender; // the last sender, where the guest's answers go
};

static struct ufwd ufwds[MAX_UFWDS];
static int nufwds;
static uint16_t ip_id;

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
    struct iface *i = ((struct stack *)opaque)->iface;
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
    fprintf(stderr, "netns-slirp %s: guest error: %s\n", ((struct stack *)opaque)->iface->name, msg);
}

static int64_t clock_get_ns(void *opaque) { (void)opaque; return now_ns(); }

static void *timer_new_opaque(SlirpTimerId id, void *cb_opaque, void *opaque) {
    struct stack *st = opaque;
    if (st->ntimers == 4) {
        fprintf(stderr, "netns-slirp: too many timers\n");
        exit(1);
    }
    struct timer *t = &st->timers[st->ntimers++];
    t->id = id;
    t->cb_opaque = cb_opaque;
    t->expire_ms = -1;
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

// Tells the programs stack the guest's link-layer address, as the guest's
// gratuitous ARP would: the stack sends its frames to it.
static void tell_guest(struct iface *i, const uint8_t *mac, struct in_addr ip) {
    if (memcmp(i->guest_mac, mac, 6) == 0 && i->guest_ip.s_addr == ip.s_addr) return;
    uint8_t arp[42] = {0};
    memset(arp, 0xff, 6);
    memcpy(arp + 6, mac, 6);
    arp[12] = 0x08, arp[13] = 0x06;                      // ARP
    arp[14] = 0, arp[15] = 1, arp[16] = 0x08, arp[17] = 0; // Ethernet, IPv4
    arp[18] = 6, arp[19] = 4, arp[20] = 0, arp[21] = 1;    // request
    memcpy(arp + 22, mac, 6);
    memcpy(arp + 28, &ip, 4);
    memcpy(arp + 38, &ip, 4); // gratuitous: sender and target the same
    slirp_input(i->progs.slirp, arp, sizeof arp);
    memcpy(i->guest_mac, mac, 6);
    i->guest_ip = ip;
}

// Whether a frame from the guest is for one of the host's programs: TCP to
// a listener's address and port.
static int for_programs(struct iface *i, const uint8_t *f, ssize_t n) {
    if (!i->progs.slirp || n < 14 + 20 + 4 || f[12] != 0x08 || f[13] != 0x00) return 0;
    const uint8_t *ip = f + 14;
    size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
    if ((ip[0] >> 4) != 4 || ip[9] != 6 || ihl < 20 || (ssize_t)(14 + ihl + 4) > n) return 0;
    struct in_addr dst, src;
    memcpy(&src, ip + 12, 4);
    memcpy(&dst, ip + 16, 4);
    if (dst.s_addr != i->host.s_addr) return 0;
    uint16_t port = (uint16_t)(ip[ihl + 2] << 8 | ip[ihl + 3]);
    for (int k = 0; k < MAX_LISTENERS; k++)
        if (i->listeners[k].port == port) {
            tell_guest(i, f + 6, src);
            return 1;
        }
    return 0;
}

// Passes the VMM's frames on: those from the interface's endpoint only,
// which names itself by its path or, made through the network's directory,
// by its name in it.
static uint16_t csum16(const uint8_t *b, size_t n, uint32_t s) {
    for (size_t k = 0; k + 1 < n; k += 2) s += (uint32_t)(b[k] << 8 | b[k + 1]);
    if (n % 2) s += (uint32_t)(b[n - 1] << 8);
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

// A datagram from a UDP forward's sender to the guest, as IPv4 frames
// (fragmented past a 1500-byte MTU, as the host's stack would).
static void udp_to_guest(struct ufwd *u, const uint8_t *data, size_t len) {
    struct iface *i = u->iface;
    static const uint8_t zero[6];
    if (!i->attached || memcmp(i->seen_mac, zero, 6) == 0 || len > 65507) return; // nobody to send to yet
    static uint8_t udp[65536], f[1514];
    size_t ulen = 8 + len;
    udp[0] = (uint8_t)(ntohs(u->sender.sin_port) >> 8), udp[1] = (uint8_t)ntohs(u->sender.sin_port);
    udp[2] = (uint8_t)(u->port >> 8), udp[3] = (uint8_t)u->port;
    udp[4] = (uint8_t)(ulen >> 8), udp[5] = (uint8_t)ulen, udp[6] = 0, udp[7] = 0;
    memcpy(udp + 8, data, len);
    uint8_t pseudo[12];
    memcpy(pseudo, &i->host, 4);
    memcpy(pseudo + 4, &u->guest, 4);
    pseudo[8] = 0, pseudo[9] = 17, pseudo[10] = (uint8_t)(ulen >> 8), pseudo[11] = (uint8_t)ulen;
    uint32_t s = 0;
    for (int k = 0; k < 12; k += 2) s += (uint32_t)(pseudo[k] << 8 | pseudo[k + 1]);
    uint16_t c = csum16(udp, ulen, s);
    if (c == 0) c = 0xffff;
    udp[6] = (uint8_t)(c >> 8), udp[7] = (uint8_t)c;
    uint16_t id = ip_id++;
    for (size_t off = 0; off < ulen;) {
        size_t chunk = ulen - off > 1480 ? 1480 : ulen - off; // a multiple of 8 but for the last
        int more = off + chunk < ulen;
        memcpy(f, i->seen_mac, 6);
        f[6] = 0x52, f[7] = 0x55; // libslirp's link-layer address of an address of its own
        memcpy(f + 8, &i->host, 4);
        f[12] = 0x08, f[13] = 0x00;
        uint8_t *ip = f + 14;
        size_t tot = 20 + chunk;
        ip[0] = 0x45, ip[1] = 0, ip[2] = (uint8_t)(tot >> 8), ip[3] = (uint8_t)tot;
        ip[4] = (uint8_t)(id >> 8), ip[5] = (uint8_t)id;
        uint16_t fo = (uint16_t)((off / 8) | (more ? 0x2000 : 0));
        ip[6] = (uint8_t)(fo >> 8), ip[7] = (uint8_t)fo;
        ip[8] = 64, ip[9] = 17, ip[10] = 0, ip[11] = 0;
        memcpy(ip + 12, &i->host, 4);
        memcpy(ip + 16, &u->guest, 4);
        uint16_t hc = csum16(ip, 20, 0);
        ip[10] = (uint8_t)(hc >> 8), ip[11] = (uint8_t)hc;
        memcpy(ip + 20, udp + off, chunk);
        if (sendto(i->fd, f, 14 + tot, 0, (struct sockaddr *)&i->vmm, sizeof i->vmm) < 0 &&
            (errno == ECONNREFUSED || errno == ENOENT))
            i->attached = 0;
        off += chunk;
    }
}

// The guest's datagram for a UDP forward's sender (from the forward's
// guest address and port to the host address): to the sender. A fragment is
// not reassembled: the guest's answers are small.
static int udp_from_guest(struct iface *i, const uint8_t *f, ssize_t n) {
    if (n < 14 + 20 + 8 || f[12] != 0x08 || f[13] != 0x00) return 0;
    const uint8_t *ip = f + 14;
    size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
    if ((ip[0] >> 4) != 4 || ip[9] != 17 || ihl < 20 || (ssize_t)(14 + ihl + 8) > n) return 0;
    struct in_addr src, dst;
    memcpy(&src, ip + 12, 4);
    memcpy(&dst, ip + 16, 4);
    if (dst.s_addr != i->host.s_addr || (ip[6] & 0x3f) || ip[7]) return 0;
    const uint8_t *uh = ip + ihl;
    uint16_t sport = (uint16_t)(uh[0] << 8 | uh[1]), dport = (uint16_t)(uh[2] << 8 | uh[3]);
    uint16_t ulen = (uint16_t)(uh[4] << 8 | uh[5]);
    if (ulen < 8 || (ssize_t)(14 + ihl + ulen) > n) return 0;
    for (int k = 0; k < nufwds; k++) {
        struct ufwd *u = &ufwds[k];
        if (u->iface == i && u->guest.s_addr == src.s_addr && u->port == sport && ntohs(u->sender.sin_port) == dport) {
            sendto(u->fd, uh + 8, ulen - 8, 0, (struct sockaddr *)&u->sender, sizeof u->sender);
            return 1;
        }
    }
    return 0;
}

static void drain(struct iface *i) {
    for (;;) {
        struct sockaddr_un from;
        socklen_t flen = sizeof from;
        memset(&from, 0, sizeof from);
        ssize_t n = recvfrom(i->fd, frame, sizeof frame, MSG_DONTWAIT, (struct sockaddr *)&from, &flen);
        if (n < 0) return;
        if (n > 0 && i->net.slirp && (strcmp(from.sun_path, i->vmm.sun_path) == 0 || strcmp(from.sun_path, i->name) == 0)) {
            if (n >= 14 && !(frame[6] & 1)) memcpy(i->seen_mac, frame + 6, 6);
            if (udp_from_guest(i, frame, n))
                continue;
            if (for_programs(i, frame, n))
                slirp_input(i->progs.slirp, frame, (int)n);
            else
                slirp_input(i->net.slirp, frame, (int)n);
        }
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

// The programs stack of an interface, made on its first listener: the
// interface's subnet widened to a /24, its own host address .254 there
// (libslirp forwards a guest's connection to a Unix socket only at another
// address than its own), as restricted as the interface's stack.
static int programs_stack(struct iface *i) {
    if (i->progs.slirp) return 0;
    if (ntohl(i->mask.s_addr) < 0xffffff00u) return EADDRNOTAVAIL; // a subnet wider than /24 has no .254 to spare
    SlirpConfig cfg = {0};
    cfg.version = 6;
    cfg.in_enabled = true;
    cfg.vnetmask.s_addr = htonl(0xffffff00u);
    cfg.vnetwork.s_addr = i->host.s_addr & cfg.vnetmask.s_addr;
    cfg.vhost.s_addr = cfg.vnetwork.s_addr | htonl(254);
    if (cfg.vhost.s_addr == i->host.s_addr) cfg.vhost.s_addr = cfg.vnetwork.s_addr | htonl(253);
    cfg.vnameserver = cfg.vhost;
    cfg.vdhcp_start.s_addr = cfg.vnetwork.s_addr | htonl(200);
    cfg.disable_dns = true;
    cfg.disable_dhcp = true;
    cfg.restricted = 1;
    cfg.disable_host_loopback = true;
    i->progs.iface = i;
    i->progs.slirp = slirp_new(&cfg, &callbacks, &i->progs);
    return i->progs.slirp ? 0 : EINVAL;
}

// Whether a program accepts at the Unix socket `path`.
static int accepting(const char *path) {
    struct sockaddr_un u = {.sun_len = sizeof u, .sun_family = AF_UNIX};
    snprintf(u.sun_path, sizeof u.sun_path, "%s", path);
    int probe = socket(AF_UNIX, SOCK_STREAM, 0);
    int ok = connect(probe, (struct sockaddr *)&u, sizeof u) == 0;
    close(probe);
    return ok;
}

static void unlisten(struct iface *i, uint16_t port) {
    for (int k = 0; k < MAX_LISTENERS; k++)
        if (i->listeners[k].port == port) {
            struct in_addr at = i->host;
            slirp_remove_guestfwd(i->progs.slirp, at, port);
            i->listeners[k].port = 0;
        }
}

// A listener at the interface's host address and `port`: the guest's
// connections there go to the Unix socket `path`. One that still accepts
// keeps the port (EADDRINUSE, as a second bind on Linux); a gone one's port
// is taken over.
static int listen_at(struct iface *i, uint16_t port, const char *path) {
    int e = programs_stack(i);
    if (e) return e;
    for (int k = 0; k < MAX_LISTENERS; k++)
        if (i->listeners[k].port == port) {
            if (accepting(i->listeners[k].path)) return EADDRINUSE;
            unlisten(i, port);
        }
    for (int k = 0; k < MAX_LISTENERS; k++)
        if (i->listeners[k].port == 0) {
            struct in_addr at = i->host;
            if (slirp_add_unix(i->progs.slirp, path, &at, port) != 0) return EADDRINUSE;
            i->listeners[k].port = port;
            snprintf(i->listeners[k].path, sizeof i->listeners[k].path, "%s", path);
            return 0;
        }
    return ENOSPC;
}

static void request(int conn, char *line) {
    char verb[16], a[64], b[64], c[128];
    int n = sscanf(line, "%15s %63s %63s %127s", verb, a, b, c);
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
        i->net.iface = i;
        i->net.slirp = slirp_new(&cfg, &callbacks, &i->net);
        if (!i->net.slirp) {
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
                if (ifaces[k].net.slirp &&
                    (g.sin_addr.s_addr & ifaces[k].mask.s_addr) == (ifaces[k].host.s_addr & ifaces[k].mask.s_addr))
                    i = &ifaces[k];
        if (!i) {
            reply(conn, ENETUNREACH, NULL);
            return;
        }
        struct sockaddr_un h = {.sun_family = AF_UNIX};
        snprintf(h.sun_path, sizeof h.sun_path, "%s/%s-%s", dir, a, b);
        if (access(h.sun_path, F_OK) != 0 &&
            slirp_add_hostxfwd(i->net.slirp, (struct sockaddr *)&h, sizeof h, (struct sockaddr *)&g, sizeof g, 0) != 0) {
            reply(conn, errno ? errno : EINVAL, NULL);
            return;
        }
        reply(conn, 0, h.sun_path);
    } else if (n == 4 && strcmp(verb, "gfwd") == 0) {
        struct in_addr at;
        int port = atoi(b);
        if (inet_pton(AF_INET, a, &at) != 1 || port < 1 || port > 65535 || strlen(c) >= sizeof ifaces[0].listeners[0].path) {
            reply(conn, EINVAL, NULL);
            return;
        }
        int e = EADDRNOTAVAIL;
        for (int k = 0; k < nifaces; k++)
            if (ifaces[k].net.slirp && (at.s_addr == INADDR_ANY || at.s_addr == ifaces[k].host.s_addr)) {
                e = listen_at(&ifaces[k], (uint16_t)port, c);
                if (e) break;
            }
        reply(conn, e, NULL);
    } else if (n == 3 && strcmp(verb, "ungfwd") == 0) {
        struct in_addr at;
        int port = atoi(b);
        if (inet_pton(AF_INET, a, &at) != 1 || port < 1 || port > 65535) {
            reply(conn, EINVAL, NULL);
            return;
        }
        for (int k = 0; k < nifaces; k++)
            if (ifaces[k].net.slirp && (at.s_addr == INADDR_ANY || at.s_addr == ifaces[k].host.s_addr))
                unlisten(&ifaces[k], (uint16_t)port);
        reply(conn, 0, NULL);
    } else if (n == 3 && strcmp(verb, "ufwd") == 0) {
        struct sockaddr_in g = {.sin_len = sizeof g, .sin_family = AF_INET, .sin_port = htons(atoi(b))};
        struct iface *i = NULL;
        if (inet_pton(AF_INET, a, &g.sin_addr) == 1)
            for (int k = 0; k < nifaces; k++)
                if (ifaces[k].net.slirp &&
                    (g.sin_addr.s_addr & ifaces[k].mask.s_addr) == (ifaces[k].host.s_addr & ifaces[k].mask.s_addr))
                    i = &ifaces[k];
        if (!i) {
            reply(conn, ENETUNREACH, NULL);
            return;
        }
        uint16_t port = ntohs(g.sin_port);
        for (int k = 0; k < nufwds; k++)
            if (ufwds[k].iface == i && ufwds[k].guest.s_addr == g.sin_addr.s_addr && ufwds[k].port == port) {
                struct sockaddr_in h;
                socklen_t hl = sizeof h;
                getsockname(ufwds[k].fd, (struct sockaddr *)&h, &hl);
                char text[32];
                snprintf(text, sizeof text, "127.0.0.1:%d", ntohs(h.sin_port));
                reply(conn, 0, text);
                return;
            }
        if (nufwds == MAX_UFWDS) {
            reply(conn, ENOSPC, NULL);
            return;
        }
        struct sockaddr_in h = {.sin_len = sizeof h, .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        socklen_t hl = sizeof h;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        int size = 4 << 20;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof size);
        if (fd < 0 || bind(fd, (struct sockaddr *)&h, sizeof h) != 0 || getsockname(fd, (struct sockaddr *)&h, &hl) != 0) {
            int e = errno;
            if (fd >= 0) close(fd);
            reply(conn, e, NULL);
            return;
        }
        fcntl(fd, F_SETFL, O_NONBLOCK);
        ufwds[nufwds++] = (struct ufwd){.iface = i, .fd = fd, .guest = g.sin_addr, .port = port};
        char text[32];
        snprintf(text, sizeof text, "127.0.0.1:%d", ntohs(h.sin_port));
        reply(conn, 0, text);
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
        int uf0 = npfds;
        for (int k = 0; k < nufwds; k++) add_poll(ufwds[k].fd, SLIRP_POLL_IN, NULL);
        int if0 = npfds;
        for (int k = 0; k < nifaces; k++) add_poll(ifaces[k].fd, SLIRP_POLL_IN, NULL);
        int64_t now_ms = now_ns() / 1000000;
        for (int k = 0; k < 2 * nifaces; k++) {
            struct stack *st = k % 2 ? &ifaces[k / 2].progs : &ifaces[k / 2].net;
            if (!st->slirp) continue;
            slirp_pollfds_fill_socket(st->slirp, &timeout, add_poll, NULL);
            for (int t = 0; t < st->ntimers; t++) {
                int64_t e = st->timers[t].expire_ms;
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
        for (int k = 0; k < 2 * nifaces; k++) {
            struct stack *st = k % 2 ? &ifaces[k / 2].progs : &ifaces[k / 2].net;
            if (st->slirp) slirp_pollfds_poll(st->slirp, r < 0, get_revents, NULL);
        }
        now_ms = now_ns() / 1000000;
        for (int k = 0; k < 2 * nifaces; k++) {
            struct stack *st = k % 2 ? &ifaces[k / 2].progs : &ifaces[k / 2].net;
            for (int t = 0; t < st->ntimers; t++) {
                struct timer *tm = &st->timers[t];
                if (tm->expire_ms >= 0 && tm->expire_ms <= now_ms) {
                    tm->expire_ms = -1;
                    slirp_handle_timer(st->slirp, tm->id, tm->cb_opaque);
                }
            }
        }
        for (int k = 0; k < nifaces; k++) {
            struct iface *i = &ifaces[k];
            if (pfds[if0 + k].revents) drain(i);
        }
        for (int k = 0; k < nufwds; k++) {
            if (!pfds[uf0 + k].revents) continue;
            for (;;) {
                struct sockaddr_in from;
                socklen_t fl = sizeof from;
                ssize_t got = recvfrom(ufwds[k].fd, frame, sizeof frame, 0, (struct sockaddr *)&from, &fl);
                if (got < 0) break;
                ufwds[k].sender = from;
                udp_to_guest(&ufwds[k], frame, (size_t)got);
            }
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
