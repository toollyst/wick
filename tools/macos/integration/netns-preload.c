// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0
//
// A host program "inside" a test's network: what `ip netns exec <ns> <prog>`
// gives upstream's tests on Linux, a program whose IPv4 sockets are the
// namespace's (its TAPs' addresses and subnets, nothing else). macOS has no
// network namespaces; a test's network is netns-slirp's user-space stack
// (tools/macos/integration/netns-slirp.c). tools/macos/integration/bin/ip
// runs the program with this library inserted (DYLD_INSERT_LIBRARIES;
// WICK_NETNS_CTL names the network's control socket, WICK_NETNS_FWD the
// directory for its sockets), and the program's IPv4 sockets go into that
// network:
//
// - TCP bind() at an interface's host address (or 0.0.0.0, every
//   interface's) and port: a listener there (netns-slirp `gfwd`); the
//   socket becomes a Unix stream socket the guest's connections are
//   forwarded to, and accept()/getsockname() show the IPv4 addresses
//   (the peer's is not known: 0.0.0.0:0);
// - TCP connect() to an address on an interface's subnet: netns-slirp's
//   forward to it (`fwd`), a Unix stream socket here;
// - UDP connect()/sendto() to an address on an interface's subnet: a UDP
//   forward (`ufwd`) at a loopback port, to which the datagrams go; what
//   comes back from it shows the guest's address;
// - 127.0.0.0/8: the host's own loopback (a namespace's lo on Linux);
// - any other IPv4 destination: ENETUNREACH, and a bind at an address that
//   is not the network's: EADDRNOTAVAIL, as in a namespace.
//
// A TCP option (IPPROTO_TCP) on a forwarded TCP socket is accepted and not
// applied: the program's end is a Unix socket, and the connection's TCP is
// netns-slirp's (the first one is reported on stderr). A UDP socket bound
// at a network address (a UDP server for the guest) is not provided: such a
// bind fails EADDRNOTAVAIL and says so.
//
// Build: cc -dynamiclib -o netns-preload.dylib netns-preload.c
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define DYLD_INTERPOSE(_replacement, _replacee)                                              \
    __attribute__((used)) static struct {                                                    \
        const void *replacement;                                                             \
        const void *replacee;                                                                \
    } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = {             \
        (const void *)(unsigned long)&_replacement, (const void *)(unsigned long)&_replacee};

#define MAX_FD 8192
#define MAX_UFWD 64

enum kind { NONE, LISTENER, CONNECTED, ACCEPTED, UDP };

struct ent {
    enum kind kind;
    struct sockaddr_in local, peer;
    char path[104]; // a listener's Unix socket
    int nodelay;
};

struct ufwd {
    struct sockaddr_in guest, loop; // guest <-> 127.0.0.1:port
};

static struct ent tab[MAX_FD];
static struct ufwd ufwds[MAX_UFWD];
static int nufwds;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void say(const char *fmt, const char *a) {
    fprintf(stderr, "netns-preload (wick, macOS): ");
    fprintf(stderr, fmt, a);
    fputc('\n', stderr);
}

// One request to the network's host side: its errno; its text in `text`.
static int request(const char *line, char *text, size_t textlen) {
    const char *ctl = getenv("WICK_NETNS_CTL");
    if (!ctl) {
        say("%s: WICK_NETNS_CTL is not set (run through tools/macos/integration/bin/ip)", line);
        return ENETUNREACH;
    }
    struct sockaddr_un a = {.sun_len = sizeof a, .sun_family = AF_UNIX};
    if (strlen(ctl) >= sizeof a.sun_path) return ENAMETOOLONG;
    strcpy(a.sun_path, ctl);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return errno;
    int err = EIO;
    if (connect(s, (struct sockaddr *)&a, sizeof a) == 0) {
        char buf[256];
        int n = snprintf(buf, sizeof buf, "%s\n", line);
        uint8_t head[6];
        if (write(s, buf, (size_t)n) == n && read(s, head, 6) == 6) {
            int32_t e;
            uint16_t len;
            memcpy(&e, head, 4);
            memcpy(&len, head + 4, 2);
            size_t got = 0;
            if (text) text[0] = 0;
            while (got < len) {
                char c;
                if (read(s, &c, 1) != 1) break;
                if (text && got + 1 < textlen) text[got] = c, text[got + 1] = 0;
                got++;
            }
            err = got == len ? e : EIO;
        }
    }
    close(s);
    return err;
}

static int sock_type(int fd) {
    int t = 0;
    socklen_t l = sizeof t;
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &t, &l) == 0 ? t : -1;
}

static int is_loopback(const struct sockaddr_in *a) { return (ntohl(a->sin_addr.s_addr) >> 24) == 127; }

// Puts a new socket of the network in fd's place, with fd's flags.
static int replace(int fd, int with) {
    int fl = fcntl(fd, F_GETFL), fdfl = fcntl(fd, F_GETFD);
    if (dup2(with, fd) < 0) {
        int e = errno;
        close(with);
        return e;
    }
    close(with);
    if (fl >= 0) fcntl(fd, F_SETFL, fl);
    if (fdfl >= 0) fcntl(fd, F_SETFD, fdfl);
    return 0;
}

static void set_inet(struct sockaddr *out, socklen_t *outlen, const struct sockaddr_in *in) {
    if (!out || !outlen) return;
    socklen_t n = *outlen < sizeof *in ? *outlen : (socklen_t)sizeof *in;
    memcpy(out, in, n);
    *outlen = sizeof *in;
}

static struct sockaddr_in inet(struct in_addr a, uint16_t port) {
    struct sockaddr_in s = {.sin_len = sizeof s, .sin_family = AF_INET, .sin_port = htons(port), .sin_addr = a};
    return s;
}

// The loopback port of the UDP forward to `guest`: 0 and errno on failure.
static int udp_forward(const struct sockaddr_in *guest, struct sockaddr_in *loop) {
    pthread_mutex_lock(&lock);
    for (int k = 0; k < nufwds; k++)
        if (ufwds[k].guest.sin_addr.s_addr == guest->sin_addr.s_addr && ufwds[k].guest.sin_port == guest->sin_port) {
            *loop = ufwds[k].loop;
            pthread_mutex_unlock(&lock);
            return 0;
        }
    pthread_mutex_unlock(&lock);
    char line[96], text[64], ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &guest->sin_addr, ip, sizeof ip);
    snprintf(line, sizeof line, "ufwd %s %d", ip, ntohs(guest->sin_port));
    int e = request(line, text, sizeof text);
    if (e) return e;
    char *colon = strrchr(text, ':');
    if (!colon) return EIO;
    *colon = 0;
    struct in_addr la;
    if (inet_pton(AF_INET, text, &la) != 1) return EIO;
    *loop = inet(la, (uint16_t)atoi(colon + 1));
    pthread_mutex_lock(&lock);
    if (nufwds < MAX_UFWD) ufwds[nufwds++] = (struct ufwd){*guest, *loop};
    pthread_mutex_unlock(&lock);
    return 0;
}

// The guest's address of a datagram from a UDP forward's loopback port.
static void from_forward(struct sockaddr *src, socklen_t *srclen) {
    if (!src || !srclen || *srclen < sizeof(struct sockaddr_in) || src->sa_family != AF_INET) return;
    struct sockaddr_in *s = (struct sockaddr_in *)src;
    pthread_mutex_lock(&lock);
    for (int k = 0; k < nufwds; k++)
        if (ufwds[k].loop.sin_addr.s_addr == s->sin_addr.s_addr && ufwds[k].loop.sin_port == s->sin_port) {
            *s = ufwds[k].guest;
            break;
        }
    pthread_mutex_unlock(&lock);
}

static int w_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    if (!addr || addr->sa_family != AF_INET || len < sizeof(struct sockaddr_in) || fd < 0 || fd >= MAX_FD)
        return bind(fd, addr, len);
    struct sockaddr_in a = *(const struct sockaddr_in *)addr;
    if (is_loopback(&a)) return bind(fd, addr, len);
    int type = sock_type(fd);
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a.sin_addr, ip, sizeof ip);
    if (type == SOCK_DGRAM) {
        if (a.sin_addr.s_addr == INADDR_ANY && a.sin_port == 0) return bind(fd, addr, len); // a client's
        say("UDP socket bound at %s in the network: a UDP server for the guest is not provided", ip);
        errno = EADDRNOTAVAIL;
        return -1;
    }
    if (type != SOCK_STREAM) return bind(fd, addr, len);
    const char *dir = getenv("WICK_NETNS_FWD");
    if (!dir) {
        say("bind at %s: WICK_NETNS_FWD is not set (run through tools/macos/integration/bin/ip)", ip);
        errno = EADDRNOTAVAIL;
        return -1;
    }
    uint16_t port = ntohs(a.sin_port);
    for (int tries = 0; tries < 64; tries++) {
        uint16_t p = port ? port : (uint16_t)(32768 + arc4random_uniform(28232));
        struct sockaddr_un u = {.sun_len = sizeof u, .sun_family = AF_UNIX};
        if ((size_t)snprintf(u.sun_path, sizeof u.sun_path, "%s/l-%d-%d", dir, getpid(), p) >= sizeof u.sun_path) {
            errno = ENAMETOOLONG;
            return -1;
        }
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s < 0) return -1;
        unlink(u.sun_path);
        if (bind(s, (struct sockaddr *)&u, sizeof u) != 0) {
            int e = errno;
            close(s);
            errno = e;
            return -1;
        }
        char line[200];
        snprintf(line, sizeof line, "gfwd %s %d %s", ip, p, u.sun_path);
        int e = request(line, NULL, 0);
        if (e == EADDRINUSE && !port) {
            close(s);
            unlink(u.sun_path);
            continue;
        }
        if (e) {
            close(s);
            unlink(u.sun_path);
            errno = e;
            return -1;
        }
        if ((e = replace(fd, s))) { // s is closed
            unlink(u.sun_path);
            errno = e;
            return -1;
        }
        pthread_mutex_lock(&lock);
        tab[fd] = (struct ent){.kind = LISTENER, .local = inet(a.sin_addr, p)};
        snprintf(tab[fd].path, sizeof tab[fd].path, "%s", u.sun_path);
        pthread_mutex_unlock(&lock);
        return 0;
    }
    errno = EADDRINUSE;
    return -1;
}

static int w_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (!addr || addr->sa_family != AF_INET || len < sizeof(struct sockaddr_in) || fd < 0 || fd >= MAX_FD)
        return connect(fd, addr, len);
    struct sockaddr_in a = *(const struct sockaddr_in *)addr;
    if (is_loopback(&a)) return connect(fd, addr, len);
    int type = sock_type(fd);
    if (type == SOCK_DGRAM) {
        struct sockaddr_in loop;
        int e = udp_forward(&a, &loop);
        if (e) {
            errno = e;
            return -1;
        }
        int r = connect(fd, (struct sockaddr *)&loop, sizeof loop);
        if (r == 0) {
            pthread_mutex_lock(&lock);
            tab[fd] = (struct ent){.kind = UDP, .peer = a};
            pthread_mutex_unlock(&lock);
        }
        return r;
    }
    if (type != SOCK_STREAM) return connect(fd, addr, len);
    char line[96], path[128], ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a.sin_addr, ip, sizeof ip);
    snprintf(line, sizeof line, "fwd %s %d", ip, ntohs(a.sin_port));
    int e = request(line, path, sizeof path);
    if (e) {
        errno = e;
        return -1;
    }
    struct sockaddr_un u = {.sun_len = sizeof u, .sun_family = AF_UNIX};
    snprintf(u.sun_path, sizeof u.sun_path, "%s", path);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;
    if ((e = replace(fd, s))) {
        errno = e;
        return -1;
    }
    pthread_mutex_lock(&lock);
    tab[fd] = (struct ent){.kind = CONNECTED, .peer = a, .local = inet((struct in_addr){0}, 0)};
    pthread_mutex_unlock(&lock);
    return connect(fd, (struct sockaddr *)&u, sizeof u);
}

static int w_accept(int fd, struct sockaddr *addr, socklen_t *len) {
    if (fd < 0 || fd >= MAX_FD || tab[fd].kind != LISTENER) return accept(fd, addr, len);
    struct sockaddr_un u;
    socklen_t ul = sizeof u;
    int c = accept(fd, (struct sockaddr *)&u, &ul);
    if (c < 0) return c;
    struct sockaddr_in unknown = inet((struct in_addr){0}, 0);
    set_inet(addr, len, &unknown);
    if (c < MAX_FD) {
        pthread_mutex_lock(&lock);
        tab[c] = (struct ent){.kind = ACCEPTED, .local = tab[fd].local, .peer = unknown};
        pthread_mutex_unlock(&lock);
    }
    return c;
}

static int w_getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
    if (fd >= 0 && fd < MAX_FD && (tab[fd].kind == LISTENER || tab[fd].kind == CONNECTED || tab[fd].kind == ACCEPTED)) {
        set_inet(addr, len, &tab[fd].local);
        return 0;
    }
    return getsockname(fd, addr, len);
}

static int w_getpeername(int fd, struct sockaddr *addr, socklen_t *len) {
    if (fd >= 0 && fd < MAX_FD && (tab[fd].kind == CONNECTED || tab[fd].kind == ACCEPTED || tab[fd].kind == UDP)) {
        set_inet(addr, len, &tab[fd].peer);
        return 0;
    }
    return getpeername(fd, addr, len);
}

static ssize_t w_sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *to, socklen_t tolen) {
    if (to && to->sa_family == AF_INET && tolen >= sizeof(struct sockaddr_in) &&
        !is_loopback((const struct sockaddr_in *)to) && sock_type(fd) == SOCK_DGRAM) {
        struct sockaddr_in loop;
        int e = udp_forward((const struct sockaddr_in *)to, &loop);
        if (e) {
            errno = e;
            return -1;
        }
        return sendto(fd, buf, n, flags, (struct sockaddr *)&loop, sizeof loop);
    }
    return sendto(fd, buf, n, flags, to, tolen);
}

static ssize_t w_recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *from, socklen_t *fromlen) {
    ssize_t r = recvfrom(fd, buf, n, flags, from, fromlen);
    if (r >= 0) from_forward(from, fromlen);
    return r;
}

static ssize_t w_sendmsg(int fd, const struct msghdr *msg, int flags) {
    const struct sockaddr *to = msg ? msg->msg_name : NULL;
    if (to && to->sa_family == AF_INET && msg->msg_namelen >= sizeof(struct sockaddr_in) &&
        !is_loopback((const struct sockaddr_in *)to) && sock_type(fd) == SOCK_DGRAM) {
        struct sockaddr_in loop;
        int e = udp_forward((const struct sockaddr_in *)to, &loop);
        if (e) {
            errno = e;
            return -1;
        }
        struct msghdr m = *msg;
        m.msg_name = &loop;
        m.msg_namelen = sizeof loop;
        return sendmsg(fd, &m, flags);
    }
    return sendmsg(fd, msg, flags);
}

static ssize_t w_recvmsg(int fd, struct msghdr *msg, int flags) {
    ssize_t r = recvmsg(fd, msg, flags);
    if (r >= 0 && msg && msg->msg_name) from_forward(msg->msg_name, &msg->msg_namelen);
    return r;
}

static int tcp_option_warned;

static int w_setsockopt(int fd, int level, int name, const void *val, socklen_t len) {
    if (level == IPPROTO_TCP && fd >= 0 && fd < MAX_FD &&
        (tab[fd].kind == LISTENER || tab[fd].kind == CONNECTED || tab[fd].kind == ACCEPTED)) {
        if (name == TCP_NODELAY && val && len >= sizeof(int)) tab[fd].nodelay = *(const int *)val;
        if (!tcp_option_warned++)
            say("%s", "a TCP option on a forwarded connection is not applied: its TCP is netns-slirp's");
        return 0;
    }
    return setsockopt(fd, level, name, val, len);
}

static int w_getsockopt(int fd, int level, int name, void *val, socklen_t *len) {
    if (level == IPPROTO_TCP && fd >= 0 && fd < MAX_FD &&
        (tab[fd].kind == LISTENER || tab[fd].kind == CONNECTED || tab[fd].kind == ACCEPTED)) {
        if (!val || !len || *len < sizeof(int)) {
            errno = EINVAL;
            return -1;
        }
        if (name == TCP_NODELAY) {
            *(int *)val = tab[fd].nodelay;
        } else if (name == TCP_MAXSEG) {
            *(int *)val = 1460; // the guest's MSS on a 1500-byte link (slirp's own is the same)
        } else {
            errno = ENOPROTOOPT;
            return -1;
        }
        *len = sizeof(int);
        return 0;
    }
    return getsockopt(fd, level, name, val, len);
}

static int w_close(int fd) {
    if (fd >= 0 && fd < MAX_FD && tab[fd].kind != NONE) {
        pthread_mutex_lock(&lock);
        struct ent e = tab[fd];
        tab[fd].kind = NONE;
        pthread_mutex_unlock(&lock);
        if (e.kind == LISTENER) {
            char line[96], ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &e.local.sin_addr, ip, sizeof ip);
            snprintf(line, sizeof line, "ungfwd %s %d", ip, ntohs(e.local.sin_port));
            request(line, NULL, 0);
            unlink(e.path);
        }
    }
    return close(fd);
}

DYLD_INTERPOSE(w_bind, bind)
DYLD_INTERPOSE(w_connect, connect)
DYLD_INTERPOSE(w_accept, accept)
DYLD_INTERPOSE(w_getsockname, getsockname)
DYLD_INTERPOSE(w_getpeername, getpeername)
DYLD_INTERPOSE(w_sendto, sendto)
DYLD_INTERPOSE(w_recvfrom, recvfrom)
DYLD_INTERPOSE(w_sendmsg, sendmsg)
DYLD_INTERPOSE(w_recvmsg, recvmsg)
DYLD_INTERPOSE(w_setsockopt, setsockopt)
DYLD_INTERPOSE(w_getsockopt, getsockopt)
DYLD_INTERPOSE(w_close, close)
