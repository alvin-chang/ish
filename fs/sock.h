/**
 * iSH - Socket Implementation
 *
 * This header defines the socket interface for the Linux emulation layer.
 * It implements socket-related system calls and provides translation between
 * Linux socket structures/constants and host platform equivalents.
 */

#ifndef SYS_SOCK_H
#define SYS_SOCK_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "kernel/errno.h"
#include "fs/fd.h"
#include "misc.h"
#include "debug.h"

/**
 * Multiplexed socket call entry point (for Linux socketcall system call)
 *
 * @param call_num Call number indicating which socket operation to perform
 * @param args_addr Address of argument structure
 * @return Result of the socket operation or negative error code
 */
int_t sys_socketcall(dword_t call_num, addr_t args_addr);

/**
 * Create a new socket
 *
 * @param domain Socket domain (PF_INET, PF_LOCAL, etc.)
 * @param type Socket type (SOCK_STREAM, SOCK_DGRAM, etc.)
 * @param protocol Protocol to use
 * @return New socket file descriptor or negative error code
 */
int_t sys_socket(dword_t domain, dword_t type, dword_t protocol);

/**
 * Bind a socket to an address
 *
 * @param sock_fd Socket file descriptor
 * @param sockaddr_addr Address to bind to
 * @param sockaddr_len Length of address structure
 * @return 0 on success or negative error code
 */
int_t sys_bind(fd_t sock_fd, addr_t sockaddr_addr, uint_t sockaddr_len);

/**
 * Connect a socket to a remote address
 *
 * @param sock_fd Socket file descriptor
 * @param sockaddr_addr Address to connect to
 * @param sockaddr_len Length of address structure
 * @return 0 on success or negative error code
 */
int_t sys_connect(fd_t sock_fd, addr_t sockaddr_addr, uint_t sockaddr_len);

/**
 * Mark a socket as a passive socket for accepting connections
 *
 * @param sock_fd Socket file descriptor
 * @param backlog Maximum queue length for pending connections
 * @return 0 on success or negative error code
 */
int_t sys_listen(fd_t sock_fd, int_t backlog);

/**
 * Accept a connection on a socket
 *
 * @param sock_fd Socket file descriptor
 * @param sockaddr_addr Address to store client address (can be NULL)
 * @param sockaddr_len_addr Pointer to store address length
 * @return New socket file descriptor for the accepted connection or negative error code
 */
int_t sys_accept(fd_t sock_fd, addr_t sockaddr_addr, addr_t sockaddr_len_addr);

/**
 * Get the local address of a socket
 *
 * @param sock_fd Socket file descriptor
 * @param sockaddr_addr Address to store socket address
 * @param sockaddr_len_addr Pointer to store address length
 * @return 0 on success or negative error code
 */
int_t sys_getsockname(fd_t sock_fd, addr_t sockaddr_addr, addr_t sockaddr_len_addr);

/**
 * Get the remote address of a connected socket
 *
 * @param sock_fd Socket file descriptor
 * @param sockaddr_addr Address to store peer address
 * @param sockaddr_len_addr Pointer to store address length
 * @return 0 on success or negative error code
 */
int_t sys_getpeername(fd_t sock_fd, addr_t sockaddr_addr, addr_t sockaddr_len_addr);

/**
 * Create a pair of connected sockets
 *
 * @param domain Socket domain
 * @param type Socket type
 * @param protocol Protocol to use
 * @param sockets_addr Array to store the two socket file descriptors
 * @return 0 on success or negative error code
 */
int_t sys_socketpair(dword_t domain, dword_t type, dword_t protocol, addr_t sockets_addr);

/**
 * Send data on a socket to a specific address
 *
 * @param sock_fd Socket file descriptor
 * @param buffer_addr Data buffer to send
 * @param len Length of data to send
 * @param flags Send flags
 * @param sockaddr_addr Destination address (can be NULL for connected sockets)
 * @param sockaddr_len Length of destination address
 * @return Number of bytes sent or negative error code
 */
int_t sys_sendto(fd_t sock_fd, addr_t buffer_addr, dword_t len, dword_t flags, addr_t sockaddr_addr, dword_t sockaddr_len);

/**
 * Receive data from a socket, optionally getting the source address
 *
 * @param sock_fd Socket file descriptor
 * @param buffer_addr Buffer to store received data
 * @param len Maximum length of data to receive
 * @param flags Receive flags
 * @param sockaddr_addr Address to store source address (can be NULL)
 * @param sockaddr_len_addr Pointer to store address length
 * @return Number of bytes received or negative error code
 */
int_t sys_recvfrom(fd_t sock_fd, addr_t buffer_addr, dword_t len, dword_t flags, addr_t sockaddr_addr, addr_t sockaddr_len_addr);

/**
 * Shut down part of a full-duplex connection
 *
 * @param sock_fd Socket file descriptor
 * @param how How to shut down (read, write, or both)
 * @return 0 on success or negative error code
 */
int_t sys_shutdown(fd_t sock_fd, dword_t how);

/**
 * Set socket options
 *
 * @param sock_fd Socket file descriptor
 * @param level Protocol level
 * @param option Option name
 * @param value_addr Option value
 * @param value_len Length of option value
 * @return 0 on success or negative error code
 */
int_t sys_setsockopt(fd_t sock_fd, dword_t level, dword_t option, addr_t value_addr, dword_t value_len);

/**
 * Get socket options
 *
 * @param sock_fd Socket file descriptor
 * @param level Protocol level
 * @param option Option name
 * @param value_addr Buffer to store option value
 * @param len_addr Pointer to length of buffer/value
 * @return 0 on success or negative error code
 */
int_t sys_getsockopt(fd_t sock_fd, dword_t level, dword_t option, addr_t value_addr, dword_t len_addr);

/**
 * Send a message on a socket (with control data)
 *
 * @param sock_fd Socket file descriptor
 * @param msghdr_addr Message header structure
 * @param flags Send flags
 * @return Number of bytes sent or negative error code
 */
int_t sys_sendmsg(fd_t sock_fd, addr_t msghdr_addr, int_t flags);

/**
 * Receive a message from a socket (with control data)
 *
 * @param sock_fd Socket file descriptor
 * @param msghdr_addr Message header structure
 * @param flags Receive flags
 * @return Number of bytes received or negative error code
 */
int_t sys_recvmsg(fd_t sock_fd, addr_t msghdr_addr, int_t flags);

/**
 * Send multiple messages on a socket
 *
 * @param sock_fd Socket file descriptor
 * @param msgvec_addr Array of message header structures
 * @param msgvec_len Number of messages to send
 * @param flags Send flags
 * @return Number of messages sent or negative error code
 */
int_t sys_sendmmsg(fd_t sock_fd, addr_t msgvec_addr, uint_t msgvec_len, int_t flags);

/** Maximum size for sockaddr data field */
#define SOCKADDR_DATA_MAX 108

/**
 * Socket address structure (emulated Linux version)
 * Represents a basic socket address with family and data
 */
struct sockaddr_ {
    /** Address family (AF_INET, AF_UNIX, etc.) */
    uint16_t family;
    
    /** Address data (specific format depends on family) */
    char data[14];
};

/**
 * Extended socket address structure for larger addresses
 * Used for unix domain sockets with longer paths
 */
struct sockaddr_max_ {
    /** Address family (AF_INET, AF_UNIX, etc.) */
    uint16_t family;
    
    /** Extended address data field */
    char data[SOCKADDR_DATA_MAX];
};

/**
 * Get the appropriate size of a sockaddr structure based on its family
 *
 * @param p Pointer to sockaddr structure
 * @return Size of the structure in bytes
 */
size_t sockaddr_size(void *p);

/**
 * Convert an emulated Linux sockaddr to a host platform sockaddr
 * 
 * @param p Pointer to Linux sockaddr structure
 * @return Host platform sockaddr (allocated with malloc)
 */
struct sockaddr *sockaddr_to_real(void *p);

/**
 * Message header structure (emulated Linux version)
 * Used for sendmsg/recvmsg calls
 */
struct msghdr_ {
    /** Optional address pointer */
    addr_t msg_name;
    
    /** Length of address */
    uint_t msg_namelen;
    
    /** I/O vector array for scatter/gather I/O */
    addr_t msg_iov;
    
    /** Number of elements in I/O vector */
    uint_t msg_iovlen;
    
    /** Ancillary data (control information) */
    addr_t msg_control;
    
    /** Length of ancillary data */
    uint_t msg_controllen;
    
    /** Flags on received message */
    int_t msg_flags;
};

/**
 * Control message header structure (emulated Linux version)
 * Used for passing file descriptors and other control information
 */
struct cmsghdr_ {
    /** Length of control message including header */
    dword_t len;
    
    /** Originating protocol level */
    int_t level;
    
    /** Protocol-specific type */
    int_t type;
    
    /** Ancillary data (variable length) */
    uint8_t data[];
};

/** "Send/receive credentials" socket option */
#define SCM_RIGHTS_ 1

/** Calculate actual length of control message with proper alignment */
#define CMSG_LEN_(cmsg) (((cmsg)->len + sizeof(dword_t) - 1) & ~(dword_t)(sizeof(dword_t) - 1))

/** Get pointer to next control message in buffer */
#define CMSG_NEXT_(cmsg) ((uint8_t *)(cmsg) + CMSG_LEN_(cmsg))

/** Get pointer to next valid control message, or NULL if at end */
#define CMSG_NXTHDR_(cmsg, mhdr_end) ((cmsg)->len < sizeof (struct cmsghdr_) || \
        CMSG_LEN_(cmsg) + sizeof(struct cmsghdr_) >= (size_t) (mhdr_end - (uint8_t *)(cmsg)) \
        ? NULL : (struct cmsghdr_ *)CMSG_NEXT_(cmsg))

/**
 * Socket control message for file descriptor passing
 * Used with SCM_RIGHTS to pass file descriptors between processes
 */
struct scm {
    /** List entry for the message queue */
    struct list queue;
    
    /** Number of file descriptors in the message */
    unsigned num_fds;
    
    /** Array of file descriptors */
    struct fd *fds[];
};

/* Socket domain/family constants */
/** Local (Unix domain) sockets */
#define PF_LOCAL_ 1
/** IPv4 Internet protocols */
#define PF_INET_ 2
/** IPv6 Internet protocols */
#define PF_INET6_ 10
/** Address family aliases for protocol families */
#define AF_LOCAL_ PF_LOCAL_
#define AF_INET_ PF_INET_
#define AF_INET6_ PF_INET6_

/**
 * Convert emulated Linux socket family to host platform socket family
 *
 * @param fake Linux socket family
 * @return Host platform socket family or -1 if unsupported
 */
static inline int sock_family_to_real(int fake) {
    switch (fake) {
        case PF_LOCAL_: return PF_LOCAL;
        case PF_INET_: return PF_INET;
        case PF_INET6_: return PF_INET6;
    }
    return -1;
}

/**
 * Convert host platform socket family to emulated Linux socket family
 *
 * @param real Host platform socket family
 * @return Linux socket family or -1 if unsupported
 */
static inline int sock_family_from_real(int real) {
    switch (real) {
        case PF_LOCAL: return PF_LOCAL_;
        case PF_INET: return PF_INET_;
        case PF_INET6: return PF_INET6_;
    }
    return -1;
}

/* Socket type constants */
/** Stream socket */
#define SOCK_STREAM_ 1
/** Datagram socket */
#define SOCK_DGRAM_ 2
/** Raw socket */
#define SOCK_RAW_ 3
/** Nonblocking mode bit */
#define SOCK_NONBLOCK_ 0x800
/** Close-on-exec bit */
#define SOCK_CLOEXEC_ 0x80000

/**
 * Convert emulated Linux socket type to host platform socket type
 *
 * @param type Linux socket type
 * @param protocol Socket protocol
 * @return Host platform socket type or -1 if unsupported
 */
static inline int sock_type_to_real(int type, int protocol) {
    switch (type & 0xff) {
        case SOCK_STREAM_:
            if (protocol != 0 && protocol != IPPROTO_TCP)
                return -1;
            return SOCK_STREAM;
        case SOCK_DGRAM_:
            switch (protocol) {
                default:
                    return -1;
                case 0:
                case IPPROTO_UDP:
                case IPPROTO_ICMP:
                case IPPROTO_ICMPV6:
                    break;
            }
            return SOCK_DGRAM;
        case SOCK_RAW_:
            switch (protocol) {
                default:
                    return -1;
                case IPPROTO_RAW:
                case IPPROTO_UDP:
                case IPPROTO_ICMP:
                case IPPROTO_ICMPV6:
                    break;
            }
            return SOCK_DGRAM;
    }
    return -1;
}

/* Socket message flags */
/** Out-of-band data */
#define MSG_OOB_ 0x1
/** Peek at incoming message */
#define MSG_PEEK_ 0x2
/** Control data was truncated */
#define MSG_CTRUNC_  0x8
/** Data was truncated */
#define MSG_TRUNC_  0x20
/** Nonblocking operation */
#define MSG_DONTWAIT_ 0x40
/** End of record */
#define MSG_EOR_    0x80
/** Wait for full request or error */
#define MSG_WAITALL_ 0x100

/**
 * Convert emulated Linux socket flags to host platform socket flags
 *
 * @param fake Linux socket flags
 * @return Host platform socket flags
 */
static inline int sock_flags_to_real(int fake) {
    int real = 0;
    if (fake & MSG_OOB_) real |= MSG_OOB;
    if (fake & MSG_PEEK_) real |= MSG_PEEK;
    if (fake & MSG_CTRUNC_) real |= MSG_CTRUNC;
    if (fake & MSG_TRUNC_) real |= MSG_TRUNC;
    if (fake & MSG_DONTWAIT_) real |= MSG_DONTWAIT;
    if (fake & MSG_EOR_) real |= MSG_EOR;
    if (fake & MSG_WAITALL_) real |= MSG_WAITALL;
    if (fake & ~(MSG_OOB_|MSG_PEEK_|MSG_CTRUNC_|MSG_TRUNC_|MSG_DONTWAIT_|MSG_EOR_|MSG_WAITALL_))
        TRACE("unimplemented socket flags %d\n", fake);
    return real;
}

/**
 * Convert host platform socket flags to emulated Linux socket flags
 *
 * @param real Host platform socket flags
 * @return Linux socket flags
 */
static inline int sock_flags_from_real(int real) {
    int fake = 0;
    if (real & MSG_OOB) fake |= MSG_OOB_;
    if (real & MSG_PEEK) fake |= MSG_PEEK_;
    if (real & MSG_CTRUNC) fake |= MSG_CTRUNC_;
    if (real & MSG_TRUNC) fake |= MSG_TRUNC_;
    if (real & MSG_DONTWAIT) fake |= MSG_DONTWAIT_;
    if (real & MSG_EOR) fake |= MSG_EOR_;
    if (real & MSG_WAITALL) fake |= MSG_WAITALL_;
    if (real & ~(MSG_OOB|MSG_PEEK|MSG_CTRUNC|MSG_TRUNC|MSG_DONTWAIT|MSG_EOR|MSG_WAITALL))
        TRACE("unimplemented socket flags %d\n", real);
    return fake;
}

/* Socket option levels */
/** Socket level options */
#define SOL_SOCKET_ 1

/* Socket options (SOL_SOCKET level) */
/** Allow reuse of local addresses */
#define SO_REUSEADDR_ 2
/** Get socket type */
#define SO_TYPE_ 3
/** Get socket error */
#define SO_ERROR_ 4
/** Allow broadcast datagrams */
#define SO_BROADCAST_ 6
/** Socket send buffer size */
#define SO_SNDBUF_ 7
/** Socket receive buffer size */
#define SO_RCVBUF_ 8
/** Keep connection alive */
#define SO_KEEPALIVE_ 9
/** Linger on close if data present */
#define SO_LINGER_ 13
/** Get credentials of peer process */
#define SO_PEERCRED_ 17
/** Timestamp received datagrams */
#define SO_TIMESTAMP_ 29
/** Get socket protocol */
#define SO_PROTOCOL_ 38
/** Get socket domain */
#define SO_DOMAIN_ 39
/** Receive timeout */
#define SO_RCVTIMEO_ 66
/** Send timeout */
#define SO_SNDTIMEO_ 67

/* IP level socket options */
/** Type of service */
#define IP_TOS_ 1
/** Time to live */
#define IP_TTL_ 2
/** Include IP header */
#define IP_HDRINCL_ 3
/** Receive IP options */
#define IP_RETOPTS_ 7
/** Path MTU discovery */
#define IP_MTU_DISCOVER_ 10
/** Receive TTL with datagrams */
#define IP_RECVTTL_ 12
/** Receive TOS with datagrams */
#define IP_RECVTOS_ 13

/* TCP level socket options */
/** Disable Nagle algorithm */
#define TCP_NODELAY_ 1
/** Defer accept until data arrives */
#define TCP_DEFER_ACCEPT_ 9
/** Get TCP connection info */
#define TCP_INFO_ 11
/** Set TCP congestion control algorithm */
#define TCP_CONGESTION_ 13

/* IPv6 level socket options */
/** Hop limit for unicast packets */
#define IPV6_UNICAST_HOPS_ 16
/** Restrict to IPv6 only */
#define IPV6_V6ONLY_ 26
/** Traffic class */
#define IPV6_TCLASS_ 67
/** ICMPv6 filter */
#define ICMP6_FILTER_ 1

/**
 * Convert emulated Linux socket option to host platform socket option
 *
 * @param fake Linux socket option
 * @param level Option level
 * @return Host platform socket option or -1 if unsupported
 */
static inline int sock_opt_to_real(int fake, int level) {
    switch (level) {
        case SOL_SOCKET_: switch (fake) {
            case SO_REUSEADDR_: return SO_REUSEADDR;
            case SO_TYPE_: return SO_TYPE;
            case SO_ERROR_: return SO_ERROR;
            case SO_BROADCAST_: return SO_BROADCAST;
            case SO_KEEPALIVE_: return SO_KEEPALIVE;
            case SO_LINGER_: return SO_LINGER;
            case SO_SNDBUF_: return SO_SNDBUF;
            case SO_RCVBUF_: return SO_RCVBUF;
            case SO_TIMESTAMP_: return SO_TIMESTAMP;
            case SO_RCVTIMEO_: return SO_RCVTIMEO;
            case SO_SNDTIMEO_: return SO_SNDTIMEO;
        } break;
        case IPPROTO_TCP: switch (fake) {
            case TCP_NODELAY_: return TCP_NODELAY;
            case TCP_DEFER_ACCEPT_: return 0; // unimplemented
#if defined(__linux__)
            case TCP_INFO_: return TCP_INFO;
            case TCP_CONGESTION_: return TCP_CONGESTION;
#endif
        } break;
        case IPPROTO_IP: switch (fake) {
            case IP_TOS_: return IP_TOS;
            case IP_TTL_: return IP_TTL;
            case IP_HDRINCL_: return IP_HDRINCL;
            case IP_RETOPTS_: return IP_RETOPTS;
            case IP_RECVTTL_: return IP_RECVTTL;
            case IP_RECVTOS_: return IP_RECVTOS;
        } break;
        case IPPROTO_IPV6: switch (fake) {
            case IPV6_UNICAST_HOPS_: return IPV6_UNICAST_HOPS;
            case IPV6_TCLASS_: return IPV6_TCLASS;
            case IPV6_V6ONLY_: return IPV6_V6ONLY;
        } break;
    }
    return -1;
}

/**
 * Convert emulated Linux socket level to host platform socket level
 *
 * @param fake Linux socket level
 * @return Host platform socket level
 */
static inline int sock_level_to_real(int fake) {
    if (fake == SOL_SOCKET_)
        return SOL_SOCKET;
    return fake;
}

/**
 * Temporary directory path prefix for Unix domain sockets
 * This is used for Unix domain sockets to create real files in the host filesystem
 */
extern const char *sock_tmp_prefix;

/**
 * TCP information structure (emulated Linux version)
 * Contains statistics and state information about a TCP connection
 */
struct tcp_info_ {
    /** TCP state (e.g., ESTABLISHED, SYN_SENT) */
    uint8_t state;
    /** Congestion algorithm state */
    uint8_t ca_state;
    /** Number of retransmitted segments */
    uint8_t retransmits;
    /** Number of probes sent */
    uint8_t probes;
    /** Backoff timer value */
    uint8_t backoff;
    /** TCP options enabled */
    uint8_t options;
    /** Window scale factors */
    uint8_t snd_wscale:4, rcv_wscale:4;

    /** Retransmission timeout in microseconds */
    uint32_t rto;
    /** Delayed ACK timeout in microseconds */
    uint32_t ato;
    /** Sender maximum segment size */
    uint32_t snd_mss;
    /** Receiver maximum segment size */
    uint32_t rcv_mss;

    /** Unacknowledged segments */
    uint32_t unacked;
    /** Selective ACK'd segments */
    uint32_t sacked;
    /** Lost segments */
    uint32_t lost;
    /** Retransmitted segments */
    uint32_t retrans;
    /** Forward acknowledged segments */
    uint32_t fackets;

    /** Time since last data packet sent (ms) */
    uint32_t last_data_sent;
    /** Time since last ACK sent (ms) */
    uint32_t last_ack_sent;
    /** Time since last data packet received (ms) */
    uint32_t last_data_recv;
    /** Time since last ACK received (ms) */
    uint32_t last_ack_recv;

    /** Path MTU */
    uint32_t pmtu;
    /** Receiver slow start threshold */
    uint32_t rcv_ssthresh;
    /** Smoothed round trip time (μs) */
    uint32_t rtt;
    /** RTT variance (μs) */
    uint32_t rttvar;
    /** Sender slow start threshold */
    uint32_t snd_ssthresh;
    /** Congestion window size */
    uint32_t snd_cwnd;
    /** Advertised MSS */
    uint32_t advmss;
    /** Reordering metric */
    uint32_t reordering;

    /** Receiver round trip time (μs) */
    uint32_t rcv_rtt;
    /** Receiver window size */
    uint32_t rcv_space;

    /** Total retransmitted segments */
    uint32_t total_retrans;
};

#endif /* SYS_SOCK_H */
