//go:build ignore

// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
//
// DNS telemetry for the HomeXDR Linux agent: the DNS messages processes send to and
// receive from UDP port 53, with the process that sent or received them. Read-only: the
// programs only observe; parsing happens in user space (dns.go).
//
// Queries: udp_sendmsg / udpv6_sendmsg run in the sending process before the payload is
// copied, so it is still in the caller's buffer (msg->msg_iter). For destination port 53
// we copy its first DNS_MAX bytes.
//
// Answers: on entry to udp_recvmsg / udpv6_recvmsg we remember the caller's buffer and
// how much the iterator could take; on return the difference is what the kernel copied,
// and msg->msg_name (or the connected peer) says where it came from. For source port 53
// we copy it out of the caller's buffer, again in the receiving process.
//
// Both hooks run in the context of the process doing the I/O, so a query to a local stub
// resolver (systemd-resolved on 127.0.0.53) is attributed to the application, and the
// stub's own upstream query to the stub.
//
// Two attachment flavours share this code. BPF trampolines (fentry/fexit) are preferred:
// unlike kretprobes they have no instance limit, which threads blocked in recvmsg would
// otherwise exhaust. kprobes/kretprobes are the fallback where trampolines are missing.
//
// A dual-stack socket sending to an IPv4 or IPv4-mapped address goes through
// udpv6_sendmsg and then udp_sendmsg; only the latter reports it.

#include "hx_vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "hx_pidns.h"

#define COMM_LEN 16
#define DNS_MAX 512 /* bytes copied of each message */
#define DNS_HDR 12  /* the shortest DNS message: a bare header */
#define DNS_PORT 53

enum { DNS_SEND = 1, DNS_RECV = 2 };

// Mirrored in Go (dns_ebpf.go); keep them in sync.
struct dns_event {
	__u32 type;
	__u32 pid; // process ID in the agent's PID namespace
	__u32 tid;
	__u32 ppid;
	__u32 uid;
	__u16 family;   // AF_INET or AF_INET6: the length of laddr / raddr
	__u16 lport;    // local port, host order
	__u16 rport;    // remote port, host order
	__u16 len;      // bytes in payload
	__u32 orig_len; // length of the whole message
	__u64 start_ns;        // group leader start_boottime
	__u64 parent_start_ns; // real parent's group leader start_boottime
	__u8 laddr[16];        // local address (first 4 bytes for IPv4; may be unspecified)
	__u8 raddr[16];        // remote address
	char comm[COMM_LEN];
	__u8 payload[DNS_MAX];
};

// What udp*_recvmsg was asked to fill, saved at entry for the return hook. Pointers are
// stored as integers (bpf2go cannot mirror pointer fields in Go).
struct recv_args {
	__u64 sk;     // struct sock *
	__u64 msg;    // struct msghdr *
	__u64 base;   // user buffer of the first segment
	__u64 seglen; // its length
	__u64 count;  // bytes the iterator could take before the copy
	__u32 v6;     // udpv6_recvmsg
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 21); // 2 MiB
} dns_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64); // pid_tgid of the receiving thread
	__type(value, struct recv_args);
} pending_recv SEC(".maps");

// The first user buffer of a message iterator, its length, and the bytes the iterator
// still covers. Only user-backed iterators are of interest: kernel users of UDP sockets
// (ITER_KVEC) are not DNS clients.
static __always_inline int iter_buf(struct iov_iter *it, void **base, __u64 *seglen, __u64 *count)
{
	__u8 t = BPF_CORE_READ(it, iter_type);
	*count = BPF_CORE_READ(it, count);
	if (bpf_core_enum_value_exists(enum iter_type, ITER_UBUF) &&
	    t == bpf_core_enum_value(enum iter_type, ITER_UBUF)) {
		*base = BPF_CORE_READ(it, ubuf);
		*seglen = *count;
		return 0;
	}
	if (t != bpf_core_enum_value(enum iter_type, ITER_IOVEC))
		return -1;
	const struct iovec *iov;
	if (bpf_core_field_exists(it->__iov))
		iov = BPF_CORE_READ(it, __iov);
	else
		iov = BPF_CORE_READ((struct iov_iter___pre64 *)it, iov);
	struct iovec v = {};
	if (!iov || bpf_probe_read_kernel(&v, sizeof(v), iov)) // the kernel's copy of the iovecs
		return -1;
	*base = v.iov_base;
	*seglen = v.iov_len;
	return 0;
}

static __always_inline bool v4mapped(const __u8 *a)
{
#pragma unroll
	for (int i = 0; i < 10; i++)
		if (a[i])
			return false;
	return a[10] == 0xff && a[11] == 0xff;
}

// Reads the port and address of a sockaddr_in / sockaddr_in6 in kernel memory. Returns
// the address family, or 0.
static __always_inline __u16 read_sockaddr(void *sa, __u16 *port, __u8 *addr)
{
	struct {
		__u16 family;
		__be16 port;
		__be32 addr4; // sockaddr_in: the address; sockaddr_in6: flowinfo
	} h = {};
	if (bpf_probe_read_kernel(&h, sizeof(h), sa))
		return 0;
	*port = bpf_ntohs(h.port);
	if (h.family == AF_INET) {
		__builtin_memcpy(addr, &h.addr4, 4);
		return AF_INET;
	}
	if (h.family == AF_INET6 && !bpf_probe_read_kernel(addr, 16, sa + 8))
		return AF_INET6;
	return 0;
}

static __always_inline void sk_local(struct sock *sk, bool v6, __u8 *addr)
{
	if (v6) {
		struct in6_addr a = {};
		BPF_CORE_READ_INTO(&a, sk, __sk_common.skc_v6_rcv_saddr);
		__builtin_memcpy(addr, &a, 16);
	} else {
		__be32 a = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__builtin_memcpy(addr, &a, 4);
	}
}

static __always_inline void sk_peer(struct sock *sk, bool v6, __u8 *addr)
{
	if (v6) {
		struct in6_addr a = {};
		BPF_CORE_READ_INTO(&a, sk, __sk_common.skc_v6_daddr);
		__builtin_memcpy(addr, &a, 16);
	} else {
		__be32 a = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__builtin_memcpy(addr, &a, 4);
	}
}

// Copies n (DNS_HDR..) bytes from the user buffer and the current process to the ring
// buffer.
static __always_inline void emit(__u32 type, struct task_struct *t, __u32 pid, bool v6,
				 struct sock *sk, __u16 rport, const __u8 *laddr, const __u8 *raddr,
				 void *base, __u64 n, __u64 orig)
{
	struct dns_event *e = bpf_ringbuf_reserve(&dns_events, sizeof(*e), 0);
	if (!e)
		return;
	if (n > DNS_MAX)
		n = DNS_MAX;
	if (bpf_probe_read_user(e->payload, n, base)) {
		bpf_ringbuf_discard(e, 0);
		return;
	}
	struct task_struct *leader = BPF_CORE_READ(t, group_leader);
	struct task_struct *parent = BPF_CORE_READ(leader, real_parent);
	e->type = type;
	e->pid = pid;
	e->tid = pid_in_ns(t);
	e->ppid = tgid_in_ns(parent);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->family = v6 ? AF_INET6 : AF_INET;
	e->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->rport = rport;
	e->len = n;
	e->orig_len = orig > 0xffffffff ? 0xffffffff : orig;
	e->start_ns = BPF_CORE_READ(leader, start_boottime);
	e->parent_start_ns = BPF_CORE_READ(parent, group_leader, start_boottime);
	__builtin_memcpy(e->laddr, laddr, 16);
	__builtin_memcpy(e->raddr, raddr, 16);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

static __always_inline int on_send(struct sock *sk, struct msghdr *msg, bool v6)
{
	__u8 laddr[16] = {}, raddr[16] = {};
	__u16 rport = 0;
	void *name = BPF_CORE_READ(msg, msg_name);
	if (name) {
		__u16 family = read_sockaddr(name, &rport, raddr);
		if (rport != DNS_PORT)
			return 0;
		// udpv6_sendmsg hands IPv4 and IPv4-mapped destinations to udp_sendmsg.
		if (v6 ? family != AF_INET6 || v4mapped(raddr) : family != AF_INET)
			return 0;
	} else {
		rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
		if (rport != DNS_PORT)
			return 0;
		sk_peer(sk, v6, raddr);
		if (v6 && v4mapped(raddr))
			return 0;
	}

	void *base = 0;
	__u64 seglen = 0, count = 0;
	if (iter_buf(&msg->msg_iter, &base, &seglen, &count) || !base)
		return 0;
	__u64 n = seglen < count ? seglen : count;
	if (n < DNS_HDR)
		return 0;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	__u32 pid = tgid_in_ns(t);
	if (!pid)
		return 0; // not in the agent's PID namespace tree
	sk_local(sk, v6, laddr);
	emit(DNS_SEND, t, pid, v6, sk, rport, laddr, raddr, base, n, count);
	return 0;
}

// Whether the datagram recvmsg is about to return may come from port 53: false only when
// the next queued datagram is known and has another source port. Most receives find it
// queued (event-driven programs read when the socket is readable), so non-DNS traffic
// skips the map; an empty queue (the caller will wait, or get EAGAIN) is remembered,
// since the source is not known yet.
static __always_inline bool next_may_be_dns(struct sock *sk)
{
	struct sk_buff_head *q = &((struct udp_sock *)sk)->reader_queue;
	struct sk_buff *skb = BPF_CORE_READ(q, next);
	if ((void *)skb == (void *)q) {
		q = &((struct sock___rq *)sk)->sk_receive_queue;
		skb = BPF_CORE_READ(q, next);
		if ((void *)skb == (void *)q)
			return true;
	}
	if (!skb)
		return true;
	unsigned char *head = BPF_CORE_READ(skb, head);
	__u16 th = BPF_CORE_READ(skb, transport_header);
	__be16 sport = 0;
	if (!head || bpf_probe_read_kernel(&sport, sizeof(sport), head + th))
		return true;
	return bpf_ntohs(sport) == DNS_PORT;
}

static __always_inline int on_recv_entry(struct sock *sk, struct msghdr *msg, bool v6)
{
	// A socket connected to another port never receives DNS answers, and one bound to
	// port 53 belongs to a DNS server (which sends its own queries from other ports).
	__u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if ((dport && dport != DNS_PORT) || BPF_CORE_READ(sk, __sk_common.skc_num) == DNS_PORT)
		return 0;
	if (!next_may_be_dns(sk))
		return 0;
	void *base = 0;
	__u64 seglen = 0, count = 0;
	if (iter_buf(&msg->msg_iter, &base, &seglen, &count) || !base || seglen < DNS_HDR)
		return 0;
	struct recv_args a = {
		.sk = (__u64)sk,
		.msg = (__u64)msg,
		.base = (__u64)base,
		.seglen = seglen,
		.count = count,
		.v6 = v6,
	};
	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&pending_recv, &id, &a, BPF_ANY);
	return 0;
}

static __always_inline int on_recv_exit(void)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct recv_args *p = bpf_map_lookup_elem(&pending_recv, &id);
	if (!p)
		return 0;
	struct recv_args a = *p;
	bpf_map_delete_elem(&pending_recv, &id);
	struct sock *sk = (struct sock *)a.sk;
	struct msghdr *msg = (struct msghdr *)a.msg;

	// The copy advanced the iterator by the number of bytes received.
	__u64 left = BPF_CORE_READ(msg, msg_iter.count);
	if (left >= a.count)
		return 0; // an error, or nothing copied
	__u64 copied = a.count - left;
	__u64 n = copied < a.seglen ? copied : a.seglen;
	if (n < DNS_HDR)
		return 0;

	bool v6 = a.v6;
	__u8 laddr[16] = {}, raddr[16] = {};
	__u16 rport = 0;
	void *name = BPF_CORE_READ(msg, msg_name);
	if (name) {
		// Filled in by recvmsg with the datagram's source.
		if (read_sockaddr(name, &rport, raddr) != (v6 ? AF_INET6 : AF_INET))
			return 0;
	} else {
		rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
		sk_peer(sk, v6, raddr);
	}
	if (rport != DNS_PORT)
		return 0;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	__u32 pid = tgid_in_ns(t);
	if (!pid)
		return 0;
	sk_local(sk, v6, laddr);
	emit(DNS_RECV, t, pid, v6, sk, rport, laddr, raddr, (void *)a.base, n, copied);
	return 0;
}

/* BPF trampolines. */

SEC("fentry/udp_sendmsg")
int BPF_PROG(hx_dns_send4, struct sock *sk, struct msghdr *msg)
{
	return on_send(sk, msg, false);
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(hx_dns_send6, struct sock *sk, struct msghdr *msg)
{
	return on_send(sk, msg, true);
}

SEC("fentry/udp_recvmsg")
int BPF_PROG(hx_dns_recv4, struct sock *sk, struct msghdr *msg)
{
	return on_recv_entry(sk, msg, false);
}

SEC("fexit/udp_recvmsg")
int BPF_PROG(hx_dns_recv4_ret)
{
	return on_recv_exit();
}

SEC("fentry/udpv6_recvmsg")
int BPF_PROG(hx_dns_recv6, struct sock *sk, struct msghdr *msg)
{
	return on_recv_entry(sk, msg, true);
}

SEC("fexit/udpv6_recvmsg")
int BPF_PROG(hx_dns_recv6_ret)
{
	return on_recv_exit();
}

/* kprobes, for kernels without BPF trampolines. */

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(hx_dns_ksend4, struct sock *sk, struct msghdr *msg)
{
	return on_send(sk, msg, false);
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(hx_dns_ksend6, struct sock *sk, struct msghdr *msg)
{
	return on_send(sk, msg, true);
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(hx_dns_krecv4, struct sock *sk, struct msghdr *msg)
{
	return on_recv_entry(sk, msg, false);
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(hx_dns_krecv4_ret)
{
	return on_recv_exit();
}

SEC("kprobe/udpv6_recvmsg")
int BPF_KPROBE(hx_dns_krecv6, struct sock *sk, struct msghdr *msg)
{
	return on_recv_entry(sk, msg, true);
}

SEC("kretprobe/udpv6_recvmsg")
int BPF_KRETPROBE(hx_dns_krecv6_ret)
{
	return on_recv_exit();
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
