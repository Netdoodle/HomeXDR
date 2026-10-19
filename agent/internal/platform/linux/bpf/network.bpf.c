//go:build ignore

// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
//
// TCP connection telemetry for the HomeXDR Linux agent. Read-only: the programs only
// observe.
//
// Outbound: inet_sock_set_state CLOSE -> SYN_SENT runs in the context of the process
// calling connect(), so we remember that process for the socket. The later
// SYN_SENT -> ESTABLISHED (or -> CLOSE on failure) transition runs in softirq context,
// where "current" is arbitrary; we emit the event there with the remembered process and
// the now-complete 4-tuple (the source port is only assigned after SYN_SENT is set).
//
// Inbound: the handshake completes in softirq context, so the PID is not reliable there.
// Instead we hook the return of inet_csk_accept(), which runs in the accepting process.

#include "hx_vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "hx_pidns.h"

#define COMM_LEN 16

enum { NET_CONNECT = 1, NET_ACCEPT = 2, NET_CONNECT_FAILED = 3 };

struct conn_owner {
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 pad;
	__u64 start_ns;
	char comm[COMM_LEN];
};

// Mirrored in Go (network_ebpf.go).
struct net_event {
	__u32 type;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u64 start_ns; // process start (group leader start_boottime)
	__u16 family;
	__u16 sport; // local port, host order
	__u16 dport; // remote port, host order
	__u16 protocol;
	__u8 saddr[16]; // local address (first 4 bytes for IPv4)
	__u8 daddr[16]; // remote address
	char comm[COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64); // struct sock *
	__type(value, struct conn_owner);
} connecting SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 21); // 2 MiB
} network_events SEC(".maps");

static __always_inline void fill_tuple(struct net_event *e, struct sock *sk)
{
	e->family = BPF_CORE_READ(sk, __sk_common.skc_family);
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	e->protocol = IPPROTO_TCP;
	if (e->family == AF_INET) {
		__be32 s = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__be32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__builtin_memset(e->saddr, 0, sizeof(e->saddr));
		__builtin_memset(e->daddr, 0, sizeof(e->daddr));
		__builtin_memcpy(e->saddr, &s, 4);
		__builtin_memcpy(e->daddr, &d, 4);
	} else {
		BPF_CORE_READ_INTO(&e->saddr, sk, __sk_common.skc_v6_rcv_saddr);
		BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_v6_daddr);
	}
}

static __always_inline bool is_tcp(struct sock *sk)
{
	return BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) == IPPROTO_TCP;
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(hx_set_state, struct sock *sk, int oldstate, int newstate)
{
	if (!is_tcp(sk))
		return 0;
	__u64 key = (__u64)sk;

	if (newstate == TCP_SYN_SENT) {
		struct conn_owner o = {};
		struct task_struct *t = (struct task_struct *)bpf_get_current_task();
		o.pid = tgid_in_ns(t);
		if (!o.pid)
			return 0; // not in the agent's PID namespace tree
		o.tid = pid_in_ns(t);
		o.uid = (__u32)bpf_get_current_uid_gid();
		o.start_ns = BPF_CORE_READ(t, group_leader, start_boottime);
		bpf_get_current_comm(&o.comm, sizeof(o.comm));
		bpf_map_update_elem(&connecting, &key, &o, BPF_ANY);
		return 0;
	}
	if (oldstate != TCP_SYN_SENT)
		return 0;

	struct conn_owner *o = bpf_map_lookup_elem(&connecting, &key);
	if (!o)
		return 0;
	if (newstate == TCP_ESTABLISHED || newstate == TCP_CLOSE) {
		struct net_event *e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
		if (e) {
			e->type = newstate == TCP_ESTABLISHED ? NET_CONNECT : NET_CONNECT_FAILED;
			e->pid = o->pid;
			e->tid = o->tid;
			e->uid = o->uid;
			e->start_ns = o->start_ns;
			__builtin_memcpy(e->comm, o->comm, COMM_LEN);
			fill_tuple(e, sk);
			bpf_ringbuf_submit(e, 0);
		}
	}
	bpf_map_delete_elem(&connecting, &key);
	return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(hx_accept, struct sock *sk)
{
	if (!sk || !is_tcp(sk))
		return 0;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	__u32 pid = tgid_in_ns(t);
	if (!pid)
		return 0;
	struct net_event *e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->type = NET_ACCEPT;
	e->pid = pid;
	e->tid = pid_in_ns(t);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->start_ns = BPF_CORE_READ(t, group_leader, start_boottime);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	fill_tuple(e, sk);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
