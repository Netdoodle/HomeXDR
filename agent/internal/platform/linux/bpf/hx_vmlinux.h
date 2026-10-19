/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * Minimal kernel type definitions for the HomeXDR eBPF programs.
 *
 * Instead of a generated vmlinux.h (several MB), we declare only the structs and fields
 * the programs read. Every struct carries preserve_access_index, so clang records each
 * field access as a CO-RE relocation and libbpf (via cilium/ebpf) resolves the real
 * offsets against the running kernel's BTF (/sys/kernel/btf/vmlinux) at load time. Field
 * order and struct sizes here therefore do not need to match the kernel; only the
 * struct and field names do. Fields that the kernel keeps inside anonymous unions or
 * structs (e.g. sock_common.skc_daddr, mm_struct.arg_start) can be declared directly:
 * CO-RE matching descends into anonymous members by name.
 *
 * Defining __VMLINUX_H__ tells libbpf's bpf_tracing.h to use the kernel's pt_regs
 * register names (di, si, ax, ...) on x86.
 */
#ifndef __HX_VMLINUX_H__
#define __HX_VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef short unsigned int __u16;
typedef unsigned int __u32;
typedef long long unsigned int __u64;
typedef signed char __s8;
typedef short int __s16;
typedef int __s32;
typedef long long int __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef _Bool bool;
enum { false = 0, true = 1 };

/* UAPI constants used by map definitions and helpers (stable ABI values). */
enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};
enum { BPF_ANY = 0 };
enum bpf_stats_type { BPF_STATS_RUN_TIME = 0 };

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6

/* include/net/tcp_states.h */
enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT = 2,
	TCP_CLOSE = 7,
};

/* include/uapi/linux/uio.h (a fixed ABI; read whole with bpf_probe_read_kernel). */
struct iovec {
	void *iov_base;
	unsigned long iov_len;
};

/* include/linux/uio.h. The values differ between kernel versions (ITER_UBUF was added
 * in 6.0 and the order changed since), so the programs only use them through
 * bpf_core_enum_value(), which relocates them by name. */
enum iter_type {
	ITER_IOVEC,
	ITER_UBUF,
};

#if defined(__TARGET_ARCH_x86)
/* arch/x86/include/asm/ptrace.h (x86-64); a fixed ABI used by kprobe contexts. */
struct pt_regs {
	unsigned long r15, r14, r13, r12, bp, bx, r11, r10, r9, r8;
	unsigned long ax, cx, dx, si, di, orig_ax, ip, cs, flags, sp, ss;
};
#elif defined(__TARGET_ARCH_arm64)
/* arch/arm64/include/uapi/asm/ptrace.h */
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
struct pt_regs {
	struct user_pt_regs user_regs;
};
#endif

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

typedef struct {
	int counter;
} atomic_t;

typedef struct {
	uid_t val;
} kuid_t;

typedef struct {
	gid_t val;
} kgid_t;

struct cred {
	kuid_t uid;
	kgid_t gid;
	kuid_t euid;
	kgid_t egid;
};

struct mm_struct {
	unsigned long arg_start;
	unsigned long arg_end;
};

struct signal_struct {
	atomic_t live;
};

struct ns_common {
	unsigned int inum; /* inode number, as in /proc/<pid>/ns/pid -> "pid:[inum]" */
};

struct pid_namespace {
	struct ns_common ns;
};

/* The PID of a task in one namespace level. */
struct upid {
	int nr;
	struct pid_namespace *ns;
};

/* include/linux/pid.h: numbers[0..level] hold the PID in each namespace, from the
 * initial namespace (0) down to the task's own (level). */
struct pid {
	unsigned int level;
	struct upid numbers[1];
};

struct task_struct {
	pid_t pid;  /* thread ID in the initial PID namespace */
	pid_t tgid; /* process ID in the initial PID namespace */
	struct pid *thread_pid;
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	/* Monotonic boot-based start time in ns (includes suspend); /proc/<pid>/stat
	 * field 22 is this value of the thread-group leader divided by 1e9/USER_HZ. */
	__u64 start_boottime;
	struct mm_struct *mm;
	const struct cred *cred;
	struct signal_struct *signal;
	int exit_code;
	char comm[16];
};

struct linux_binprm {
	const char *filename;
};

struct in6_addr {
	__u8 u6_addr8[16];
};

struct sock_common {
	__be32 skc_daddr;     /* remote IPv4 */
	__be32 skc_rcv_saddr; /* local IPv4 */
	__be16 skc_dport;     /* remote port, network order */
	__u16 skc_num;        /* local port, host order */
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
};

/* include/linux/skbuff.h. next is inside anonymous unions in the kernel. */
struct sk_buff {
	struct sk_buff *next;
	unsigned char *head;
	__u16 transport_header; /* offset from head */
};

/* An empty queue's next points back at the queue itself. */
struct sk_buff_head {
	struct sk_buff *next;
};

struct sock {
	struct sock_common __sk_common;
	__u16 sk_protocol; /* a bitfield before 5.6; read with BPF_CORE_READ_BITFIELD_PROBED */
};

/* More of struct sock, as a CO-RE flavour (matched against the kernel's struct sock) so
 * that programs not using it keep the smaller struct sock above. */
struct sock___rq {
	struct sk_buff_head sk_receive_queue;
};

/* include/linux/udp.h (embeds struct sock at offset 0). recvmsg takes datagrams from
 * reader_queue first and refills it from sk_receive_queue (4.13+). */
struct udp_sock {
	struct sk_buff_head reader_queue;
};

/* include/linux/uio.h (5.14+, when iter_type became its own field). __iov, count and
 * ubuf sit inside anonymous unions in the kernel. */
struct iov_iter {
	__u8 iter_type;
	unsigned long count;       /* bytes left */
	const struct iovec *__iov; /* ITER_IOVEC; named iov before 6.4 */
	void *ubuf;                /* ITER_UBUF (6.0+): a single user buffer */
};

/* The pre-6.4 name of iov_iter.__iov (a CO-RE flavour: the ___ suffix is ignored when
 * matching against the kernel's struct iov_iter). */
struct iov_iter___pre64 {
	const struct iovec *iov;
};

/* include/linux/socket.h. msg_name points to a kernel copy of the address. */
struct msghdr {
	void *msg_name;
	int msg_namelen;
	struct iov_iter msg_iter;
};

#pragma clang attribute pop

#endif /* __HX_VMLINUX_H__ */
