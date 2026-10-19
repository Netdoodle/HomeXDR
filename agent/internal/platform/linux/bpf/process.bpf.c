//go:build ignore

// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
//
// Process telemetry for the HomeXDR Linux agent: one event per exec (with argv) and one
// per process exit (with exit code). Read-only: the programs only observe.
//
// Built with bpf2go (see gen.go). Requires BTF (CO-RE), tp_btf (5.5+) and the BPF ring
// buffer (5.8+); the agent falls back to the netlink proc connector otherwise.

#include "hx_vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "hx_pidns.h"

#define ARGS_MAX 4096 /* must be a power of two (used as a verifier mask) */
#define PATH_MAX_ 256
#define COMM_LEN 16

enum { EV_EXEC = 1, EV_EXIT = 2 };

// Layouts are mirrored in Go (process_ebpf.go); keep them in sync.
struct exec_event {
	__u32 type;
	__u32 pid;  // process ID in the agent's PID namespace
	__u32 tid;
	__u32 ppid; // real parent's process ID
	__u32 uid;
	__u32 gid;
	__u32 euid;
	__u32 args_len;
	__u64 start_ns;        // group leader start_boottime
	__u64 parent_start_ns; // real parent's group leader start_boottime
	__u32 args_truncated;
	__u32 pad;
	char comm[COMM_LEN];
	char filename[PATH_MAX_];
	char args[ARGS_MAX]; // NUL-separated argv, args_len bytes
};

struct exit_event {
	__u32 type;
	__u32 pid;
	__u32 ppid;
	__s32 exit_code; // raw wait status: (code << 8) | signal
	__u64 start_ns;
	char comm[COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); // 4 MiB
} process_events SEC(".maps");

SEC("tp_btf/sched_process_exec")
int BPF_PROG(hx_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	__u32 pid = tgid_in_ns(p);
	if (!pid)
		return 0; // not in the agent's PID namespace tree

	struct exec_event *e = bpf_ringbuf_reserve(&process_events, sizeof(*e), 0);
	if (!e)
		return 0;

	struct task_struct *parent = BPF_CORE_READ(p, real_parent);
	__u64 ugid = bpf_get_current_uid_gid();

	e->type = EV_EXEC;
	e->pid = pid;
	e->tid = pid_in_ns(p);
	e->ppid = tgid_in_ns(parent);
	e->uid = (__u32)ugid;
	e->gid = (__u32)(ugid >> 32);
	e->euid = BPF_CORE_READ(p, cred, euid.val);
	// After exec, de_thread() has made this task the group leader and copied the old
	// leader's start time, so this equals /proc/<pid>/stat field 22 (in ns).
	e->start_ns = BPF_CORE_READ(p, group_leader, start_boottime);
	e->parent_start_ns = BPF_CORE_READ(parent, group_leader, start_boottime);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), BPF_CORE_READ(bprm, filename));

	// argv lives in the new process image's user memory between arg_start and arg_end;
	// it was just written by exec, so the pages are present.
	unsigned long as = BPF_CORE_READ(p, mm, arg_start);
	unsigned long ae = BPF_CORE_READ(p, mm, arg_end);
	__u64 len = ae > as ? ae - as : 0;
	e->args_truncated = 0;
	if (len > ARGS_MAX - 1) {
		len = ARGS_MAX - 1;
		e->args_truncated = 1;
	}
	e->args_len = 0;
	len &= ARGS_MAX - 1; // bound for the verifier
	if (len > 0 && bpf_probe_read_user(&e->args, len, (void *)as) == 0)
		e->args_len = len;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(hx_exit, struct task_struct *p)
{
	// sched_process_exit fires for every thread. do_exit() decrements signal->live
	// before the tracepoint, so live == 0 means the last thread of the process is
	// exiting: report the process once.
	if (BPF_CORE_READ(p, signal, live.counter) != 0)
		return 0;
	__u32 pid = tgid_in_ns(p);
	if (!pid)
		return 0;

	struct exit_event *e = bpf_ringbuf_reserve(&process_events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->type = EV_EXIT;
	e->pid = pid;
	e->ppid = tgid_in_ns(BPF_CORE_READ(p, real_parent));
	e->exit_code = BPF_CORE_READ(p, exit_code);
	e->start_ns = BPF_CORE_READ(p, group_leader, start_boottime);
	BPF_CORE_READ_STR_INTO(&e->comm, p, comm);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
