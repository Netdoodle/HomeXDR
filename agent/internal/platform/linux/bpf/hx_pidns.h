/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * PID namespace translation.
 *
 * task->pid / task->tgid are PIDs in the initial PID namespace. The agent reads /proc in
 * its own namespace, which differs when it runs in a container or under WSL (where each
 * distribution has its own PID namespace). Entity IDs hash the PID, so the eBPF sensors
 * must report the PID as the agent sees it.
 *
 * struct pid holds the task's PID at every level from the initial namespace (0) down to
 * its own; we pick the entry whose namespace is the agent's (target_pidns, the inode of
 * /proc/self/ns/pid, set by the loader). Tasks outside the agent's namespace tree yield 0
 * and are not reported.
 */
#ifndef __HX_PIDNS_H__
#define __HX_PIDNS_H__

#define MAX_PIDNS_LEVEL 8

/* Set from user space before load; 0 disables translation. */
const volatile __u32 target_pidns = 0;

static __always_inline __u32 pid_in_ns(struct task_struct *t)
{
	if (!target_pidns)
		return BPF_CORE_READ(t, pid);
	struct pid *p = BPF_CORE_READ(t, thread_pid);
	if (!p)
		return 0;
	unsigned int level = BPF_CORE_READ(p, level);
	struct upid *nums = (struct upid *)((void *)p + bpf_core_field_offset(p->numbers));
#pragma unroll
	for (int i = 0; i < MAX_PIDNS_LEVEL; i++) {
		if (i > level)
			break;
		struct upid u = {};
		if (bpf_probe_read_kernel(&u, sizeof(u), &nums[i]))
			break;
		if (BPF_CORE_READ(u.ns, ns.inum) == target_pidns)
			return u.nr;
	}
	return 0;
}

/* The process ID (thread-group leader's PID) as the agent sees it. */
static __always_inline __u32 tgid_in_ns(struct task_struct *t)
{
	return pid_in_ns(BPF_CORE_READ(t, group_leader));
}

#endif /* __HX_PIDNS_H__ */
