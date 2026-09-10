// gate.bpf.c - Ningshi gate.
// Deterministic detect-then-kill, no delay hack.
//
// Two independent anchors, either of which is enough to catch a blocked app
// before its code runs:
//
//  1. binder_transaction
//     kprobe  entry: current uid is blocked AND target handle != 0 -> mark tgid.
//             handle == 0 is a ServiceManager lookup (getService), skipped; the
//             first handle != 0 transaction of a new process is
//             attachApplication (app -> AMS).
//     kretprobe exit: still blocked -> push a ringbuf event.
//
//  2. __arm64_sys_setresuid
//     kretprobe: the process swapped to a blocked uid (zygote's child does this
//     right after fork, before any app code runs) -> push a ringbuf event.
//     This anchor does not depend on binder internals at all, so it keeps the
//     module working on kernels where binder_transaction is missing, renamed or
//     inlined.
//
// The userspace thread sends SIGKILL from outside the binder driver, so
// system_server gets the death notification promptly: window removed, no black
// screen.

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_RINGBUF 27

// No bpf_helpers.h on purpose: this file keeps its own minimal shims.
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_probe_read)(void *dst, __u32 size, const void *src) = (void *)4;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static void *(*bpf_ringbuf_reserve)(void *map, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;

// Block list: uid -> 1. App uids only (>= 10000); the program enforces it too.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} blocked_uids SEC(".maps");

// Pending kills from the binder anchor: tgid -> 1 (marked at entry, reported at
// exit).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} spawned SEC(".maps");

// Event ring buffer.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} events SEC(".maps");

// Health counters, readable from userspace. Per-CPU so no atomic instruction is
// needed (BPF atomics are only available on newer kernels); the daemon sums the
// values per index.
//   0 marks accepted        1 events emitted (binder)   2 ringbuf full (binder)
//   3 uid-switch events     4 uid-switch ringbuf full   5 probe_read failures
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v)
        (*v) += 1;
}

struct event {
    __u32 pid;
    __u32 uid;
};

// arm64 pt_regs head (only the argument registers are needed).
struct pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};

static __always_inline int blocked(__u32 uid)
{
    if (uid < 10000)
        return 0;
    __u8 *b = bpf_map_lookup_elem(&blocked_uids, &uid);
    return b && *b;
}

static __always_inline void emit(__u32 pid, __u32 uid, __u32 drop_idx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        bump(drop_idx);
        return;
    }
    e->pid = pid;
    e->uid = uid;
    bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/binder_transaction")
int gate_binder_entry(struct pt_regs *ctx)
{
    __u32 uid = (__u32)bpf_get_current_uid_gid();
    if (!blocked(uid))
        return 0;

    // The signature is binder_transaction(proc, thread, tr, reply,
    // extra_buffers_size), so the binder_transaction_data* is the THIRD
    // argument: regs[2] on arm64 (regs[0] is the proc pointer). Offset 0 of
    // tr is target.handle.
    void *tr = (void *)ctx->regs[2];
    __u32 handle = 0;
    if (bpf_probe_read(&handle, sizeof(handle), tr) != 0) {
        bump(5);
        return 0;
    }
    if (handle == 0)
        return 0; // ServiceManager getService, keep waiting for attach

    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u8 one = 1;
    bpf_map_update_elem(&spawned, &tgid, &one, 0);
    bump(0);
    return 0;
}

SEC("kretprobe/binder_transaction")
int gate_binder_exit(void *ctx)
{
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u8 *mark = bpf_map_lookup_elem(&spawned, &tgid);
    if (!mark || !*mark)
        return 0;

    // The mark is cleared either way: if the uid is no longer blocked (the rule
    // was removed, or the process that made the mark was killed before its
    // kretprobe ran), the stale mark must not follow a recycled tgid.
    __u32 uid = (__u32)bpf_get_current_uid_gid();
    bpf_map_delete_elem(&spawned, &tgid);

    if (!blocked(uid))
        return 0;

    emit(tgid, uid, 2);
    bump(1);
    return 0;
}

// Secondary anchor: a process that just switched to a blocked uid. Catches app
// spawns independently of binder, right after zygote forked the child.
SEC("kretprobe/__arm64_sys_setresuid")
int gate_uid_switch(void *ctx)
{
    __u32 uid = (__u32)bpf_get_current_uid_gid();
    if (!blocked(uid))
        return 0;

    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    emit(tgid, uid, 4);
    bump(3);
    return 0;
}

char _license[] SEC("license") = "GPL";
