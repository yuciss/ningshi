// gate.bpf.c - Ningshi gate.
// Deterministic kill, no delay hack:
//   kprobe  binder_transaction entry: current uid is blocked AND target
//           handle != 0 -> increment a per-tgid counter. handle == 0 is a
//           ServiceManager lookup (getService), skipped. The first handle != 0
//           transaction of a new process is attachApplication (app -> AMS).
//   kretprobe binder_transaction exit: count >= 2 -> bpf_send_signal(SIGKILL)
//           in the kernel. Killing on the SECOND call lets the attach reply
//           reach system_server first, so the window closes with no black screen.

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_RINGBUF 27

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_probe_read)(void *dst, __u32 size, const void *src) = (void *)4;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static void *(*bpf_ringbuf_reserve)(void *map, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static long (*bpf_send_signal)(__u32 sig) = (void *)109;

// Block list: uid -> 1. App uids only (>= 10000); the program enforces it too.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} blocked_uids SEC(".maps");

// Pending kills: tgid -> count of handle!=0 transactions seen.
// 1 = attach done (reply delivered); 2 = the next call, kill now.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} spawned SEC(".maps");

// Event ring buffer.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} events SEC(".maps");

struct event {
    __u32 pid;
    __u32 uid;
};

// arm64 pt_regs head (only regs[0] = x0 = first argument is needed).
struct pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};

SEC("kprobe/binder_transaction")
int gate_binder_entry(struct pt_regs *ctx)
{
    __u32 uid = (__u32)bpf_get_current_uid_gid();
    if (uid < 10000)
        return 0;
    __u8 *blocked = bpf_map_lookup_elem(&blocked_uids, &uid);
    if (!blocked || !*blocked)
        return 0;

    // First argument: struct binder_transaction_data*, offset 0 = target.handle.
    void *tr = (void *)ctx->regs[0];
    __u32 handle = 0;
    bpf_probe_read(&handle, sizeof(handle), tr);
    if (handle == 0)
        return 0; // ServiceManager getService, keep waiting for attach

    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u32 *cnt = bpf_map_lookup_elem(&spawned, &tgid);
    __u32 next = cnt ? (*cnt + 1) : 1;
    bpf_map_update_elem(&spawned, &tgid, &next, 0);
    return 0;
}

SEC("kretprobe/binder_transaction")
int gate_binder_exit(void *ctx)
{
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u32 *cnt = bpf_map_lookup_elem(&spawned, &tgid);
    if (!cnt || *cnt < 2)
        return 0; // first (attach) transaction just finished; reply is delivered

    bpf_send_signal(9); // SIGKILL the app process

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (e) {
        e->pid = tgid;
        e->uid = (__u32)bpf_get_current_uid_gid();
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&spawned, &tgid);
    return 0;
}

char _license[] SEC("license") = "GPL";
