#include "vmlinux.h"

#define SEC(NAME) __attribute__((section(NAME), used))

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

static long (*bpf_printk)(const char *fmt, int fmt_size, ...) = (void *) 6;
#define bpf_log(fmt, ...) \
    ({ \
        char ____fmt[] = fmt; \
        bpf_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, u64 flags) = (void *) 2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;
static u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
static long (*bpf_probe_read_kernel)(void *dst, u32 size, const void *unsafe_ptr) = (void *) 113;

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)

volatile const u32 TARGET_IP = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(u64));
} start_map SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int handle_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sockaddr_in *usin = (struct sockaddr_in *)PT_REGS_PARM2(ctx);
    if (!usin || !sk) return 0;

    u32 daddr = 0;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &usin->sin_addr.s_addr);

    if (daddr == TARGET_IP) {
        u64 ts = bpf_ktime_get_ns();
        u64 key = (u64)sk;
        bpf_map_update_elem(&start_map, &key, &ts, BPF_ANY);
    }
    return 0;
}

SEC("kprobe/tcp_finish_connect")
int handle_tcp_finish(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    u64 key = (u64)sk;
    u64 *start_ts = bpf_map_lookup_elem(&start_map, &key);

    if (start_ts) {
        u64 rtt_ms = (bpf_ktime_get_ns() - *start_ts) / 1000000;
        u32 saddr, daddr;

        bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

        bpf_log("RTT_RESULT: RTT: %llu ms (Conn: %u -> %u)\n", rtt_ms, saddr, daddr);
        bpf_map_delete_elem(&start_map, &key);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
