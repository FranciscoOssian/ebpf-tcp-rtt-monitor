//   1. SYN_SENT: salva bpf_ktime_get_ns() no mapa syn_ts
//   2. SYN_SENT -> ESTABLISHED: calcula RTT = now - syn_ts
//   3. Resultado armazenado no mapa rtt_results

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "monitor.h"

char LICENSE[] SEC("license") = "GPL";

#define AF_INET         2
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_CLOSE       7
#define MAX_ENTRIES     1024

const volatile __u32 target_daddr = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, __u64);
} syn_ts SEC(".maps");

/* Mapa de resultados: 4-tuple -> RTT medido .
 * Este é o mapa lido pelo user-space. A chave é a 4-tuple completa
 * , construída no ESTABLISHED quando todos os campos
 * já estão disponíveis. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct four_tuple);
	__type(value, __u64);
} rtt_results SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	/* Filtra apenas TCP sobre IPv4 */
	if (ctx->protocol != IPPROTO_TCP)
		return 0;
	if (ctx->family != AF_INET)
		return 0;

	struct sock *sk = (struct sock *)ctx->skaddr;
	if (!sk)
		return 0;

	__u32 daddr = 0;
	bpf_probe_read_kernel(&daddr, sizeof(daddr),
			      &sk->__sk_common.skc_daddr);

	/* Aplica filtro de IP destino (se configurado) */
	if (target_daddr && daddr != target_daddr)
		return 0;

	int oldstate = ctx->oldstate;
	int newstate = ctx->newstate;
	__u64 sk_key = (__u64)sk;

	if (newstate == TCP_SYN_SENT) {
		/*
		 * SYN enviado pelo cliente.
		 * Salva o timestamp indexado pelo ponteiro do socket.
		 */
		__u64 ts = bpf_ktime_get_ns();
		bpf_map_update_elem(&syn_ts, &sk_key, &ts, BPF_ANY);
		bpf_printk("SYN: sk=%llx dport=%d", sk_key, ctx->dport);

	} else if (oldstate == TCP_SYN_SENT && newstate == TCP_ESTABLISHED) {
		/*
		 * SYN_SENT -> ESTABLISHED: handshake completo.
		 * Agora a 4-tuple está completa (sport atribuída).
		 * Calcula RTT e armazena no mapa com chave 4-tuple.
		 */
		__u64 *start = bpf_map_lookup_elem(&syn_ts, &sk_key);
		if (start) {
			__u64 rtt_us = (bpf_ktime_get_ns() - *start) / 1000;

			struct four_tuple key = {};
			bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr),
					      &sk->__sk_common.skc_rcv_saddr);
			key.daddr = daddr;
			key.sport = ctx->sport;
			key.dport = ctx->dport;

			bpf_map_update_elem(&rtt_results, &key, &rtt_us, BPF_ANY);
			bpf_map_delete_elem(&syn_ts, &sk_key);
			bpf_printk("RTT: %llu us %d->%d",
				   rtt_us, key.sport, key.dport);
		}

	} else if (newstate == TCP_CLOSE) {
        // Conexão fechada, realiza a limpeza
		bpf_map_delete_elem(&syn_ts, &sk_key);
	}

	return 0;
}
