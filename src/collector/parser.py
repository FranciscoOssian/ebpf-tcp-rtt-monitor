import socket
import struct


class RTTParser:
    """Formata e exibe os resultados de medição de RTT do mapa BPF."""

    @staticmethod
    def ip_to_str(ip_int):
        """Converte inteiro IP (native byte order do kernel) para string dotted."""
        return socket.inet_ntoa(struct.pack("=I", ip_int))

    def display(self, results):
        """Exibe os resultados de RTT formatados com a 4-tuple completa."""
        if not results:
            print("[-] Nenhuma medição de RTT capturada.")
            return

        print(f"\n{'='*55}")
        print(f"  Medições RTT do Handshake realizo no kernel ebpf")
        print(f"{'='*55}")

        for i, r in enumerate(results, 1):
            saddr = self.ip_to_str(r["saddr"])
            daddr = self.ip_to_str(r["daddr"])
            rtt_us = r["rtt_us"]
            rtt_ms = rtt_us / 1000.0

            print(f"\n  Conexão #{i}")
            print(f"  IP Origem:    {saddr}")
            print(f"  IP Destino:   {daddr}")
            print(f"  Porta Origem: {r['sport']}")
            print(f"  Porta Destino:{r['dport']}")
            print(f"  RTT Handshake: {rtt_us} µs ({rtt_ms:.3f} ms)")

        print(f"\n{'='*55}\n")

    def report(self, results, ping_val, domain=""):
        """Gera relatório comparativo entre RTT do eBPF e do Ping ICMP."""
        if results:
            rtt_ms = results[0]["rtt_us"] / 1000.0
            bpf_rtt = f"{rtt_ms:.3f} ms"
        else:
            bpf_rtt = "N/A"

        print(f"\n{'='*55}")
        print(f"  relatório")
        if domain:
            print(f"  Alvo: {domain}")
        print(f"{'='*55}")
        print(f"  Latência eBPF (Handshake TCP):  {bpf_rtt}")
        print(f"  Latência Ping (ICMP):           {ping_val}")
        print(f"{'='*55}\n")
