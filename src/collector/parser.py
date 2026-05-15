import os
import socket
import struct
import time

class RTTParser:
    """Responsável por ler o trace_pipe do kernel e formatar os resultados."""
    
    def __init__(self):
        self.trace_path = self._find_trace_pipe()

    def _find_trace_pipe(self):
        """Localiza o arquivo trace_pipe dinamicamente conforme a distro."""
        paths = ["/sys/kernel/debug/tracing/trace_pipe", "/sys/kernel/tracing/trace_pipe"]
        for p in paths:
            if os.path.exists(p):
                return p
        raise RuntimeError("[-] Erro: Sistema de tracing não encontrado.")

    def monitor(self, timeout=5):
        """Lê o trace_pipe até encontrar o marcador RTT_RESULT ou atingir timeout."""
        results = []
        try:
            with open(self.trace_path, "r") as f:
                start_time = time.time()
                while time.time() - start_time < timeout:
                    line = f.readline()
                    if "RTT_RESULT" in line:
                        results.append(line.strip())
                        break
        except PermissionError:
            raise RuntimeError("[-] Erro: Permissão negada. Execute com sudo.")
        return results

    def display(self, results):
        """Formata e exibe os resultados capturados de forma premium."""
        if not results:
            print("[-] Nenhuma medição de RTT capturada (Timeout).")
            return

        for res in results:
            try:
                # Exemplo: RTT_RESULT: RTT: 48 ms (Conn: 3707873472 -> 3457997228)
                rtt_val = res.split("RTT: ")[1].split(" (")[0]
                conn_info = res.split("Conn: ")[1].replace(")", "")
                s_ip_raw, d_ip_raw = conn_info.split(" -> ")
                
                # Conversão de Network Order para IP String
                s_ip = socket.inet_ntoa(struct.pack("=I", int(s_ip_raw)))
                d_ip = socket.inet_ntoa(struct.pack("=I", int(d_ip_raw)))

                print("\n" + "★"*45)
                print(f"  TCP HANDSHAKE RTT: {rtt_val}")
                print(f"  Connection: {s_ip} -> {d_ip}")
                print("★"*45 + "\n")
            except (IndexError, ValueError):
                print(f"[+] Relatório Bruto: {res}")
