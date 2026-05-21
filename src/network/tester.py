import socket
import struct
import subprocess
import re


class NetworkTester:
    """Dispara tráfego de rede (TCP e ICMP) para validação do monitor."""

    def __init__(self, domain):
        self.domain = domain
        self.ip = self._resolve()

    def _resolve(self):
        """Resolve o nome de domínio para um endereço IP."""
        try:
            return socket.gethostbyname(self.domain)
        except socket.gaierror:
            raise RuntimeError(f"[-] Erro: Não foi possível resolver {self.domain}")

    def get_ip_int(self):
        """Retorna o IP no formato inteiro (Network Byte Order) para o Kernel."""
        return struct.unpack("=I", socket.inet_aton(self.ip))[0]

    def trigger_test(self, port=80):
        """Dispara uma conexão TCP real para ativar o tracepoint eBPF."""
        print(f"[+] Conectando TCP em {self.domain} ({self.ip}:{port})...")
        try:
            with socket.create_connection((self.ip, port), timeout=5):
                print("[+] Handshake TCP completo.")
                return True
        except socket.timeout:
            print("[!] Timeout na conexão TCP.")
            return False
        except ConnectionRefusedError:
            print("[!] Conexão recusada.")
            return False
        except Exception as e:
            print(f"[!] Erro na conexão: {e}")
            return False

    def run_ping(self, count=3):
        """Executa ping ICMP para comparação de latência."""
        print(f"[+] Executando ping para {self.domain}...")
        try:
            output = subprocess.check_output(
                ["ping", "-c", str(count), self.domain],
                stderr=subprocess.STDOUT, timeout=10
            ).decode()
            match = re.search(r"min/avg/max/mdev = [\d\.]+/([\d\.]+)/", output)
            if match:
                return f"{match.group(1)} ms"
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            pass
        return "Indisponível"
