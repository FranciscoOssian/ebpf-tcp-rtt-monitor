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

    def trigger_test(self):
        """Dispara uma conexão TCP real para o alvo para ativar os hooks eBPF."""
        print(f"[+] Disparando conexão TCP nativa para {self.domain} (IP: {self.ip})...")
        try:
            # Tenta conectar na porta 80 (HTTP) para gerar o handshake
            with socket.create_connection((self.ip, 80), timeout=2):
                print("[+] Conexão TCP estabelecida (Handshake completo).")
                return True
        except Exception:
            print("[!] Aviso: Conexão não completou, mas o SYN foi disparado.")
            return False

    def run_ping(self):
        """Executa um ping real (ICMP) para fornecer um valor de comparação."""
        print(f"[+] Disparando ICMP Ping para comparação...")
        try:
            output = subprocess.check_output(["ping", "-c", "3", self.domain], stderr=subprocess.STDOUT).decode()
            match = re.search(r"min/avg/max/mdev = [\d\.]+/([\d\.]+)/[\d\.]+/", output)
            if match:
                return f"{match.group(1)} ms"
        except Exception:
            pass
        return "Indisponível"
