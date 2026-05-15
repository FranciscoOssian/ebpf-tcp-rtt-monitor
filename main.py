#!/usr/bin/env python3
import sys
import os

# Adiciona o diretório src ao path para permitir imports modulares
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from driver.bpf_driver import BPFDriver
from network.tester import NetworkTester
from collector.parser import RTTParser

def main():
    """Ponto de entrada do monitor de latência TCP via eBPF."""
    if len(sys.argv) < 2:
        print(f"Uso: sudo python3 {sys.argv[0]} <dominio>")
        sys.exit(1)

    domain = sys.argv[1]

    try:
        # 1. Preparação da Rede
        tester = NetworkTester(domain)
        target_ip_int = tester.get_ip_int()

        # 2. Inicialização do Kernel (eBPF)
        driver = BPFDriver(obj_path="src/kernel/monitor.bpf.o")
        driver.load(target_ip_int)
        driver.attach_all()
        
        # 3. Coleta e Teste
        collector = RTTParser()
        
        # Dispara o tráfego TCP para gerar medição
        tester.trigger_test()

        # Captura o resultado do handhsake no Kernel
        bpf_results = collector.monitor(timeout=3)
        collector.display(bpf_results)

        # 4. Relatório Comparativo
        ping_val = tester.run_ping()
        print("\n" + "="*45)
        print(f"  RELATÓRIO COMPARATIVO")
        print(f"  Alvo: {domain}")
        print(f"  Latência eBPF (Handshake): {bpf_results[0].split('RTT: ')[1].split(' (')[0] if bpf_results else 'N/A'}")
        print(f"  Latência Ping (ICMP): {ping_val}")
        print("="*45 + "\n")

    except Exception as e:
        print(f"[-] Erro crítico: {e}")
    except KeyboardInterrupt:
        print("\n[+] Encerrando monitor...")
    finally:
        print("[+] Processo finalizado.")

if __name__ == "__main__":
    main()
