#!/usr/bin/env python3
import sys
import os
import time

# Adiciona o diretório src ao path para permitir imports modulares
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from driver.bpf_driver import BPFDriver
from network.tester import NetworkTester
from collector.parser import RTTParser


def main():
    """Ponto de entrada do monitor de latência TCP via eBPF."""
    if len(sys.argv) < 2:
        print(f"Uso: sudo python3 {sys.argv[0]} <dominio> [porta]")
        sys.exit(1)

    domain = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    driver = None

    try:
        # 1. Preparação da Rede
        tester = NetworkTester(domain)
        target_ip = tester.get_ip_int()
        print(f"[+] Alvo: {domain} ({tester.ip})")

        # 2. Inicialização do Kernel (eBPF)
        driver = BPFDriver(obj_path="src/kernel/monitor.bpf.o")
        driver.load(target_ip)
        driver.attach()
        print("[+] Programa eBPF carregado e anexado ao tracepoint do kernel.")

        # 3. Disparo do tráfego TCP (gera o handshake monitorado)
        tester.trigger_test(port)
        time.sleep(0.2)  # Aguarda o kernel processar os eventos

        # 4. Leitura dos resultados direto do mapa BPF
        parser = RTTParser()
        results = driver.read_rtt_results()
        parser.display(results)

        # 5. Comparação com Ping (ICMP)
        ping_val = tester.run_ping()
        parser.report(results, ping_val, domain)

    except KeyboardInterrupt:
        print("\n[+] Encerrando...")
    except Exception as e:
        print(f"[-] Erro: {e}")
    finally:
        if driver:
            driver.close()
        print("[+] Finalizado.")

if __name__ == "__main__":
    main()
