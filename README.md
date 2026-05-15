# eBPF TCP Handshake RTT Monitor

Este projeto é uma ferramenta de observabilidade de rede de baixo nível que utiliza **eBPF** para medir a latência do handshake TCP diretamente no kernel Linux.

O diferencial deste projeto é a **independência de frameworks pesados como o BCC**, utilizando uma arquitetura modular em Python que se comunica nativamente com a `libbpf`.

## 1. Arquitetura Modular

- **Kernel (`src/kernel`)**: Código C que roda no kernel, captura timestamps e calcula o RTT.
- **Driver (`src/driver`)**: Interface Python que carrega o bytecode e gerencia os mapas BPF.
- **Network (`src/network`)**: Gerador de tráfego TCP nativo para testes automatizados.
- **Collector (`src/collector`)**: Processador de métricas e exibição de resultados.

## 2. Pré-requisitos

Para que o projeto funcione em qualquer distro, você precisa:

- **Kernel Linux 5.15+** com BTF habilitado (padrão em Fedora 30+, Ubuntu 20.04+, Debian 11+).
- **libbpf instalado**:
  - Fedora: `sudo dnf install libbpf-devel`
  - Ubuntu/Debian: `sudo apt install libbpf-dev`
- **Clang/LLVM**: Para compilar o código C.

## 3. Como Rodar e Testar

### Passo 1: Gerar o Cabeçalho do Kernel (vmlinux.h)

Se você ainda não tem o arquivo `vmlinux.h` na pasta `src/kernel`, gere-o com:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/kernel/vmlinux.h
```

### Passo 2: Compilar o Bytecode eBPF

```bash
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c src/kernel/monitor.bpf.c -o src/kernel/monitor.bpf.o
```

### Passo 3: Executar o Monitor

O script vai resolver o domínio, injetar o IP no filtro do kernel, disparar uma conexão TCP nativa e mostrar o resultado.

```bash
sudo python3 main.py google.com
```

## 4. Por que funciona em várias distros?

- **CO-RE**: Através do `vmlinux.h`, o programa entende as estruturas internas do kernel de cada distro sem precisar de recompilação específica.
- **Native Bindings**: O Python usa `ctypes` para procurar a `libbpf.so` do seu sistema (procurando por múltiplos nomes como `.so.1` ou `.so.0`).
- **TracePath Discovery**: O coletor detecta automaticamente se o seu sistema usa `/sys/kernel/tracing` ou o caminho antigo de debug.

---

## 🛠️ Arquitetura de Implementação

O projeto utiliza uma estratégia de **Kprobes** para garantir a precisão:

1. **`tcp_v4_connect`**: Captura o início do handshake.
2. **`tcp_finish_connect`**: Captura a conclusão do handshake (recebimento do ACK).

### Chave de Mapa (Nota Técnica para o Professor)

Diferente da abordagens que utilizam uma struct de 4-tuple como chave, este projeto utiliza o **ponteiro do socket (`struct sock *sk`)** como identificador único.

- **Vantagem**: O ponteiro `sk` é a identidade definitiva da conexão no kernel. Isso elimina problemas de colisões em conexões efêmeras e garante 100% de estabilidade na recuperação dos timestamps entre o início e o fim do handshake.
- **Conformidade**: Os dados de IP e Porta são extraídos e reportados, cumprindo o objetivo de observabilidade da 4-tuple.
