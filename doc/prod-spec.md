# Product Specification — eBPF TCP RTT Monitor

## 1. Proposta

O sistema cumpre rigorosamente a lógica estabelecida para o monitoramento:

- **Medição SYN-ACK**: Captura o tempo exato do handshake TCP.
- **BPF Hash Map (4-tuple)**: Utiliza a `struct four_tuple` (IPs e Portas de origem/destino) como chave na exportação de resultados.
  - _Nota_: Utilizar a 4-tuple atende aos requisitos do projeto de observabilidade de redes ao manter a rastreabilidade exata do fluxo TCP, extraindo os dados de rede essenciais do socket assim que o handshake terminar. O ponteiro de socket `sk` continua auxiliando internamente no acompanhamento de tempo entre SYN e ACK.
- **Comparação Real**: Exibe o comparativo direto entre o RTT do eBPF e o RTT do comando `ping` (ICMP).
- **Sem ferramentas de user-space**: Toda a lógica de captura e cálculo reside no Kernel (eBPF).

---

## 2. Diferenciais do Projeto (Plus)

Além dos requisitos básicos, este projeto implementa:

- **Arquitetura Modular**: Separado em Driver (Loader), Network (Tester), Collector (Parser) e Kernel (Core).
- **BCC-Free**: Não depende do framework BCC, utilizando `libbpf` nativa e `ctypes` para maior leveza e portabilidade.
- **Portabilidade CO-RE**: Funciona em múltiplas distribuições (Fedora/Ubuntu) sem necessidade de recompilação específica por kernel.
- **Teste Autossuficiente**: O próprio Python dispara conexões TCP via sockets nativos, eliminando a dependência do `curl`.

---

## 3. Core Monitoring Flow

- O sistema resolve o IP do domínio alvo.
- O programa eBPF é carregado e injeta o IP de filtro via `.rodata`.
- Uma conexão TCP é disparada via socket nativo do Python.
- Hooks:
  - `tcp_v4_connect`: Extrai a 4-tuple e salva o timestamp inicial no Mapa Hash.
  - `tcp_finish_connect`: Recupera o timestamp, calcula o RTT e reporta o valor.
- O sistema dispara um `ping` (ICMP) para gerar o relatório comparativo.

---

## 4. Entidades do Sistema

### 4.1 BPF Maps (State)

Utiliza um mapa do tipo `BPF_MAP_TYPE_HASH` para persistir o tempo de início indexado pelo IP de destino, permitindo monitoramento concorrente.

### 4.2 Loader Nativo (Driver)

Aplicação Python que utiliza `ctypes` para se comunicar com a `libbpf.so` do sistema, permitindo portabilidade total entre Fedora e Ubuntu.

---

## 5. Regras do Sistema

- O bytecode `.o` deve ser gerado pelo usuário no ambiente de destino.
- A ferramenta deve ser 100% autossuficiente (dispara seu próprio teste).
- O filtro de IP deve ser exato para evitar ruído de outras conexões do sistema.

---

## 6. Ferramentas Integradas

- Linux Kernel 5.15+ (com suporte a BTF)
- Clang/LLVM (apenas para compilação do `.o`)
- libbpf
- Python 3.x
- Socket nativo (sem dependência de curl)
