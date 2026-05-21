# System Specification — eBPF TCP RTT Monitor

## 1. System Overview

O sistema é uma ferramenta de observabilidade baseada em eBPF que executa programas dentro do kernel Linux para monitorar eventos TCP em tempo real.

A arquitetura utiliza:

- programas eBPF em C executando no kernel
- aplicação user-space em Python utilizando libbpf via ctypes (BCC-free)
- mapas BPF para persistência temporária de estado

O sistema segue um modelo orientado a eventos baseado em hooks da stack TCP do kernel.

---

## 2. Architecture Layers (Strict Layering)

### Kernel Layer (eBPF)

Responsável por:

- interceptar eventos TCP
- capturar timestamps
- armazenar dados em mapas BPF
- calcular RTT
- emitir eventos ao user-space

Essa camada deve ser minimalista devido às restrições do verifier do eBPF.

---

### BPF Maps Layer

Responsável pelo armazenamento temporário de:

- timestamps
- identificadores de conexão
- métricas

Os mapas funcionam como ponte entre eventos do kernel.

---

### User-space Layer

Responsável por:

- carregar programas eBPF
- anexar kprobes/tracepoints
- consumir eventos
- exibir logs e métricas
- realizar debugging

Implementação prevista:

- Python + ctypes + libbpf

---

### Debug Layer

Responsável por:

- leitura do `trace_pipe`
- logs de validação
- inspeção via `bpftool`
- troubleshooting do verifier

---

## 3. Technical Constraints

### Restrições do eBPF

O código eBPF:

- não pode acessar memória arbitrária
- não pode executar operações inseguras
- deve sempre terminar
- possui limitações de loops dependendo da versão do kernel
- não pode utilizar bibliotecas tradicionais da user-space

---

### Performance

O sistema deve minimizar overhead.

Operações custosas:

- loops desnecessários
- prints excessivos
- parsing complexo

Devem ser evitadas dentro do kernel.

---

### Compatibilidade

Kernel mínimo:

- Linux 5.15+

---

## 4. Data Model

### Connection Key (4-tuple)

O sistema utiliza a estrutura de 4-tuple como chave para reportar os resultados monitorados, garantindo rastreabilidade completa:

```c
struct four_tuple {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
};
```

**Decisão Técnica**: 
A 4-tuple (Endereços IP e Portas de origem e destino) é extraída do objeto `sock` no Kernel logo que o handshake finaliza. Esta abordagem cumpre os requisitos do projeto, estabelecendo a identidade de rede comum (fluxo TCP) para que as informações sejam reportáveis ao user-space. Internamente, apenas para transição de estados do handshake antes da porta de origem estar disponível, o ponteiro do socket (`sk`) atua de maneira auxiliar rápida.

---

### Timestamp Map

Utiliza um mapa `BPF_MAP_TYPE_HASH` indexado pelo ponteiro do socket (`u64 sk`) para armazenar o timestamp de início (`u64 ns`).

---

### Event Data (Reporting)

Os dados reportados incluem a latência calculada e os endereços IP (4-tuple) extraídos diretamente do objeto `sock` no momento da conclusão do handshake.

## 4. Kernel Data Model

Para rastrear o RTT, utilizamos um Mapa BPF do tipo `HASH`.

#### Estrutura dos Mapas:
1. **Mapa Temporário (`syn_ts`)**:
   - **Tipo**: `BPF_MAP_TYPE_HASH`
   - **Chave**: `u64` (Ponteiro do socket `sk`)
   - **Valor**: `u64` (Timestamp do SYN em ns)

2. **Mapa de Resultados (`rtt_results`)**:
   - **Tipo**: `BPF_MAP_TYPE_HASH`
   - **Chave**: `struct four_tuple` (IPs e portas)
   - **Valor**: `u64` (RTT em microssegundos)

> **Decisão de Projeto**: Optamos por usar a `struct four_tuple` no mapa de resultados final (`rtt_results`) por ser uma métrica que o projeto precisa para fornecer observabilidade completa em cima da conexão TCP. O timestamp de SYN utiliza o socket pointer (`sk`) de forma otimizada para fins meramente efêmeros (o que torna a busca rápida até a construção ser finalizada).

---

## 5. Hook Points (eBPF)

O monitor utiliza dois Kprobes principais:

1.  **`tcp_v4_connect`**: 
    - Disparado no início da tentativa de conexão.
    - Filtra pelo IP alvo informado.
    - Salva o `bpf_ktime_get_ns()` no mapa usando o ponteiro do socket como identificador.
2.  **`tcp_finish_connect`**: 
    - Disparado quando o handshake é concluído com sucesso (recebimento do ACK).
    - Recupera o timestamp inicial, calcula o delta e reporta via `bpf_trace_printk`.

---

## 6. Logic Flow

### Fluxo Geral

```text
TCP SYN
    ↓
Hook eBPF captura evento
    ↓
Timestamp salvo no mapa BPF
    ↓
ACK recebido
    ↓
Lookup da conexão
    ↓
RTT calculado
    ↓
Evento enviado ao user-space
    ↓
Exibição no terminal
```

---

## 7. User-space Flow

```text
Python Driver (ctypes)
    ↓
Libbpf carrega monitor.bpf.o
    ↓
Programa carregado no kernel
    ↓
Kprobe/Tracepoint anexado
    ↓
Leitura contínua de eventos
    ↓
Logs e métricas exibidos
```

---

## 8. Observability & Debugging

Ferramentas utilizadas:

- `sudo cat /sys/kernel/debug/tracing/trace_pipe`
- `bpftool prog`
- `bpftool map`
- `dmesg`
- logs Python

---

## 9. Failure Cases

### ACK sem SYN correspondente

Possíveis causas:

- perda do estado
- corrida temporal
- limpeza prematura do mapa

---

### Verifier Rejection

O verifier pode rejeitar programas por:

- acesso inválido de memória
- complexidade excessiva
- caminhos não seguros

---

### Crescimento do Mapa

Caso entradas antigas não sejam removidas:

- aumento de memória
- degradação de performance

---

## 10. Future Extensions

Possíveis evoluções futuras:

- suporte IPv6
- dashboard web
- exportação Prometheus
- histogramas de latência
- suporte XDP
- comparação automática com ICMP ping
- visualização gráfica em tempo real
