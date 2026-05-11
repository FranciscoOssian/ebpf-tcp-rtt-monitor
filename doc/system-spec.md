# System Specification — eBPF TCP RTT Monitor

## 1. System Overview

O sistema é uma ferramenta de observabilidade baseada em eBPF que executa programas dentro do kernel Linux para monitorar eventos TCP em tempo real.

A arquitetura utiliza:

- programas eBPF em C executando no kernel
- aplicação user-space em Python utilizando BCC
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

- Python + BCC

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

```c
struct conn_key_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};
```

A estrutura identifica unicamente uma conexão TCP.

---

### Timestamp Map

```c
BPF_HASH(start, struct conn_key_t, u64);
```

Armazena:

- chave da conexão
- timestamp do SYN

---

### Event Structure

```c
struct event_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u64 rtt_ns;
};
```

Estrutura enviada ao user-space.

---

## 5. Hooking Strategy

O sistema deve interceptar funções/eventos relacionados ao ciclo TCP.

Possíveis hooks:

- `tcp_v4_connect`
- `tcp_rcv_state_process`
- tracepoints TCP

A escolha final depende:

- estabilidade
- simplicidade
- compatibilidade com o kernel

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
Python Loader
    ↓
BCC compila programa eBPF
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
