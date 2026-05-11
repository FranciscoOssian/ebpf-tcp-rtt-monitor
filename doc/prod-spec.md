# Product Specification — eBPF TCP RTT Monitor

## 1. Proposta

Criar um sistema de observabilidade de rede baseado em eBPF para medir a latência do handshake TCP diretamente no kernel Linux, sem depender de ferramentas tradicionais de user-space para a captura dos eventos.

O projeto deve monitorar conexões TCP em tempo real, capturando o momento do envio do pacote `SYN` e posteriormente o recebimento do `ACK`, calculando o tempo entre esses eventos utilizando timestamps internos do kernel.

O sistema servirá como ferramenta educacional e experimental para análise de redes, observabilidade de sistemas Linux e compreensão do fluxo TCP dentro da stack de rede.

---

## 2. Objetivo Principal

- Medir o RTT (Round Trip Time) do handshake TCP.
- Executar a lógica diretamente no kernel via eBPF.
- Minimizar overhead de observabilidade.
- Comparar os valores obtidos com ferramentas tradicionais como `ping`.
- Demonstrar rastreamento de conexões TCP utilizando mapas BPF.

---

## 3. Core Monitoring Flow

- Um host inicia uma conexão TCP.
- O programa eBPF intercepta o evento de envio do pacote `SYN`.
- O timestamp atual é armazenado em um mapa BPF.
- Quando o `ACK` correspondente é identificado, o sistema recupera o timestamp inicial.
- O RTT é calculado.
- O resultado é enviado ao user-space para visualização.
- O usuário pode comparar os resultados com `ping` ou outras ferramentas.

---

## 4. Entidades do Sistema

### 4.1 Conexão TCP

Representa uma conexão identificada pela 4-tuple:

- IP de origem
- Porta de origem
- IP de destino
- Porta de destino

Essa estrutura funciona como chave única para localizar timestamps armazenados no mapa BPF.

---

### 4.2 Mapa BPF

Estrutura persistente dentro do kernel utilizada para:

- armazenar timestamps de SYN
- recuperar informações da conexão
- associar ACKs aos SYNs corretos

O mapa deve ser do tipo hash.

---

### 4.3 Coletor User-space

Aplicação responsável por:

- carregar o programa eBPF
- anexar probes
- ler eventos do kernel
- exibir RTTs ao usuário
- auxiliar no debug

Pode ser implementado utilizando BCC com Python.

---

## 5. Regras do Sistema

- Apenas conexões TCP devem ser monitoradas.
- O sistema deve ignorar conexões incompletas.
- Cada conexão precisa possuir identificação única.
- O programa eBPF não pode causar impacto perceptível no sistema.
- Eventos antigos devem ser removidos do mapa para evitar crescimento indefinido.

---

## 6. Métricas Observadas

### RTT do Handshake TCP

Tempo entre:

- envio do SYN
- recebimento do ACK correspondente

---

### Quantidade de Conexões

Número de conexões TCP observadas durante a execução.

---

### Tempo Médio de Resposta

Média dos RTTs observados.

---

## 7. Ferramentas Previstas

- Linux Kernel 5.15+
- eBPF
- BCC
- Python
- Clang/LLVM
- bpftool
- trace_pipe
- Wireshark (opcional)
- ping

---

## 8. Casos de Uso

### Observabilidade

Visualizar em tempo real a latência de conexões TCP.

### Estudo Acadêmico

Compreender como o kernel Linux processa conexões TCP.

### Diagnóstico

Comparar diferentes RTTs dependendo do destino da conexão.

---

## 9. Limitações Conhecidas

- RTT do handshake TCP não é equivalente ao RTT ICMP do `ping`.
- O projeto não mede throughput.
- Conexões muito rápidas podem dificultar debugging.
- O sistema depende de suporte eBPF do kernel.

---

## 10. Resultado Esperado

Ao executar conexões TCP (ex.: `curl`, `wget`, navegadores), o sistema deve exibir:

- IPs envolvidos
- portas
- timestamps
- RTT calculado

Exemplo:

```text
192.168.0.10:53412 -> 142.250.184.14:443
RTT TCP Handshake: 18 ms
```
