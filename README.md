# 🛡️ Detecção e Resposta a Ataques de Força Bruta — Perspectiva Blue Team / SOC

> Documentação técnica do desafio **DIO**, abordado pela ótica **defensiva**: como ataques de força bruta se manifestam em logs, como são **detectados e tunados em SIEM**, investigados (RCA) e mitigados em um ambiente de SOC real.

![Blue Team](https://img.shields.io/badge/Blue%20Team-SOC-1f6feb)
![SIEM](https://img.shields.io/badge/SIEM-Detection%20Engineering-8957e5)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1110-orange)
![NIST](https://img.shields.io/badge/NIST-CSF-success)

---

## ⚠️ Aviso de Confidencialidade

Este material é baseado em **experiência profissional**, porém **todo dado é sanitizado**:
- IPs usam faixas de documentação (**RFC 5737**: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) e RFC 1918 genéricas.
- Usuários, hostnames e nomes de regras são **fictícios/ilustrativos**.
- Nenhuma configuração proprietária, nome de empregador ou cliente, ou lógica de detecção real é divulgada.

O objetivo é demonstrar **metodologia e raciocínio técnico** de detecção, não reproduzir ambiente de produção.

---

## 📑 Sumário

1. [Por que documentar força bruta pela ótica defensiva](#-por-que-documentar-força-bruta-pela-ótica-defensiva)
2. [Anatomia do ataque](#-anatomia-do-ataque)
3. [Como a força bruta aparece nos logs](#-como-a-força-bruta-aparece-nos-logs)
4. [Engenharia de detecção no SIEM](#-engenharia-de-detecção-no-siem)
5. [Redução de falsos positivos (tuning)](#-redução-de-falsos-positivos-tuning)
6. [Investigação e Resposta — Playbook](#-investigação-e-resposta--playbook)
7. [Análise de Causa Raiz (RCA)](#-análise-de-causa-raiz-rca)
8. [Mapeamento MITRE ATT&CK e Kill Chain](#-mapeamento-mitre-attck-e-kill-chain)
9. [Mitigações](#-mitigações)
10. [Métricas de eficácia](#-métricas-de-eficácia)
11. [Conclusão e aprendizados](#-conclusão-e-aprendizados)
12. [Referências](#-referências)

---

## 🎯 Por que documentar força bruta pela ótica defensiva

Força bruta (MITRE **T1110**) é um dos eventos mais frequentes no dia a dia de um SOC — e justamente por isso é onde mora a maior parte do **ruído** (falsos positivos) e das oportunidades de tuning. Executar o ataque num lab ensina *como ele funciona*; documentar a **detecção** ensina o que realmente importa para quem defende: separar sinal de ruído, priorizar, investigar e conter.

Este repositório foca em três perguntas que um analista responde todo dia:
1. **Isto é ataque ou comportamento legítimo?** (ex.: serviço com senha expirada gerando falhas em rajada)
2. **Se é ataque, teve sucesso?** (a diferença entre `failed` e `failed → success`)
3. **Como reduzo a recorrência?** (tuning + mitigação na fonte)

---

## 🧬 Anatomia do ataque

| Técnica | Lógica | Pegada no log | MITRE |
|---|---|---|---|
| **Brute Force clássico** | N senhas → 1 conta | Muitas falhas, **mesma conta**, mesma origem | T1110.001 |
| **Password Spraying** | 1 senha → N contas | Poucas falhas por conta, **muitas contas**, mesma origem | T1110.003 |
| **Credential Stuffing** | Pares vazados usuário:senha | Falhas distribuídas, origens variadas, baixa repetição | T1110.004 |

O detalhe que mais engana detecção: **spraying não dispara `account lockout`**. Uma regra ingênua de "X falhas na mesma conta" passa batido. A detecção precisa pivotar por **origem + diversidade de contas**, não por contagem numa única conta.

---

## 🪵 Como a força bruta aparece nos logs

### Windows — Event ID 4625 (An account failed to log on)

O campo decisivo é o **Sub-Status Code**, que diz *por que* falhou:

| Sub-Status | Significado | Relevância para detecção |
|---|---|---|
| `0xC000006A` | Senha incorreta (usuário existe) | Núcleo do brute force |
| `0xC0000064` | Usuário **não existe** | Enumeração / spraying cego |
| `0xC0000234` | Conta **bloqueada** (lockout) | Ataque já disparou defesa |
| `0xC0000072` | Conta desabilitada | Tentativa contra conta morta |
| `0xC000015B` | Logon type não permitido | Pode indicar movimentação lateral |

O campo **Logon Type** também orienta a severidade:
- `Type 3` (Network) → SMB, compartilhamentos
- `Type 8` (NetworkCleartext) → logon web/IIS, básico
- `Type 10` (RemoteInteractive) → **RDP**, alto valor para o atacante

> 💡 Correlacionar `4625` (falha) seguido de `4624` (sucesso) da **mesma origem para a mesma conta** é o sinal de **brute force bem-sucedido** — a transição que mais importa.

**Exemplo ilustrativo (sanitizado):**
```
EventID=4625  Account=jsilva  Source=203.0.113.45  LogonType=10  SubStatus=0xC000006A
EventID=4625  Account=jsilva  Source=203.0.113.45  LogonType=10  SubStatus=0xC000006A
... (repetido N vezes em segundos) ...
EventID=4624  Account=jsilva  Source=203.0.113.45  LogonType=10   ← ⚠️ SUCESSO
```

### Outros vetores
- **FTP / SSH (Linux):** `auth.log`, `/var/log/secure` — `Failed password for <user> from <ip>`.
- **Web (form login):** `access.log` — rajada de `POST /login` da mesma origem, respostas de tamanho idêntico (falha) seguidas de redirect (sucesso).
- **VPN / Portal / O365:** logs de autenticação do provedor — spraying costuma aparecer aqui, de múltiplos IPs (proxy/cloud).

> 📌 **[ESPAÇO PARA SUA EVIDÊNCIA — RawLog sanitizado do seu vetor principal]**
> Substitua o exemplo abaixo pelo seu log alterado (IPs RFC 5737, usuários fictícios).

```
EventID=4625  Account=jsilva  Source=203.0.113.45  Workstation=WKS-INVASOR  LogonType=10  SubStatus=0xC000006A
EventID=4625  Account=jsilva  Source=203.0.113.45  Workstation=WKS-INVASOR  LogonType=10  SubStatus=0xC000006A
... (14 falhas em 38 segundos) ...
EventID=4624  Account=jsilva  Source=203.0.113.45  LogonType=10   ← ⚠️ SUCESSO
```

---

## ⚙️ Engenharia de detecção no SIEM

A detecção de força bruta é uma **regra de correlação com threshold temporal e agrupamento**. Abaixo, a lógica em pseudocódigo (aplicável a LogRhythm AIE, Splunk, Elastic, Sentinel):

```
REGRA 1 — Brute Force (conta única)
  FILTRO:   evento = falha_autenticação
  AGRUPA:   por (origin_ip, account)
  THRESHOLD: COUNT >= 10 em 00:01:00
  AÇÃO:     alerta [Severidade: Média]  → T1110.001

REGRA 2 — Password Spraying (muitas contas)
  FILTRO:   evento = falha_autenticação
  AGRUPA:   por (origin_ip)
  THRESHOLD: DISTINCT(account) >= 8 em 00:10:00
  CONDIÇÃO: COUNT(falhas por conta) <= 3   // abaixo do lockout, por isso o spraying
  AÇÃO:     alerta [Severidade: Alta]  → T1110.003

REGRA 3 — Brute Force BEM-SUCEDIDO (a que importa)
  SEQUÊNCIA:
    (A) >= 8 falhas (origin_ip → account) em 00:05:00
    SEGUIDO DE
    (B) 1 sucesso (mesma origin_ip → mesma account) em 00:05:00
  AÇÃO:     alerta [Severidade: Crítica] + acionar IR  → T1110 + Credential Access
```

> No **LogRhythm**, isso se materializa como *AI Engine Rules* com blocos `Log Observed` + `Threshold` e agrupamento por `Origin Host` / `Login`. A Regra 3 usa um bloco de **sequência** (`Followed By`) — é a de maior valor e menor ruído, porque exige o sucesso.

### Pirâmide de prioridade
```
         ╱ Regra 3 (sucesso) ╲   ← crítico, baixo volume, alta fidelidade
        ╱────────────────────╲
       ╱  Regra 2 (spraying)  ╲  ← alto, volume médio
      ╱────────────────────────╲
     ╱   Regra 1 (BF simples)   ╲ ← médio, ALTO volume → onde mora o FP
    ╱────────────────────────────╲
```

> 📌 **[ESPAÇO PARA SUA EVIDÊNCIA — descreva como estrutura seus casos de uso]**
> Ex.: "Separo as detecções por fonte (O365 e Windows) e por severidade; a regra de sucesso tem prioridade de triagem." (adapte e sanitize)

---

## 🎯 Aprofundamento: os dois vetores predominantes

### A) Password Spraying em O365 / Entra ID

**Fonte de log:** O365 Management Activity API / Entra ID (Azure AD) Sign-in logs — ingeridos no SIEM via log source dedicado do O365.

**Campos que importam na triagem:**

| Campo | Uso na detecção |
|---|---|
| `UserId` / `Login` | Identifica a conta-alvo (contar **distintos** = spraying) |
| `ClientIP` | Origem — spraying vem de poucos IPs (cloud/proxy) ou de muitos |
| `Operation` | `UserLoggedIn`, `UserLoginFailed` |
| `ResultStatus` / error code | O "porquê" da falha (tabela abaixo) |
| `UserAgent` | **`BAV2ROPC`** e similares denunciam **legacy/basic auth** |
| `ApplicationId` | App-alvo (Exchange, SharePoint...) |

**Error codes AADSTS (conhecimento público da Microsoft):**

| Código | Significado | Sinal |
|---|---|---|
| `AADSTS50126` | Usuário ou senha inválidos | **Núcleo do spraying** |
| `AADSTS50053` | Conta bloqueada (smart lockout) | Ataque disparou defesa |
| `AADSTS50055` | Senha expirada | Possível FP ou conta-alvo |
| `AADSTS50076` | MFA exigido (credencial correta!) | ⚠️ senha acertada, MFA segurou |
| `AADSTS50128/50059` | Tenant/domínio inválido | Enumeração cega |

> 💡 O par mais crítico: `AADSTS50126` (senha errada) em várias contas, **seguido de** `AADSTS50076` numa delas → o atacante **acertou a senha** e só o MFA barrou. Isso é incidente, não ruído: a credencial está comprometida.

**O grande habilitador — Legacy Auth:** protocolos legados (POP, IMAP, SMTP AUTH, ActiveSync básico) **ignoram MFA e Conditional Access**. Spraying mira neles. Detectar `UserAgent = BAV2ROPC` ou autenticação por protocolo legado é meio caminho andado.

**Desenho de regra AIE — Spraying O365 (ilustrativo):**
```
Nome: O365 - Password Spraying (Multiplas Contas, Mesma Origem)
  Log Source Type: MS Office 365 Management Activity
  Bloco 1 — Log Observed:
     Classification = Failed Authentication
     Vendor Msg ID / Result = AADSTS50126
  Bloco 2 — Unique Values (Threshold):
     Group By:  Origin Host (ClientIP)
     Contar:    DISTINCT(Login)  >= 8
     Janela:    10 minutos
     Condição:  COUNT(falhas por Login) <= 3   // abaixo do smart lockout
  Ação: Alarme [Alta] → T1110.003
```
```
Nome: O365 - Spray com Sucesso / Impossible Travel
  Bloco 1 — sequência de falhas (como acima)  FOLLOWED BY
  Bloco 2 — Log Observed:
     Classification = Authentication Success  (UserLoggedIn)
     mesmo Login, dentro de 30 min
  Enriquecimento: GeoIP divergente (impossible travel)
  Ação: Alarme [Crítico] → acionar IR
```

> 📌 **[ESPAÇO PARA SUA EVIDÊNCIA — RawLog sanitizado de spray O365]**
> Substitua pelos seus dados alterados.

```
Operation:  UserLoginFailed
UserId:     msouza@exemplo.corp
ClientIP:   198.51.100.22
ErrorCode:  AADSTS50126 (Invalid username or password)
UserAgent:  BAV2ROPC   ← legacy auth (ignora MFA)
Status:     Failure
→ mesma ClientIP tentou 11 contas distintas em 9 min, 1-2 tentativas cada
```

---

### B) Rajadas de 4625 no ambiente On-Premises

**Fonte de log:** Windows Security Event Log (DCs, member servers, estações) — Event ID **4625**.

A tabela de **Sub-Status** e **Logon Type** (seção anterior) é o coração da triagem aqui. O que separa ataque de ruído on-prem:

| Observação | Leitura |
|---|---|
| Mesmo `Origin Host` → 1 `Target Account`, N falhas | Brute force clássico (T1110.001) |
| Mesmo `Origin Host` → N contas, poucas falhas cada | Spraying interno (T1110.003) |
| `LogonType=10` (RDP) + falhas | Alta prioridade — superfície valiosa |
| `SubStatus=0xC0000064` (user inexistente) | Enumeração — atacante chutando usuários |
| Rajada vinda de um **servidor de aplicação** | Forte candidato a FP (credencial cacheada) |

**Desenho de regra AIE — Brute Force On-Prem (ilustrativo):**
```
Nome: Win - Brute Force (4625) por Origem
  Log Source Type: MS Windows Event Log - Security
  Bloco 1 — Log Observed:
     Common Event = Authentication Failure (EventID 4625)
     Sub-Status IN (0xC000006A, 0xC0000064)
  Bloco 2 — Threshold:
     Group By:  Origin Host, Login
     Contar:    >= 10
     Janela:    1 minuto
  Ação: Alarme [Média] → T1110.001
```
```
Nome: Win - Brute Force BEM-SUCEDIDO (4625 -> 4624)
  Bloco 1 — Threshold: >= 8 x EventID 4625 (Origin Host -> Login), 5 min
  FOLLOWED BY
  Bloco 2 — Log Observed: EventID 4624 (sucesso), mesmo Origin Host -> Login, 5 min
  Ação: Alarme [Crítico] + IR → T1110 + Credential Access
```

> Atenção ao **LogonType** no agrupamento: separar RDP (Type 10) e Network/SMB (Type 3) em regras distintas permite severidades e tunings diferentes — RDP exposto merece gatilho mais sensível.

> 📌 **[ESPAÇO PARA SUA EVIDÊNCIA — RawLog + triagem de uma rajada de 4625]**
> Substitua pelos seus dados alterados.

```
EventID=4625  Target=admin_fin   Source=203.0.113.88  Host=SRV-APP01  LogonType=3  SubStatus=0xC0000064
EventID=4625  Target=admin_rh    Source=203.0.113.88  Host=SRV-APP01  LogonType=3  SubStatus=0xC0000064
EventID=4625  Target=admin_ti    Source=203.0.113.88  Host=SRV-APP01  LogonType=3  SubStatus=0xC000006A
→ spraying interno: 9 contas distintas da mesma origem em 6 min. Desfecho: sem 4624 (sucesso) → bloqueio do IP + hunt.
```

---

## 🔧 Redução de falsos positivos (tuning)

A Regra 1 é a que mais gera ruído. Fontes comuns de **falso positivo** e como tratá-las:

| Causa raiz do FP | Padrão no log | Tratamento |
|---|---|---|
| Senha de serviço expirada | Mesma conta (service account), mesmo host, 24/7 | Allowlist da conta + alerta separado de "credencial expirada" |
| App com credencial cacheada antiga | Falhas de um app server específico | Exceção por `origin_host` + ticket para o time de app |
| Dispositivo móvel com senha trocada | Falhas de IP de VPN/wifi, 1 usuário | Correlacionar com troca de senha recente (suprimir) |
| Scanner/monitoração interno | Origem conhecida, periódica | Allowlist de ativos de segurança |
| **O365:** mailbox compartilhada / app com token velho | Mesma conta, `AADSTS50126` recorrente de IP interno | Exceção por `Login`+app; abrir ticket p/ reconfigurar |
| **O365:** cliente legacy auth legítimo | `UserAgent=BAV2ROPC` de usuário conhecido | Migrar para modern auth e então bloquear legacy |

**Princípio de tuning:** nunca suprimir cegamente por volume. Primeiro **identificar a causa raiz** do FP, depois criar a exceção **mais específica possível** (preferir `host+conta` a `host` inteiro). Documentar cada exceção — exceção sem justificativa vira ponto cego.

> Métrica-chave: **taxa de FP** antes/depois do tuning. Reduzir ruído aumenta a confiança do analista no alerta (menos *alert fatigue*).

> 📌 **[ESPAÇO PARA SUA EVIDÊNCIA — caso de falso positivo que você tunou]**
> Ex.: "Service account `svc_backup` gerava rajada de 4625 toda madrugada por senha expirada. Após allowlist por conta+host, os alertas dessa regra caíram significativamente, sem perder cobertura de ataque real." (adapte e sanitize)

---

## 🚨 Investigação e Resposta — Playbook

> **Versão sanitizada de um playbook de produção.** Nomes de grupos, hosts, contas, pessoas e runbooks internos foram substituídos por placeholders genéricos (`GRP-*`, `XX-0*`, "time de IAM", "runbook interno", "ITSM"). A lógica de decisão é preservada.

### Etapa 1 — Identificação
1. Identificar o **User (Origin)** e o **Host (Origin)** que geraram a falha.
2. Contatar o usuário e questionar se está com dificuldade de login ou se trocou de equipamento.
   - *Sem retorno do usuário:* acionar o **gestor direto** do colaborador e solicitar apoio.

### Etapa 2 — Validações iniciais (Azure AD / Entra ID)
1. **Última alteração de senha** — consultar no Entra ID (runbook interno).
   - Se a última troca foi há **mais de 90 dias** → tratar como **senha expirada** (Cenário D).
2. **Status do MFA** — assegurar que o usuário está com MFA ativo (runbook interno).
   - Se **inativo** e o usuário **não é VIP**: adicionar ao grupo `GROUP-O365-MFA`, marcar "troca de senha no próximo logon" no AD e acionar o **time de IAM** para forçar a troca no Entra ID.
3. **Revogar sessões** ativas no Entra ID (runbook interno).

### Etapa 3 — Cenários de desfecho

**A) Usuário acabou de alterar a senha**
- Validar com o usuário se foi ele quem trocou a senha e se possui MFA ativo.
- Estando tudo correto: anexar evidências ao Case e **encerrar**.

**B) Conta de terceiro com host fora do padrão corporativo** *(User com prefixo de terceiro e Host fora do padrão `XX-0*`)*
- Validar se a máquina está conectada à rede corporativa.
  - *Regra:* máquinas de terceiros só devem conectar pela **rede segmentada de consultores** ou **VPN**.
- Se a máquina de terceiro estiver em rede diferente da de consultores: orientar o colaborador a usar exclusivamente essa rede e reportar ao **N2**.
- Se estiver via **VPN**: validar que o colaborador está apenas no grupo de VPN novo com MFA (`GROUP-MFA-VPN`).
  - Se estiver em grupo de VPN fora do padrão: escalar ao **N2** para avaliar remoção do grupo.

**C) Reincidência mesmo após troca de senha**
- Abrir incidente no **ITSM** (runbook interno de abertura de chamado).
- Alterar o status do alerta para **Closed: Reported** e registrar o número do chamado no Case do SIEM.
- Acompanhar o chamado diariamente; ao resolver, anexar evidências e **encerrar**.

**D) Senha expirada**
- Realizar a troca da senha e comunicar o gestor direto (modelo interno de brute force com senha expirada).
- Anexar evidências ao Case e **encerrar**.

**E) Conta bloqueada**
- Desbloquear a conta e realizar a troca de senha, comunicando o gestor direto (modelo interno de brute force com conta bloqueada).
- Anexar evidências ao Case e **encerrar**.

**F) Conta de serviço**
- Contatar diretamente o analista responsável pela conta, repassando o máximo de informações para identificar a origem das falhas.
- Orientar a execução do procedimento de **limpeza de credenciais** na máquina que gera as falhas.
- Anexar evidências ao Case e **encerrar**.
- *Sem retorno, resposta insatisfatória ou reincidência:* escalar ao **N2**.

> 💡 **Pergunta decisiva em qualquer cenário:** houve um `4624` (sucesso) da mesma origem? Sem sucesso, é contenção e tuning; **com** sucesso, vira resposta a incidente (isolar, resetar, revogar sessões, caçar persistência/movimentação lateral).

### Threat Hunting proativo
Mesmo sem alerta, hunts úteis:
- Contas com **alto volume de 4625** nos últimos 7 dias agrupadas por origem.
- **Spraying lento** ("low and slow"): 1–2 falhas por conta, mas dezenas de contas da mesma origem ao longo de horas — escapa de thresholds curtos.
- Falhas em **contas desabilitadas/inexistentes** (`0xC0000064`/`0xC0000072`) → sinal forte de enumeração.

---

## 🔬 Análise de Causa Raiz (RCA)

Quando um brute force **tem sucesso**, o RCA responde *como chegamos aqui*:

| Camada | Pergunta de RCA | Falha típica |
|---|---|---|
| Autenticação | Havia MFA? Lockout policy? | MFA ausente na superfície exposta |
| Exposição | Por que o serviço estava acessível? | RDP/SMB exposto à internet |
| Credencial | Senha fraca/padrão/vazada? | Política de senha fraca |
| Detecção | O alerta disparou a tempo? | Threshold mal calibrado / gap de log |
| Resposta | Quanto tempo até conter? | MTTD/MTTR altos |

O RCA não para no "senha fraca" — segue até a **falha de controle** que permitiu o vetor existir, e gera ações corretivas rastreáveis.

> 📌 **[ESPAÇO PARA SUA EVIDÊNCIA — RCA de um caso]** (pode ser hipotético-realista)
> Ex.: conta de usuário comprometida via spraying O365 porque o legacy auth (IMAP) estava habilitado e ignorava o MFA. Ação corretiva: bloquear legacy auth no tenant + Conditional Access exigindo MFA. (adapte e sanitize)

---

## 🎯 Mapeamento MITRE ATT&CK e Kill Chain

| Técnica | ID | Observável de detecção |
|---|---|---|
| Brute Force | **T1110** | Volume de falhas de auth |
| Password Guessing | T1110.001 | Falhas concentradas em 1 conta |
| Password Spraying | T1110.003 | 1 senha, muitas contas |
| Credential Stuffing | T1110.004 | Pares vazados, origens distribuídas |

**Cyber Kill Chain:** o brute force vive em **Exploitation → Credential Access**. Se bem-sucedido, habilita **Lateral Movement** (T1021) e **Persistence** — por isso a Regra 3 (sucesso) aciona resposta imediata.

---

## 🔒 Mitigações

| Vetor | Controle | Efeito |
|---|---|---|
| Qualquer | **MFA** | Quebra o ataque mesmo com senha correta — controle de maior impacto |
| Qualquer | **Account lockout** (com cuidado p/ não virar DoS) | Interrompe BF clássico |
| Qualquer | **Rate limiting** / `fail2ban` / bloqueio de IP | Reduz velocidade e ruído |
| Spraying | Banir **senhas comuns**, monitorar "1 senha → N contas" | Fecha a lacuna do lockout |
| RDP/SMB | Tirar da internet; **VPN + MFA**; segmentação | Elimina a superfície |
| Credencial | Política de senha forte + checagem de vazamento (HIBP) | Reduz chance de sucesso |
| Detecção | Tuning contínuo + hunts de "low and slow" | Pega o que threshold perde |

> Alinhamento **NIST CSF**: *Protect* (MFA, política de senha), *Detect* (regras + hunting), *Respond* (playbook de IR).

---

## 📊 Métricas de eficácia

O que um SOC acompanha para provar que a detecção funciona:

- **MTTD** (tempo médio de detecção) de eventos de BF.
- **Taxa de falsos positivos** por regra (antes/depois de tuning).
- **% de alertas críticos** (Regra 3) vs. ruído (Regra 1).
- Contas privilegiadas visadas por período.

> 📌 **[ESPAÇO PARA SUA EVIDÊNCIA — métricas, se puder compartilhar]** (opcional)
> Pode deixar vazio ou colocar valores ilustrativos (ex.: "MTTD médio de X min para eventos de BF").

---

## 📝 Conclusão e aprendizados

Conduzir eventos relacionados a ataques de força bruta sob a ótica defensiva reforçou algo que vivencio diariamente no SOC: o maior desafio nem sempre é identificar um ataque, mas lidar com o enorme volume de eventos que chegam a todo momento. Seja por senhas expiradas, configurações incorretas, problemas de integração ou até situações críticas envolvendo falsos positivos e falsos negativos, a dificuldade real está em separar o ruído daquilo que realmente exige atenção. Na prática, grande parte das falhas de autenticação acaba sendo gerada por serviços com credenciais expiradas, aplicações utilizando tokens antigos ou processos legítimos mal configurados. Tratar tudo como incidente apenas aumenta a fadiga operacional e reduz a capacidade de resposta do time.

O principal aprendizado dessa experiência foi entender que detectar uma tentativa, por si só, tem pouco valor quando analisada isoladamente. O que realmente muda o cenário é identificar quando uma dessas tentativas se transforma em sucesso. Uma sequência de eventos 4625 sem um 4624 correspondente costuma representar apenas mais um caso de ajuste fino nas regras ou correção de configuração. Já quando observamos a transição de falha para sucesso a partir da mesma origem, o contexto muda completamente: deixa de ser apenas monitoramento e passa a exigir uma resposta efetiva de segurança. Por isso, na minha visão, as detecções mais valiosas não são necessariamente aquelas que contabilizam o maior número de falhas, mas sim as que conseguem correlacionar eventos e fornecer contexto suficiente para indicar comprometimento real.

No ambiente O365, os testes de password spraying evidenciaram as limitações das regras baseadas apenas em limiares por conta. Como o atacante distribui as tentativas entre diversos usuários utilizando poucas senhas, o comportamento normalmente passa longe dos mecanismos tradicionais de bloqueio. Nesses casos, a detecção se torna muito mais eficaz quando a análise é feita pela origem das tentativas e pela quantidade de contas distintas impactadas. Também ficou evidente como a autenticação legada continua sendo um dos principais facilitadores desse tipo de ataque, justamente por não exigir MFA. Já no ambiente on-premises, a análise dos códigos de Sub-Status do evento 4625 mostrou-se extremamente útil para diferenciar tentativas de adivinhação de senha de atividades voltadas à enumeração de usuários, agregando muito mais precisão à investigação.

Por fim, em relação às medidas de mitigação, cheguei à conclusão de que o MFA continua sendo o controle com melhor relação entre esforço e benefício. Mesmo em cenários onde a senha é comprometida, ele adiciona uma barreira capaz de interromper o avanço do atacante antes que o acesso seja efetivamente obtido. Detecções bem ajustadas são fundamentais para reduzir o tempo de resposta e limitar impactos, mas são, em essência, mecanismos reativos. O MFA, por outro lado, atua de forma preventiva e impede que um acerto de credencial se transforme em comprometimento. Depois de analisar diferentes cenários de ataque e detecção, fica claro para mim que monitorar é indispensável, mas fortalecer os controles de acesso continua sendo a forma mais eficaz de fechar a porta antes que alguém consiga entrar.

---

## 📚 Referências

- [MITRE ATT&CK — T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Microsoft — Event 4625 (logon failure) e Sub-Status codes](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [NIST Cybersecurity Framework (CSF)](https://www.nist.gov/cyberframework)
- [Lockheed Martin — Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [Have I Been Pwned — checagem de credenciais vazadas](https://haveibeenpwned.com/)

> Documentação desenvolvida como parte da formação em segurança da **DIO**, a partir de experiência prática em SOC/Blue Team. Todo dado é ilustrativo e sanitizado.
Autor: Welington AV| github.com/wav-cyber
