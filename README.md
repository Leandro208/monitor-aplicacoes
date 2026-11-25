# Monitor de Aplicações

Monitora sites e domínios (públicos ou internos via VPN), mostra o status em uma
tela web e envia notificação quando um site cai — e quando volta.

- Cards com estado (No ar / Lento / Instável / Fora do ar / Pausado), latência,
  código HTTP, uptime de 24h e 7 dias e gráfico de latência.
- Detecção de queda com tolerância (só alerta após N falhas seguidas).
- Notificação por **Telegram**, **Google Chat**, **webhook** (Teams/Slack/Discord) e
  **e-mail SMTP**.
- Aviso de **possível perda de VPN**: se todos os sites internos caírem enquanto os
  públicos respondem, ele avisa isso em vez de disparar vários alertas soltos.
- Histórico de incidentes e uptime em SQLite.
- Sites cadastrados em `sites.json`, editáveis pela tela **ou** por SSH (com recarga
  automática, sem reiniciar).
- Somente biblioteca padrão do Python — nada para instalar com `pip`.

---

## Requisitos

- Python 3.9 ou superior (testado no 3.12).
- Nenhuma dependência externa.

## Início rápido

```bash
cd monitor-aplicacoes
python3 app.py senha     # define a senha de acesso (entrada oculta)
python3 app.py           # sobe o servidor
```

Acesse `http://<ip-do-servidor>:8090` e clique em **+ Adicionar site**.

Sem senha definida, a aplicação sobe em **modo somente leitura**: a tela mostra o
status, mas ninguém consegue cadastrar ou alterar nada. Isso evita que qualquer
pessoa da rede use o monitor para sondar hosts internos.

Para mudar porta ou endereço, edite `config.json` (`porta` e `host`) e reinicie.

## Cadastro de sites

Pela tela: **+ Adicionar site**. Campos:

| Campo | Para que serve |
|---|---|
| Nome | Identificação na tela e nas notificações |
| URL | Endereço checado com `GET` (precisa ser `http://` ou `https://`) |
| Rede | `Público` ou `Interno (VPN)` — usado no aviso de VPN caída |
| Status esperado | Códigos HTTP aceitos, ex.: `200` ou `200, 301, 302` |
| Intervalo | De quanto em quanto tempo checar (10–3600 s) |
| Timeout | Tempo máximo de espera (1–60 s) |
| Falhas para alertar | Quantas falhas seguidas antes de considerar fora do ar |
| Palavra-chave | Opcional: texto que precisa aparecer na página (pega tela de erro disfarçada de 200) |
| Ignorar certificado | Para sites internos com certificado inválido |
| Ativo | Pausa a checagem sem remover |
| Notificar | Liga/desliga alertas só deste site |

O botão **Testar URL** faz uma checagem na hora, antes de salvar.

### Pelo arquivo `sites.json`

O arquivo é a fonte de verdade e é recarregado sozinho quando muda. Se ele não
existir, o app cria um com lista vazia na primeira execução (por isso ele não é
versionado no Git: cada instalação mantém o seu).

Exemplo de conteúdo:

```json
{
  "editar_pela_tela": true,
  "sites": [
    {
      "id": "portal-sigeduc",
      "nome": "Portal SIGEDUC",
      "url": "https://sigeduc.exemplo.gov.br",
      "rede": "publico",
      "intervalo_s": 60,
      "timeout_s": 10,
      "status_esperado": [200, 301, 302],
      "palavra_chave": null,
      "falhas_para_alerta": 2,
      "ignorar_certificado": false,
      "ativo": true,
      "notificar": true
    }
  ]
}
```

- `editar_pela_tela: false` transforma a tela em somente leitura (o JSON passa a mandar).
- `id` é opcional; se faltar, é gerado a partir do nome.
- Campos ausentes usam os padrões (60 s, timeout 10 s, 2 falhas, status 200).

## Sites internos e VPN

A checagem é feita **de onde a aplicação roda**. Para monitorar domínios internos,
o monitor precisa estar dentro da VPN (ou numa máquina com rota para eles).

Se você abrir a tela do notebook conectado na VPN mas o monitor estiver rodando num
servidor fora dela, os internos aparecerão como caídos — e a tela vai mostrar o
aviso **"Possível perda de VPN/rede local"**, porque os públicos continuam de pé.

Ao sair da VPN, use o botão **⏸ Pausar internos** no topo para não gerar alarme
falso. Ele pausa todos os sites marcados como `Interno (VPN)` de uma vez.

## Notificações

Configure em **Ajustes → Notificações**, marque os canais desejados e use
**Enviar notificação de teste**.

### Telegram (mais simples)

1. No Telegram, fale com o **@BotFather** e crie um bot (`/newbot`). Ele devolve um
   token parecido com `123456789:AAH...`.
2. Envie qualquer mensagem para o seu bot.
3. Descubra o chat ID:
   ```bash
   curl -s "https://api.telegram.org/bot<SEU_TOKEN>/getUpdates" | grep -o '"chat":{"id":[-0-9]*'
   ```
   Para grupo, o ID começa com `-`. Alternativa: fale com o **@userinfobot**.
4. Cole token e chat ID na aba Notificações e salve.

O token nunca volta para o navegador: depois de salvo, o campo aparece em branco e
só é alterado se você digitar outro.

### Google Chat

1. No espaço do Google Chat, abra **Apps e integrações → Webhooks → Adicionar webhook**.
2. Dê um nome (ex.: "Monitor de Aplicações") e copie a URL
   (`https://chat.googleapis.com/v1/spaces/.../messages?key=...&token=...`).
3. Cole em **Ajustes → Notificações → Google Chat**, uma URL por linha (pode avisar
   várias salas), marque o canal e salve.

A URL é uma credencial: fica em `secrets.json` (600) e não volta para a tela. Para
apagar as URLs salvas, use **Apagar URLs salvas**.

As mensagens vão como **cards nativos** do Chat: cabeçalho com o status (vermelho para
queda, verde para recuperação, âmbar para aviso de VPN), seção de detalhes e botão
**Abrir site**. Se você preencher **URL pública deste monitor** em Ajustes → Geral,
aparece também o botão **Abrir monitor**.

O agrupamento em **thread** (ligado por padrão) mantém todos os alertas de um mesmo
site na mesma conversa, em vez de encher a sala. A política do Workspace pode
exigir liberação de webhooks pelo administrador.

### Webhook (Teams / Slack / Discord)

Cole a URL do webhook. A mensagem é enviada como JSON com os campos `text` e
`content`, cobrindo os três serviços.

### E-mail (SMTP)

Informe servidor, porta, STARTTLS (desligue para porta 465, que usa SSL direto),
usuário, senha, remetente e destinatários (separados por vírgula).

### O que é enviado

- Queda: site, URL, motivo, número de falhas e horário.
- Recuperação: site, URL, latência e tempo total de indisponibilidade.
- VPN: um aviso único quando todos os internos caem e os públicos seguem no ar.

Alertas de queda respeitam um **cooldown** (padrão 5 min) para não floodar.

## Certificados TLS (site abre no navegador, mas o monitor não)

O navegador é tolerante a um erro comum de configuração: quando o servidor **não
envia o certificado intermediário correto**, o Chrome/Firefox baixam o que falta
pela extensão AIA do certificado. Python, curl e OpenSSL não fazem isso — e a
checagem falha com `certificado TLS não validado`.

Sintoma no monitor:

```
certificado TLS não validado (cadeia incompleta ou CA desconhecida)
```

Duas soluções:

1. **Rápida (menos segura):** no cadastro do site, marque **Ignorar certificado TLS
   inválido**. O tráfego continua criptografado, mas a identidade do servidor não é
   verificada.
2. **Correta:** fornecer o certificado que falta. Em **Ajustes → Geral → Arquivo de
   CA extra (PEM)**, informe um arquivo `.pem` com o intermediário.

Para obter o intermediário que falta:

```bash
echo | openssl s_client -connect host:443 -servername host -showcerts \
  | openssl x509 -noout -subject -issuer
```

Se a cadeia enviada não contiver o emissor do certificado do site, baixe-o pela
URL `CA Issuers` do campo AIA:

```bash
openssl x509 -in cert-do-site.pem -noout -text | grep -A2 "Authority Information"
curl -s -o intermediario.pem "http://.../cacert/....crt"
```

Este projeto já vem com `certs/globalsign-atlas-r46-alphaSSL-2026.pem`, necessário
para `*.esig.com.br` (o servidor envia a cadeia incompleta). Se o certificado do
site mudar de emissor, gere um novo arquivo. O ideal é a infraestrutura corrigir a
cadeia enviada pelo servidor.

## Rodar como serviço (systemd)

Crie `/etc/systemd/system/monitor-aplicacoes.service`:

```ini
[Unit]
Description=Monitor de Aplicações
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=monitor
WorkingDirectory=/opt/monitor-aplicacoes
ExecStart=/usr/bin/python3 /opt/monitor-aplicacoes/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now monitor-aplicacoes
sudo journalctl -u monitor-aplicacoes -f
```

Se a VPN for por interface, garanta que o serviço suba depois dela (ajuste `After=`).

## Segurança

- Login com senha (PBKDF2, 200 mil iterações) e sessão em cookie `HttpOnly`.
- Limite de 8 tentativas de login por IP a cada 5 minutos.
- Segredos ficam em `secrets.json` com permissão `600` e fora do Git.
- Só URLs `http://` e `https://` são aceitas; `file://` e afins são recusados.
- A aplicação **não tem HTTPS próprio**. Na rede interna, use atrás de um proxy
  reverso (nginx/Apache) se quiser TLS.
- Quem tem acesso ao servidor pode editar `sites.json` diretamente — é o mesmo
  nível de confiança de quem tem a senha.

## Arquivos e backup

| Arquivo | Conteúdo |
|---|---|
| `app.py` | Aplicação |
| `index.html` | Tela |
| `sites.json` | Sites monitorados (local, criado automaticamente; não versionado) |
| `config.json` | Ajustes gerais |
| `certs/` | Certificados de CA extra para sites com cadeia incompleta |
| `secrets.json` | Senha e credenciais (não versionar) |
| `monitor.db` | Histórico de checagens e incidentes |

Backup mínimo: `sites.json`, `config.json` e `secrets.json`. O `monitor.db` pode
ser recriado (perde-se o histórico). O histórico cru é apagado após
`retencao_dias` (padrão 7); os incidentes ficam.

## API (resumo)

Tudo em JSON. Com login ativo, use o cookie de sessão.

| Método | Rota | Função |
|---|---|---|
| GET | `/api/sessao` | Estado do login |
| POST | `/api/login` · `/api/logout` | Entrar / sair |
| GET | `/api/status` | Status de todos os sites |
| GET | `/api/incidentes` | Últimos incidentes |
| GET/PUT | `/api/ajustes` | Ler / salvar configuração |
| POST | `/api/sites` | Criar site |
| PUT/DELETE | `/api/sites/{id}` | Alterar / remover |
| POST | `/api/sites/{id}/teste` | Checar agora |
| POST | `/api/sites/teste` | Testar uma URL antes de salvar |
| POST | `/api/internos/pausar` | `{"pausar": true}` |
| POST | `/api/notificacoes/teste` | Enviar teste |

## Problemas comuns

| Sintoma | Causa provável |
|---|---|
| Tudo fora do ar, inclusive públicos | Monitor sem internet/DNS, ou firewall bloqueando saída |
| Só internos fora do ar | Monitor fora da VPN (veja o aviso na tela) |
| Site "no ar" mas com tela de erro | Use o campo **Palavra-chave** |
| Erro de certificado em site interno | Veja a seção **Certificados TLS**; use `ca_bundle` ou marque "Ignorar certificado" |
| Notificação do Google Chat retorna 400 | URL errada/expirada; gere outra no espaço do Chat |
| Notificação não chega | Aba Notificações mostra o último resultado; use o teste |
| Tela pede login e não aceita senha | Rode `python3 app.py senha` no servidor |
| Porta em uso | Altere `porta` em `config.json` |
