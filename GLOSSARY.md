# pi-sudo-prompt

Ponte entre comandos executados pelo pi sem TTY e o usuário, para que segredos digitados no modal cheguem ao comando sem entrar no contexto do agente.

## Segredos

**Segredo durável**:
Segredo que continua válido depois do uso: senha do sudo, senha mestra de cofre, chave, senha de aplicação. Nunca pode entrar no contexto do agente.
_Avoid_: senha (sem qualificar), credencial

**Segredo efêmero**:
Segredo que expira em segundos e serve para um único uso, como o OTP de TOTP. Pode aparecer na saída do tool e no contexto do agente.
_Avoid_: token, código

**Pedido de segredo**:
Quando o agente pede ao usuário um segredo durável para um consumidor. O usuário digita o segredo no modal, e o agente nunca o vê.
_Avoid_: prompt de senha, askpass

## Participantes

**Consumidor**:
O processo que recebe o segredo durável digitado pelo usuário (o `sudo`, o `keepassxc-cli`, ...).
_Avoid_: destino, alvo, comando final

**Broker**:
Componente instalado com dono root que entrega um segredo durável a um consumidor que não é o sudo, por um canal que o agente não consegue ler.
_Avoid_: helper, wrapper, executor
