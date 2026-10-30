# 0002 — Broker root para entregar segredos duráveis a consumidores que não são o sudo

**Status:** aceito

## Contexto

O bash do agente roda sem TTY, e só o `sudo` consegue pedir senha ao usuário (ADR 0001). Outros consumidores, como `keepassxc-cli`, `curl -H @-`, `gh auth login --with-token` e `docker login --password-stdin`, precisam de um **segredo durável** (senha mestra, chave de API, senha de aplicação). Hoje o usuário tem de sair do pi para rodá-los (issue #1).

A regra é que nenhum segredo durável entre no contexto do agente. **Segredos efêmeros**, como o OTP de TOTP, podem entrar.

A garantia do ADR 0001 vem do root, e não do socket nem do HMAC: o sudo cria um pipe com dono uid 0 e modo `0600`, e o agente não consegue reabri-lo. Um consumidor comum roda com o uid do usuário. Testado nesta máquina com `ptrace_scope=1`: um processo do mesmo uid **abre** `/proc/<pid>/fd/0` do pipe de outro processo e lê o que passa por ele. O agente também lê `/proc/<pid>/environ`, porque o `exec` do consumidor o torna dumpable de novo. Sem root, o agente pode capturar o segredo.

## Decisão

- **`pi-secret-run --label "…" -- <cmd> <args>`** é o comando que o agente usa no bash, e também funciona em `!`/`!!`. Ele faz um **pedido de segredo** a um **broker**. Os `promptGuidelines` ensinam o agente a usá-lo. Não há tool dedicada.
- **Broker:** script Python com dono root em `/usr/local/libexec/`, executado pelo `/usr/bin/python3` do sistema (o node do nvm tem o usuário como dono e não pode rodar como root), com uma regra `NOPASSWD` no sudoers só para ele. O broker lê o argv real do consumidor, pede o segredo à extensão pelo socket e cria o canal **como root** (`0600`). Depois executa o consumidor com o uid do usuário, nunca como root. A extensão confere que quem pede é o broker verdadeiro: euid 0 e executável com dono root.
- **Canal:** **stdin** ou **fd herdado** (`/dev/fd/N`, para opções como `--password-file`). **Nunca variável de ambiente.**
- **Genérico, com consentimento informado:** qualquer consumidor funciona. Uma **allowlist** em `/etc/pi-sudo-prompt/allowlist`, com dono root, só decide qual modal aparece. Cada item é **executável + formato de argumentos**, porque o executável inteiro deixaria passar `keepassxc-cli show -s`/`export`, que imprimem senhas de aplicação. A allowlist é instalada vazia, com exemplos comentados. Edita-se com `sudoedit` ou com `/sudo-prompt allow` (só o usuário dispara, e o comando passa pelo sudo).
- **Modal:** mostra o argv real lido pelo broker e a descrição do agente marcada como "não verificada". O título nunca é o do modal do sudo. Fora da allowlist, aparece um aviso vermelho: "este comando pode mostrar ao agente o que você digitar".
- **Sem cache:** cada pedido de segredo abre o modal.
- **Instalação:** pelo `/sudo-prompt install-broker` (só o usuário dispara, e a senha do sudo vem do modal atual) ou por um script manual. A extensão compara a versão do protocolo do broker e recusa quando ela não bate. Sem broker, ou fora do TUI, o `pi-secret-run` **recusa** e explica o motivo, sem cair para um modo inseguro.
- **O sudo continua no `SUDO_ASKPASS`** (ADR 0001) e não precisa do broker.

## Alternativas descartadas

- **Helper sem root (`pi-askpass "…" | cmd`, como sugeria a issue):** o stdout dele é legível pelo agente, e o pipe do consumidor pode ser reaberto por `/proc`. Também facilita o phishing da senha do sudo.
- **Variável de ambiente:** fica legível em `/proc/<pid>/environ` do consumidor e passa para os filhos dele. Ferramentas que só leem variáveis usam um wrapper que lê o stdin, e isso cai no aviso vermelho.
- **TTY falso:** mais código rodando como root para ferramentas que leem `/dev/tty`, sem ganho no caso de uso.
- **Só uma allowlist fechada, sem modo genérico:** dispensa a atenção do usuário, mas não é genérico. O aviso vermelho cobre os demais casos.
- **Allowlist só por executável:** vaza o conteúdo de cofres sem aviso.
- **Allowlist em `~/.pi`:** o agente poderia editá-la e se incluir.
- **Cache do segredo:** deixa o segredo minutos na memória do pi. Um cache por executável deixaria o agente reutilizar o segredo sem modal.
- **`sudo pi update` para instalar o broker:** o `pi` do nvm não está no `secure_path`, usaria `/root/.pi` e rodaria scripts de pacotes como root.

## Consequências

- A instalação deixa de ser só `pi install` para quem quiser segredos que não são do sudo. O broker é um passo separado, feito como root.
- O broker é código que roda como root e precisa ser pequeno e auditável. Ele e a extensão precisam ficar na mesma versão do protocolo.
- Fora da allowlist, a garantia depende de o usuário ler o comando no modal. Se ele aprovar um destino que ecoa o segredo (`cat`), o segredo vaza por escolha dele.
- Continua sendo só Linux (`/proc`).
