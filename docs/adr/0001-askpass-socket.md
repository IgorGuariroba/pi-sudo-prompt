# 0001 — SUDO_ASKPASS + socket privado em vez de PTY ou wrapper

**Status:** aceito

## Contexto

O bash do pi roda sem TTY. Por isso o `sudo` falha com `a password is required`, e a única saída hoje é `echo senha | sudo -S`, que vaza a senha para o modelo, a sessão e o `ps`. Queremos o comportamento do Cursor: o modal pede a senha e a senha vai direto ao `sudo`, sem passar pelo modelo.

## Decisão

Usar o mecanismo oficial do `sudo`: `SUDO_ASKPASS` mais `-A`. O auxiliar (`askpass.mjs`) conversa com a extensão por um socket Unix em diretório `0700`, com mensagens JSON assinadas por HMAC (`password_request` / `password_response` / `password_denied`). Os dois lados validam via `/proc` que o pai do auxiliar é `sudo`/`doas` com euid 0.

O `-A` é forçado por uma função `sudo()` injetada antes do comando, e não pelo `alias sudo='sudo -A'` que o Cursor usa. O alias quebra `sudo -S` (`-A` e `-S` não podem ser usados juntos). A função mantém o efeito do alias e deixa de acrescentar o `-A` quando o comando já usa `-S` ou `-A`.

## Alternativas descartadas

- **Rodar o comando num PTY e detectar `[sudo] senha` na saída:** frágil (prompts localizados, `-p` customizado, buffering), exige módulo nativo e mistura a senha no fluxo do terminal do comando.
- **Wrapper `sudo` no PATH ou reescrever o texto do comando com regex:** não cobre scripts, `bash -c` nem `/usr/bin/sudo`. O `SUDO_ASKPASS` cobre, porque o `sudo` o usa sempre que não há TTY.
- **Pedir a senha num `ctx.ui.input` e repassar via `-S`:** a senha passaria pelo texto do comando.

## Consequências

- Funciona onde o `sudo` funciona sem TTY, inclusive dentro de scripts.
- A extensão precisa substituir o tool `bash` para injetar o env (`spawnHook`), o que conflita com outras extensões que também o substituam.
- Depende de `/proc`, então é só Linux. No macOS seria preciso usar `sysctl`/`libproc`.
- O segredo HMAC fica visível no env do shell do agente. A garantia real vem da checagem de processo (euid 0 do pai), não do segredo.
