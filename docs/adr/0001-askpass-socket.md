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
- O segredo HMAC fica visível no env do shell do agente. A garantia real vem das checagens de processo, não do segredo.

## Revisão (0.1.2): checar o pai não basta

Na 0.1.1, o auxiliar e a extensão só conferiam se o pai era um sudo com euid 0. Isso é contornável porque o `exec` mantém o PID: um `SUDO_ASKPASS` malicioso com `exec <auxiliar> > arquivo` passava na checagem e recebia a senha. Também era possível injetar código no auxiliar via `NODE_OPTIONS`/`--import`. Os dois ataques foram reproduzidos com o sudo real.

Agora:

- **stdout do auxiliar:** precisa ser um FIFO anônimo com dono uid 0 e modo `600`, ou seja, o pipe que o sudo cria como root. Um processo do usuário não consegue criar nem reabrir um pipe assim (`/proc/<pid>/fd/1` dá `EACCES`). O auxiliar confere ao iniciar e de novo antes de escrever; a extensão confere no servidor.
- **Launcher:** usa `env -i` com uma lista fixa de variáveis. A extensão exige do auxiliar argv exato, `exe` igual ao node esperado e `environ` exatamente igual ao do launcher.

Continua fora de alcance alterar arquivos que pertencem ao usuário (código do auxiliar, node do nvm). Isso exige um auxiliar com dono root e fica para um modo blindado opcional.

## Revisão (0.1.2): módulos e `/reload`

O pi carrega extensões com jiti (`moduleCache: false`). Arquivos `.ts` são recarregados a cada `/reload`, mas `.mjs`/`.js`/`.cjs` de um pacote `"type": "module"` são importados de forma nativa e ficam no cache do Node até o processo terminar. Cache busting também não funciona: o jiti ignora query string, e o código roda num `vm` sem `import()` nativo. Com um `protocol.mjs` compartilhado, uma atualização seguida de `/reload` misturava a `index.ts` nova com o protocolo velho (`launcherScript is not a function`).

Por isso:

- **Lado do pi:** importa só módulos `.ts` (`protocol.ts`, `modal.ts`). Um teste estático garante isso.
- **Auxiliar:** `askpass.mjs` é autossuficiente e sempre roda num processo novo. As poucas funções que ele duplica (assinatura, checagem de sudo e de pipe) são mantidas em sincronia com `protocol.ts` por `test/interop.test.mjs`.
