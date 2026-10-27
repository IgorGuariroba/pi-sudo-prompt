# pi-sudo-prompt

Prompt seguro de senha do `sudo` para o [Pi Coding Agent](https://pi.dev), no estilo do *Sudo password prompting* do Cursor.

Quando o agente (ou você, via `!`/`!!`) roda um comando com `sudo`, o pi abre um modal **Sudo Authentication Required** com campo mascarado. A senha vai direto para o `sudo` e **nunca passa pelo modelo**: não aparece no output do tool, na sessão nem no histórico.

```
╭────────────────────────────────────────────────────────────────────╮
│ 🔐 Sudo Authentication Required                                    │
│                                                                    │
│ Command: sudo apt update                                           │
│                                                                    │
│ [sudo] senha para movida:                                          │
│                                                                    │
│ Password: ••••••••                                                 │
│                                                                    │
│ Press Enter to submit, Escape to cancel · auto-cancel in 1:54      │
│                                                                    │
│ Your password is secure and will not be visible to the AI model.   │
╰────────────────────────────────────────────────────────────────────╯
```

## Instalação

```bash
pi install npm:@igor-guari/pi-sudo-prompt
# ou
pi install git:github.com/IgorGuariroba/pi-sudo-prompt@v0.1.0
```

Requer Linux e o pi no modo interativo (TUI).

## Como funciona

```
agente: sudo whoami
        │
        ▼
   sudo -A  ──exec──►  pi-askpass  (SUDO_ASKPASS)
        ▲                   │  valida: pai é sudo/doas com euid 0
        │ stdout (senha)    │  Unix socket privado + HMAC
        │                   ▼
        │            extensão (sessão do pi)
        │                   │  revalida o processo solicitante
        │                   ▼
        │            modal "Sudo Authentication Required"
```

1. Na sessão, a extensão cria um diretório privado (`$XDG_RUNTIME_DIR/pi-sudo-prompt-*`, modo `0700`) com o socket e o launcher `pi-askpass`.
2. Cada comando do bash tool e dos comandos `!`/`!!` recebe `SUDO_ASKPASS`, `PI_ASKPASS_SOCKET`, `PI_ASKPASS_SECRET` e uma função `sudo()` que acrescenta `-A`. A função não acrescenta `-A` quando o comando já usa `-S`/`--stdin` ou `-A`.
3. O `sudo` executa o auxiliar com o prompt (`[sudo] senha para movida:`). O auxiliar confere se o processo pai é `sudo`/`doas` rodando como root e envia um `password_request` assinado.
4. A extensão revalida no `/proc` (o solicitante é o auxiliar e o pai dele é um sudo privilegiado) e abre o modal.
5. **Enter** responde com `password_response`; **Escape**, o timeout de 120 s ou o fim do `sudo` (por abort do tool, por exemplo) respondem com `password_denied`.
6. O auxiliar imprime a senha no pipe do `sudo` e termina. Se a senha estiver errada, o `sudo` pede de novo, e o modal mostra `Incorrect password, try again (2/3)`.

O cache de credenciais do `sudo` (timestamp) continua valendo: logo depois de autenticar, os próximos comandos podem não pedir senha.

## Limites

- **Só Linux.** A validação usa `/proc`. O suporte a macOS fica para depois.
- **Só no modo interativo.** Em `pi -p`, `--mode json` e RPC nada é injetado, e o `sudo` se comporta como sem a extensão.
- **Substitui o tool `bash`.** A extensão registra seu próprio `bash` (mesma implementação e renderização do built-in, com `shellCommandPrefix`/`shellPath` das settings). Outra extensão que também substitua o `bash` vai conflitar.
- A função `sudo()` só existe no shell do comando. Scripts filhos e `xargs sudo` ainda usam o modal (sem TTY, o `SUDO_ASKPASS` basta), mas não recebem o `-A` forçado.
- **Modelo de ameaça:** a extensão protege a senha contra o *modelo* e os registros da sessão. Ela não protege contra outro processo malicioso rodando com o seu usuário. Esse processo poderia, por exemplo, ler a memória do pi ou instalar um keylogger, e ver o segredo HMAC no env não dá a ele a senha. Por isso o modal mostra o comando que será autorizado: confira antes de digitar.

## Desenvolvimento

```bash
npm test                      # protocolo, auxiliar e função sudo()
pi install ./                 # carrega a cópia local
```

Decisões de arquitetura em [`docs/adr/`](docs/adr/).

## Licença

MIT
