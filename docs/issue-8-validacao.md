# Issue #8 — validação e limite de origem

## Implementado

- `/sudo-prompt allow`: último argv não verificado mostrado na sessão → sugestão → editor → confirmação explícita → gravação via ponte sudo existente.
- O formato editado deve corresponder ao pedido anterior. A classificação continua sendo relida por pedido; a gravação não cria cache nem muda o protocolo.
- Escrita com Python do sistema em modo isolado: exige arquivo root regular protegido, ancestrais protegidos, sem symlink/hardlink; usa flock e fsync e mantém dono/modo/conteúdo existente.
- Recusas claras sem histórico, fora do TUI, formato inválido e falhas de gravação. Cancelamento e troca de sessão não executam a gravação pendente.

## Evidência automatizada

Após `git merge feat/pi-secret-run` (já atualizado):

```text
PI_SUDO_PROMPT_TEST_NO_SUDO=1 npm test
77 testes: 61 passam, 16 skip, 0 falhas
```

Os oito testes novos cobrem o comando registrado, edição e confirmação, recusas, cancelamentos, falhas, troca de sessão e escrita real em um chroot com root de user/mount namespace (sem sudo). O texto persistido é classificado: outro cofre/entrada no formato OTP é permitido; `show -s` e `export` continuam não verificados. A estrutura do pacote inclui o novo `.ts`.

Pulados: nove testes que exigem broker instalado e sete testes de exfiltração com sudo real. A primeira execução sem a variável acionou o sudo dos testes preexistentes (sem autenticação); a opção de opt-out foi adicionada após constatar isso, e a validação final não chama sudo. A interação real com o modal do sudo não foi validada neste modo não interativo. O fluxo de produção do sudo, #5, #7 e o bloqueio de #6 permanecem preservados.

## Critério não garantido: origem exclusivamente humana

No runtime instalado, `AgentSession.prompt` chama `_tryExecuteExtensionCommand` antes do evento `input`. `sendUserMessage` usa `expandPromptTemplates: false` por padrão, mas uma extensão pode passar `true`. Nesse caso, uma mensagem de origem programática pode abrir o handler registrado, que não recebe prova de origem.

Texto normal de resposta do modelo não dispara o comando e não foi registrada uma tool para `allow`. Entretanto, **“o agente não tem nenhum caminho para disparar o comando” não é uma garantia fornecida pelo runtime**. A confirmação explícita no TUI protege o caminho implementado contra gravação sem consentimento, mesmo se sudo estiver em cache; não é isolamento contra extensões maliciosas, controle do terminal ou código do mesmo uid que substitua a extensão. Uma garantia absoluta exige mudança de contrato no pi e/ou uma fronteira de confiança fora do processo mutável pelo usuário. Esse critério permanece pendente, sem alegar cumprimento integral da issue.
