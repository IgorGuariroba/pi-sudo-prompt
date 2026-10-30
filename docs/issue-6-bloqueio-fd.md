# #6 — bloqueio do canal por caminho de arquivo

**Estado:** não implementado; `--fd` continua sem suporte. Não considerar os critérios de aceite da #6 atendidos.

## Experimento reproduzível, sem sudo

```sh
node --test test/fd-channel-constraint.test.mjs
```

O teste usa `unshare -r --map-auto` e Python do sistema. Na user namespace, cria um pipe como uid 0, fixa modo `0600`, herda a leitura no fd 9, troca definitivamente para uid/gid 1 e executa outro processo Python. O segredo é sintético. A fronteira observada é a API Linux do consumidor, não o seam 1 do broker instalado.

Resultado nesta máquina:

- `fstat(9)`: FIFO, dono uid 0, modo `0600`;
- `open('/dev/fd/9', O_RDONLY)`: `EACCES` (13);
- `open('/proc/<próprio pid>/fd/9', O_RDONLY)`: `EACCES` (13);
- depois das tentativas, `read(9)` recebe integralmente `synthetic-secret\n`.

A hipótese de que `/dev/fd/N` permitiria a abertura enquanto `/proc` a negaria foi testada primeiro e falhou (esperado sucesso, obtido errno 13). O teste preserva o comportamento constatado como caracterização do bloqueio. É pulado se Linux/user namespaces/mapeamentos subordinados não estiverem disponíveis; não exige broker instalado nem altera componentes de sistema.

## Por que bloqueia `--password-file`

No Linux com `/dev/fd` apontando para `/proc/self/fd`, abrir esse caminho **não equivale a `dup(N)`**: reabre o inode do pipe e verifica as permissões para o uid atual. O fd herdado já autoriza `read(N)`, mas não concede ao consumidor permissão de reabertura. Isso independe de o pipe já ter sido consumido: o teste tenta abrir antes da leitura.

Assim, a mesma proteção root `0600` que impede o agente de reabrir o pipe também impede a ferramenta com `--password-file /dev/fd/N` de abri-lo após o drop de uid. A recusa por `/proc/self` neste teste não substitui o teste de ataque entre processos do seam 1.

## Alternativas avaliadas

- **Leitura direta do fd herdado:** funciona no experimento e mantém o pipe protegido; requer consumidor que use `read(N)`/`dup(N)`, não resolve ferramentas genéricas que abrem um caminho. Exige mudar o contrato da #6.
- **`chmod`, `chown` ou ACL para permitir a reabertura pelo uid do consumidor:** permite também ao agente com esse mesmo uid passar pela verificação do inode; abandona a garantia exigida. Não adotado.
- **Executar consumidor como root:** viola a spec e cria risco de escalada. Não adotado.
- **Interposição de `open` ou tradução de `/dev/fd/N` em wrapper:** não é compatível genericamente com binários estáticos, runtimes e chamadas diretas ao kernel; não é solução genérica segura.
- **Isolamento adicional (outro uid, namespaces/mounts, controle de acesso):** precisaria de novo projeto e auditoria; não foi implementado nem validado. Não afirmar impossibilidade para todas as arquiteturas, apenas incompatibilidade com a arquitetura atual.

## Pendências para integração

Decidir entre restringir o contrato a leitores diretos de fd ou redesenhar o isolamento para consumidores por caminho. Só depois implementar parsing/validação de `--fd N`, conflitos de fd, vínculo do argv real à validação do broker e seam 1 completo. O fluxo do sudo e o canal stdin não foram alterados; nenhuma permissão foi relaxada. Testes de broker instalado continuam com `skip` quando ele não está disponível.
