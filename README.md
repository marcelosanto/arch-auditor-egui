# Arch Linux Visual System Auditor (`arch-auditor-egui`)

Ferramenta visual desktop em **Rust + `eframe` (`egui`)** para auditoria rápida e somente-leitura no **Arch Linux**.

## Funcionalidades

- **Portas Abertas:** Lista sockets TCP/UDP em escuta (`ss -tulnp`, com fallback para `/proc/net`), destacando binds externos em `0.0.0.0` ou `[::]`, processo associado e PID.
- **Pacotes Desatualizados:** Consulta atualizações dos repositórios oficiais via `checkupdates` (`pacman-contrib`) e do AUR via `paru` ou `yay`, sem rodar `pacman -Sy` diretamente.
- **Vulnerabilidades (CVEs):** Integra-se ao `arch-audit` para listar CVEs, severidade (`High`/`Critical`, `Medium`, `Low`), correções e abertura direta no navegador via `xdg-open` apontando para `security.archlinux.org`.
- **Cache Local de CVEs com TTL:** Persiste resultados em `~/.cache/arch-auditor/cves.cache` (TTL de 600s) para abertura rápida mesmo offline, com botão e atalho dedicados para atualização exclusiva de CVEs.
- **WMs e Ambientes Gráficos:** Detecta a sessão ativa (`XDG_CURRENT_DESKTOP`, `DESKTOP_SESSION`, `XDG_SESSION_TYPE`) e ambientes/WMs instalados em `/usr/share/wayland-sessions`, `/usr/share/xsessions` e `/usr/bin`.
- **AppImages e Flatpaks:** Varre diretórios usuais (`~/Applications`, `~/Downloads`, `~/Desktop`, `~/.local/bin`, `/opt`) por arquivos `.AppImage` (tamanho e permissão `+x`) e lista aplicativos `flatpak`.
- **Busca em Tempo Real e Exportação:** Filtra itens na aba ativa (`Ctrl+F` / `Esc`) e exporta um resumo Markdown em `~/arch-audit-resumo-<timestamp>.md` além de copiar para a área de transferência (`Ctrl+E`).

## Dependências no Arch Linux

```bash
sudo pacman -S --needed rust cargo base-devel iproute2 pacman-contrib arch-audit xdg-utils

```

Opcionais:  `flatpak`,  `yay` ou `paru`.

## Como Compilar e Executar

Bash

```
cargo run --release

```

Para revelar nomes/PIDs de serviços pertencentes a outros usuários/`root`:

Bash

```
cargo build --release
sudo ./target/release/arch-auditor-egui

```

## Atalhos

-   `Ctrl+F`: Foca no campo de busca da aba atual
    
-   `Esc`: Limpa o filtro de busca
    
-   `Ctrl+U`: Atualiza o cache de pacotes desatualizados
    
-   `Ctrl+Shift+C`: Atualiza exclusivamente os dados de CVEs (`arch-audit`)
    
-   `Ctrl+E`: Exporta o resumo em Markdown e copia para a área de transferência
