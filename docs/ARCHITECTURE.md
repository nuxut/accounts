# nuxut-accounts — mimari

Durum: Faz 1 sürüyor (2026-10-16). Tasarım: shell `docs/design/accounts.md`.

## 1. Crate'ler ve süreçler

| Crate | Ne | Bağımlılık sınırı |
|---|---|---|
| `nuxut-accounts` | Hesap modeli ve kalıcı liste, Secret Service, OAuth, Nextcloud Login Flow, tarayıcı açma, istemci kimlikleri | UI ve D-Bus sözleşmesi bilmez |

Kararlar: `docs/adr/` (0001 repo ve daemon, 0002 Secret Service).
