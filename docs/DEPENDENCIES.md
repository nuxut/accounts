# Bağımlılıklar

Çalışma zamanı sistem paketleri (Arch): **yok** (C kütüphanesine bağlanılmaz). Çalışma zamanında
beklenen servisler: oturum D-Bus'ı, bir Secret Service sağlayıcısı (`gnome-keyring` ya da
`keepassxc`), isteğe bağlı `xdg-desktop-portal` (tarayıcı açma; yoksa `xdg-utils`'teki
`xdg-open`), kök sertifikalar için `ca-certificates`.

Crate'lerin çoğu calendar reposundan `nuxut-accounts` ile birlikte taşındı (2026-10-16); gerekçeler
aynıdır, calendar `docs/DEPENDENCIES.md` ile tutarlı tutulur.

| Crate | Neden | Alternatif (neden değil) |
|---|---|---|
| `nuxut-net` (framework, yol bağımlılığı) | SSRF'ye dayanıklı senkron HTTP istemcisi; shell ve calendar ile ortak. `nuxut_accounts::http` adıyla yeniden aktarılır | Kendi kopyamız (iki yerde bakım, güvenlik düzeltmesi kaçar) |
| `ureq` 3 (rustls, platform-verifier) — `nuxut-net` üzerinden | Senkron, küçük HTTP; gövde sınırı, faz zaman aşımları | `reqwest` (tokio + hyper), `isahc` (libcurl, C) |
| `rustls` + `ring` (ureq üzerinden) | TLS; ≥ 0.23.46 (RUSTSEC-2026-0346..0349). `ring` C/asm içerir, kaçınılmaz | `aws-lc-rs` (daha ağır C), `native-tls` (OpenSSL) |
| `oo7` 0.6 (async-std/async-io, native_crypto) | Saf Rust Secret Service istemcisi (ADR-0002) | `secret-service` (oo7'ye devredildi), `keyring` (gereksiz katman) |
| `zbus` 5 | D-Bus: portal OpenURI, Secret Service (oo7 üzerinden); shell ve calendar ile aynı sürüm | `dbus` (libdbus, C) |
| `futures-lite` | oo7/zbus async çağrılarını servis thread'inde `block_on` | — |
| `serde`, `serde_json` | Hesap listesi (`accounts.json`), OAuth ve Login Flow JSON yanıtları | — |
| `url` | URL ayrıştırma/birleştirme | — |
| `chrono` | Belirteç bitiş zamanı, hesap oluşturma zamanı | `time` (calendar chrono kullanıyor; iki kütüphane taşımamak için) |
| `sha2`, `base64`, `getrandom` | PKCE S256, base64url, rastgele `state` ve hesap kimliği | — |
| `zeroize` | Gizli metni bellekten silme (oo7 zaten getiriyor) | — |
| `thiserror`, `tracing` | Hata tipleri, log | — |
| `tempfile` (dev) | Testlerde geçici dizin | — |

## Lisans uyumu (proje: MIT)

Ağaç calendar'ınkinin alt kümesidir; tüm lisanslar izin verici (MIT/Apache-2.0, ISC, BSD-3,
Unicode-3.0, CDLA-Permissive-2.0; ayrıntı calendar `docs/DEPENDENCIES.md` "Lisans uyumu").
Denetim: `cargo deny check` (`deny.toml` framework politikasıyla aynı; `ignore` boş: framework'ün
tek istisnası ttf-parser bu ağaçta yok — 2026-10-16: yalnız gerçekten geçerli istisna
yazılır).
