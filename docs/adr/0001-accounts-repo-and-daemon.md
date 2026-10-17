# ADR-0001 — Ayrı `accounts` reposu ve `nuxut-accountsd`

Tarih: 2026-10-16 · Durum: kabul edildi (2026-10-16) · Kaynak: shell
`docs/design/accounts.md` (K6), `docs/research/online-accounts.md`

## Bağlam
Hesap kodu (`nuxut-accounts`: model, kalıcı liste, Secret Service, OAuth, Nextcloud Login Flow)
ve akışlar takvim reposundaydı; tek tüketici `nuxut-calendard`'dı. Kullanıcı hedefi (2026-10-16):
tek "Hesap ekle" ile takvim, kişiler, posta ve dosyalar masaüstüne bağlansın. Kişiler, posta ve
dosya servisleri takvime bağımlı olmamalı.

## Seçenekler
- Calendar workspace'inde kalıp adı değişir: kişiler/posta servisleri takvim reposuna bağımlı olur.
- Framework'e taşımak: framework UI çerçevesidir, ağ ve anahtarlık sahibi bir daemon taşımaz.
- Shell'e taşımak: hesaplar shell'e özgü değil (Ayarlar, takvim, ileride posta da kullanır).
- **Ayrı `accounts` reposu (seçilen):** `nuxut-accounts` (kütüphane), `nuxut-accounts-ipc`
  (`org.nuxut.Accounts1` sözleşmesi, yalnız zbus + serde), `nuxut-accountsd` (daemon).

## Karar
- Hesap listesinin ve tüm belirteçlerin **tek sahibi** `nuxut-accountsd`'dir. Takvim (ve sonraki
  kişiler, posta, dosya servisleri) belirteci/parolayı istek başına `Accounts1`'den alır, yalnız
  bellekte tutar.
- `nuxut-accounts` kütüphanesi calendar `d4f2dac`'taki hâliyle taşındı; davranış değişmeden.
- GOA köprüsü yok (2026-10-16). GOA içe aktarma düşük öncelik (K4), iCloud Drive
  sunulmaz (K5), Drive Gmail'den sonra (K2).
- Google ve Microsoft kodu istemci kimliği gelene kadar gizli kalır (K0, K1, K3 kullanıcı kararı;
  mevcut "kimlik yoksa sağlayıcı görünmez" kuralı).

## Sonuçlar
- Calendar `nuxut-accounts`'a `../accounts` yol bağımlılığıyla bağlanır (framework'e bağlandığı
  gibi). Hesap ekleme akışları calendard'dan çıkar; `Calendar1`'in akış yöntemleri bir sürüm
  boyunca `Accounts1`'e yönlendiren uyumluluk katmanı olur.
- Tüketici yeni bir süreç başlatır (D-Bus etkinleştirme): boşta 0 CPU, hedef RSS < 10 MB.
