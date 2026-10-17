# ADR-0002 — Gizli bilgi yalnızca Secret Service'te (oo7)

Tarih: 2026-10-16 · Durum: kabul edildi · Önceki: calendar ADR-0005 (2026-10-04), buraya taşındı

## Bağlam
Uygulama parolaları ve OAuth yenileme belirteçleri kalıcı saklanmalı. Hesaplar çekirdeği taşınınca
saklama da tek sahibe (`nuxut-accountsd`) geçer.

## Seçenekler
- `secret-service` crate: bakımı oo7'ye devredildi.
- `keyring` crate: çok platformlu soyutlama; Linux'ta yine Secret Service, ek katman.
- Şifreli dosya: anahtar yine bir yerde saklanmalı; düz metne düşmenin kapısını açar.
- **`oo7` (seçilen):** saf Rust Secret Service istemcisi (GNOME'un resmî), şifreli oturum
  (DH + AES), `async-io` yürütücüsüyle (zbus ile aynı), tokio yok.

## Karar
- `oo7::dbus` doğrudan kullanılır (Flatpak dosya arka ucunu kullanan `Keyring` soyutlaması değil).
- Yedek dosya deposu **yok**: Secret Service yoksa ya da kilitliyse hesap "anahtarlık kilitli"
  durumunda bekler.
- Erişim belirteçleri yalnızca `nuxut-accountsd` belleğinde. `SecretString` sıfırlanarak düşer,
  `Debug`'da görünmez.
- Öğe nitelikleri değişmez: `application=nuxut`, `nuxut-account=<id>`, `nuxut-kind=password |
  oauth-refresh-token`. Takvimden taşınan hesaplar yeniden bağlanmadan çalışır.
- Anahtarlığa yalnız `nuxut-accountsd` erişir; tüketiciler (`nuxut-calendard`) Secret Service'e
  hiç bağlanmaz.

## Sonuçlar
Secret Service sağlayıcısı olmayan oturumlarda parolalı ve OAuth hesapları çalışmaz (ICS aboneliği
çalışır). Bilinçli güvenlik tercihi; belgede ve UI'da açıkça söylenir.
