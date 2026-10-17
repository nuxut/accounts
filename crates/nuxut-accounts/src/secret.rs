//! Gizli bilgi saklama: uygulama şifreleri ve OAuth yenileme token'ları.
//!
//! Tek kalıcı yer **Secret Service**'tir (gnome-keyring, KeePassXC, KWallet köprüsü…).
//! Gizli bilgi hiçbir zaman düz metin dosyaya, önbelleğe veya loga yazılmaz. Secret Service
//! yoksa ya da anahtarlık kilitliyse hesap "kilitli" durumuna düşer; yedek dosya deposu
//! **bilinçli olarak yoktur** (bkz. ADR-0005).
//!
//! Öğe nitelikleri: `application=nuxut`, `nuxut-account=<id>`, `nuxut-kind=<tür>`. Etiket
//! kullanıcının anahtarlık yöneticisinde (Seahorse) gördüğü addır.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::account::AccountId;

/// Bellekten silinirken sıfırlanan, `Debug`'da gizlenen metin.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(..)")
    }
}

impl<'de> serde::Deserialize<'de> for SecretString {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self::new)
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

/// HTTP kimliği ([`crate::http::Auth`]) için; kopya da düşerken sıfırlanır.
impl From<SecretString> for crate::http::Secret {
    fn from(s: SecretString) -> Self {
        Self::new(s.expose().to_string())
    }
}

/// Hesap başına saklanan gizli bilgi türü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretKind {
    /// CalDAV/Nextcloud uygulama şifresi.
    Password,
    /// OAuth 2.0 yenileme token'ı.
    RefreshToken,
}

impl SecretKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::RefreshToken => "oauth-refresh-token",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// Oturumda Secret Service sağlayıcısı yok.
    #[error("anahtarlık hizmeti (Secret Service) bulunamadı")]
    Unavailable,
    /// Anahtarlık kilitli ve kullanıcı kilit açma isteğini kapattı.
    #[error("anahtarlık kilidi açılmadı")]
    Locked,
    #[error("anahtarlık hatası: {0}")]
    Backend(String),
}

/// Gizli bilgi deposu. Çağrılar bloklayabilir (anahtarlık kilit açma istemi); servis
/// thread'lerinden çağrılır, UI thread'inden değil.
pub trait SecretStore: Send + Sync + fmt::Debug {
    fn store(&self, account: &AccountId, kind: SecretKind, label: &str, secret: &SecretString) -> Result<(), SecretError>;
    /// Yoksa `Ok(None)`.
    fn lookup(&self, account: &AccountId, kind: SecretKind) -> Result<Option<SecretString>, SecretError>;
    /// Hesabın tüm gizli bilgilerini siler; zaten yoksa hata değildir.
    fn delete_account(&self, account: &AccountId) -> Result<(), SecretError>;
}

const ATTR_APP: &str = "application";
const ATTR_ACCOUNT: &str = "nuxut-account";
const ATTR_KIND: &str = "nuxut-kind";
const APP: &str = "nuxut";

/// Secret Service (D-Bus) deposu, `oo7` ile. Her çağrı kısa ömürlü bir oturum açar:
/// çağrılar seyrektir (hesap ekleme, token yenileme) ve uzun yaşayan bağlantı tutmak
/// anahtarlık yeniden başlatıldığında bayat kalır.
#[derive(Debug, Default)]
pub struct KeyringStore;

impl KeyringStore {
    pub fn new() -> Self {
        Self
    }

    fn collection() -> Result<oo7::dbus::Collection, SecretError> {
        futures_lite::future::block_on(async {
            let service = oo7::dbus::Service::new().await.map_err(map_err)?;
            let collection = service.default_collection().await.map_err(map_err)?;
            if collection.is_locked().await.map_err(map_err)? {
                collection.unlock(None).await.map_err(map_err)?;
            }
            Ok(collection)
        })
    }
}

fn map_err(e: oo7::dbus::Error) -> SecretError {
    match e {
        oo7::dbus::Error::Dismissed => SecretError::Locked,
        oo7::dbus::Error::ZBus(zbus::Error::MethodError(name, ..))
            if name.as_str() == "org.freedesktop.DBus.Error.ServiceUnknown" =>
        {
            SecretError::Unavailable
        }
        oo7::dbus::Error::ZBus(zbus::Error::FDO(e)) if matches!(*e, zbus::fdo::Error::ServiceUnknown(_)) => {
            SecretError::Unavailable
        }
        oo7::dbus::Error::ZBus(zbus::Error::Address(_)) => SecretError::Unavailable,
        other => SecretError::Backend(other.to_string()),
    }
}

impl SecretStore for KeyringStore {
    fn store(&self, account: &AccountId, kind: SecretKind, label: &str, secret: &SecretString) -> Result<(), SecretError> {
        let collection = Self::collection()?;
        let attrs = [(ATTR_APP, APP), (ATTR_ACCOUNT, account.as_str()), (ATTR_KIND, kind.as_str())];
        futures_lite::future::block_on(async {
            collection
                .create_item(label, &attrs, oo7::Secret::text(secret.expose()), true, None)
                .await
                .map(|_| ())
                .map_err(map_err)
        })
    }

    fn lookup(&self, account: &AccountId, kind: SecretKind) -> Result<Option<SecretString>, SecretError> {
        let collection = Self::collection()?;
        let attrs = [(ATTR_APP, APP), (ATTR_ACCOUNT, account.as_str()), (ATTR_KIND, kind.as_str())];
        futures_lite::future::block_on(async {
            let items = collection.search_items(&attrs).await.map_err(map_err)?;
            let Some(item) = items.into_iter().next() else { return Ok(None) };
            if item.is_locked().await.map_err(map_err)? {
                item.unlock(None).await.map_err(map_err)?;
            }
            let secret = item.secret().await.map_err(map_err)?;
            let text = std::str::from_utf8(secret.as_bytes())
                .map_err(|_| SecretError::Backend("gizli bilgi UTF-8 değil".into()))?;
            Ok(Some(SecretString::new(text.to_string())))
        })
    }

    fn delete_account(&self, account: &AccountId) -> Result<(), SecretError> {
        let collection = Self::collection()?;
        let attrs = [(ATTR_APP, APP), (ATTR_ACCOUNT, account.as_str())];
        futures_lite::future::block_on(async {
            for item in collection.search_items(&attrs).await.map_err(map_err)? {
                item.delete(None).await.map_err(map_err)?;
            }
            Ok(())
        })
    }
}

/// Bellek içi depo: testler ve `--ephemeral` çalıştırma için.
#[derive(Debug, Default)]
pub struct MemoryStore {
    items: Mutex<HashMap<(AccountId, SecretKind), SecretString>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for MemoryStore {
    fn store(&self, account: &AccountId, kind: SecretKind, _label: &str, secret: &SecretString) -> Result<(), SecretError> {
        self.items.lock().unwrap().insert((account.clone(), kind), secret.clone());
        Ok(())
    }

    fn lookup(&self, account: &AccountId, kind: SecretKind) -> Result<Option<SecretString>, SecretError> {
        Ok(self.items.lock().unwrap().get(&(account.clone(), kind)).cloned())
    }

    fn delete_account(&self, account: &AccountId) -> Result<(), SecretError> {
        self.items.lock().unwrap().retain(|(a, _), _| a != account);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_secret() {
        let s = SecretString::new("hunter2".into());
        assert!(!format!("{s:?}").contains("hunter2"));
    }

    /// Gerçek oturum anahtarlığına yazar ve siler. Elle: `cargo test -- --ignored keyring`.
    #[test]
    #[ignore = "gerçek Secret Service gerektirir"]
    fn keyring_store_round_trip_against_session_keyring() {
        let store = KeyringStore::new();
        let a = AccountId::generate();
        store.store(&a, SecretKind::RefreshToken, "Nuxut test öğesi (silinecek)", &"tok-123".into()).unwrap();
        assert_eq!(store.lookup(&a, SecretKind::RefreshToken).unwrap().unwrap().expose(), "tok-123");
        store.store(&a, SecretKind::RefreshToken, "Nuxut test öğesi (silinecek)", &"tok-456".into()).unwrap();
        assert_eq!(store.lookup(&a, SecretKind::RefreshToken).unwrap().unwrap().expose(), "tok-456");
        store.delete_account(&a).unwrap();
        assert!(store.lookup(&a, SecretKind::RefreshToken).unwrap().is_none());
    }

    #[test]
    fn memory_store_round_trip_and_delete() {
        let store = MemoryStore::new();
        let a = AccountId::parse("a1b2c3d4e5f60718").unwrap();
        store.store(&a, SecretKind::Password, "x", &"pw".into()).unwrap();
        assert_eq!(store.lookup(&a, SecretKind::Password).unwrap().unwrap().expose(), "pw");
        assert!(store.lookup(&a, SecretKind::RefreshToken).unwrap().is_none());
        store.delete_account(&a).unwrap();
        assert!(store.lookup(&a, SecretKind::Password).unwrap().is_none());
    }
}
