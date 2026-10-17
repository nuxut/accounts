//! Nuxut çevrimiçi hesap katmanı.
//!
//! Takvim (ve ileride posta, kişiler) için ortak: hesap modeli ve kalıcı listesi, Secret
//! Service'te gizli bilgi saklama, OAuth 2.0 (loopback + PKCE, cihaz kodu), Nextcloud Login
//! Flow v2, tarayıcı açma. HTTP istemcisi framework'ün `nuxut-net` crate'idir; burada `http`
//! adıyla yeniden aktarılır. UI veya senkron bilmez.
//!
//! Mimari: `docs/ARCHITECTURE.md` (depo kökü).

pub mod account;
pub mod browser;
pub mod client_ids;
pub mod nextcloud;
pub mod oauth;
pub mod paths;
pub mod secret;

/// SSRF'ye dayanıklı HTTP istemcisi (`nuxut-net`); kurallar orada belgelenir.
pub use nuxut_net as http;
/// Testler için sahte HTTP sunucusu (`nuxut_net::testing`).
#[cfg(any(test, feature = "test-support"))]
pub use nuxut_net::testing;

pub use account::{Account, AccountId, AccountRegistry, AccountState, Provider};
pub use http::{Auth, HttpClient, HttpError, OriginBoundClient, Policy, Request, Response, Trust};
pub use secret::{KeyringStore, MemoryStore, SecretError, SecretKind, SecretStore, SecretString};
pub use url::Url;
