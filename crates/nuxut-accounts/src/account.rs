//! Hesap modeli ve kalıcı hesap listesi.
//!
//! Hesap listesi gizli olmayan bilgidir (sağlayıcı, ad, sunucu adresi, durum) ve
//! `$XDG_DATA_HOME/nuxut/accounts.json` dosyasında (0600) tutulur. Şifre/token burada
//! **yoktur**; onlar [`crate::secret`] ile Secret Service'tedir.
//!
//! Yazma atomiktir (geçici dosya + `rename`); bozuk dosya yok sayılmaz, hata döner (hesapları
//! sessizce kaybetmek yerine). Sürüm alanı ileride şema göçü içindir.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use url::Url;

/// 16 onaltılık karakterlik rastgele kimlik. Dosya yolu ve D-Bus nesne yolu içinde güvenle
/// kullanılabilir.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AccountId(String);

impl AccountId {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("işletim sistemi rastgelelik kaynağı");
        Self(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    pub fn parse(s: &str) -> Option<Self> {
        (s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())).then(|| Self(s.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for AccountId {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        Self::parse(&s).ok_or_else(|| format!("invalid account id: {s:?}"))
    }
}

impl From<AccountId> for String {
    fn from(id: AccountId) -> String {
        id.0
    }
}

/// Hesap sağlayıcısı. Davranışı (kimlik türü, senkron protokolü) belirler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    /// Google Calendar API v3, OAuth 2.0.
    Google,
    /// Microsoft Graph (Outlook.com, Microsoft 365), OAuth 2.0.
    Microsoft,
    /// Nextcloud: Login Flow v2 ile alınan uygulama şifresi + CalDAV.
    Nextcloud,
    /// Genel CalDAV (iCloud, Fastmail, Radicale…): uygulama şifresi.
    Caldav,
    /// Salt okunur ICS aboneliği (webcal://). Kimlik yok.
    IcsSubscription,
}

impl Provider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Microsoft => "microsoft",
            Self::Nextcloud => "nextcloud",
            Self::Caldav => "caldav",
            Self::IcsSubscription => "ics-subscription",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "google" => Self::Google,
            "microsoft" => Self::Microsoft,
            "nextcloud" => Self::Nextcloud,
            "caldav" => Self::Caldav,
            "ics-subscription" => Self::IcsSubscription,
            _ => return None,
        })
    }

    pub fn uses_oauth(self) -> bool {
        matches!(self, Self::Google | Self::Microsoft)
    }
}

/// Hesabın çalışma durumu. UI bunu doğrudan gösterir.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum AccountState {
    Active,
    /// İzin iptal edildi / şifre değişti / token süresi doldu: kullanıcı "Yeniden bağlan"a
    /// basmalı. Senkron bu hesap için durur.
    NeedsReconnect { reason: String },
    /// Kullanıcı hesabı geçici olarak kapattı.
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub id: AccountId,
    pub provider: Provider,
    /// Kullanıcıya gösterilen ad ("alice@example.com", "Ev Nextcloud'u").
    pub display_name: String,
    /// Sunucudaki oturum adı (CalDAV kullanıcı adı, OAuth hesabının e-postası).
    pub login: String,
    /// CalDAV kökü / Nextcloud sunucusu / ICS adresi. OAuth sağlayıcılarında `None`.
    pub server: Option<Url>,
    pub state: AccountState,
    /// Unix zamanı (sn).
    pub created: i64,
    /// Sunucu adresi dışarıdan geldi (tarayıcıdaki `webcal:` bağlantısı): bu hesabın tüm
    /// istekleri yalnızca genel internete gider (yerel ağ/loopback asla). Kullanıcının Ayarlar'da
    /// kendisinin yazdığı adreste `false`.
    #[serde(default)]
    pub external: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("hesap dosyası okunamadı: {0}")]
    Io(#[from] std::io::Error),
    #[error("hesap dosyası bozuk: {0}")]
    Corrupt(String),
    #[error("XDG_DATA_HOME/HOME tanımlı değil")]
    NoDataDir,
}

const FILE_VERSION: u32 = 1;
/// Hesap dosyasının kabul edilen en büyük boyutu.
const MAX_FILE_BYTES: u64 = 1024 * 1024;
pub const MAX_ACCOUNTS: usize = 64;

#[derive(Debug, Serialize, Deserialize)]
struct FileFormat {
    version: u32,
    accounts: Vec<Account>,
}

/// Diskteki hesap listesi. Tek yazıcı daemon'dur; okuma başlangıçta bir kez yapılır.
#[derive(Debug)]
pub struct AccountRegistry {
    path: PathBuf,
    accounts: Vec<Account>,
}

impl AccountRegistry {
    /// `$XDG_DATA_HOME/nuxut/accounts.json` (yoksa `~/.local/share/...`).
    pub fn default_path() -> Result<PathBuf, RegistryError> {
        crate::paths::data_dir().map(|d| d.join("accounts.json")).ok_or(RegistryError::NoDataDir)
    }

    /// Dosya yoksa boş liste.
    pub fn load(path: &Path) -> Result<Self, RegistryError> {
        let accounts = match fs::File::open(path) {
            Ok(file) => {
                if file.metadata()?.len() > MAX_FILE_BYTES {
                    return Err(RegistryError::Corrupt("dosya çok büyük".into()));
                }
                let parsed: FileFormat =
                    serde_json::from_reader(std::io::BufReader::new(file)).map_err(|e| RegistryError::Corrupt(e.to_string()))?;
                if parsed.version > FILE_VERSION {
                    return Err(RegistryError::Corrupt(format!("bilinmeyen sürüm {}", parsed.version)));
                }
                parsed.accounts
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path: path.to_path_buf(), accounts })
    }

    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    pub fn get(&self, id: &AccountId) -> Option<&Account> {
        self.accounts.iter().find(|a| &a.id == id)
    }

    /// Ekler ya da aynı kimlikliyi değiştirir, diske yazar.
    pub fn upsert(&mut self, account: Account) -> Result<(), RegistryError> {
        match self.accounts.iter().position(|a| a.id == account.id) {
            Some(i) => self.accounts[i] = account,
            None if self.accounts.len() >= MAX_ACCOUNTS => {
                return Err(RegistryError::Corrupt(format!("en fazla {MAX_ACCOUNTS} hesap")));
            }
            None => self.accounts.push(account),
        }
        self.save()
    }

    pub fn set_state(&mut self, id: &AccountId, state: AccountState) -> Result<bool, RegistryError> {
        let Some(account) = self.accounts.iter_mut().find(|a| &a.id == id) else { return Ok(false) };
        if account.state == state {
            return Ok(false);
        }
        account.state = state;
        self.save()?;
        Ok(true)
    }

    pub fn remove(&mut self, id: &AccountId) -> Result<Option<Account>, RegistryError> {
        let Some(pos) = self.accounts.iter().position(|a| &a.id == id) else { return Ok(None) };
        let removed = self.accounts.remove(pos);
        self.save()?;
        Ok(Some(removed))
    }

    fn save(&self) -> Result<(), RegistryError> {
        let data = serde_json::to_vec_pretty(&FileFormat { version: FILE_VERSION, accounts: self.accounts.clone() })
            .map_err(|e| RegistryError::Corrupt(e.to_string()))?;
        write_private_atomic(&self.path, &data)?;
        Ok(())
    }
}

/// Dosyayı 0600 izinle atomik yazar; üst dizini 0700 ile yaratır.
pub fn write_private_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: AccountId) -> Account {
        Account {
            id,
            provider: Provider::Nextcloud,
            display_name: "Ev".into(),
            login: "alice".into(),
            server: Some(Url::parse("https://cloud.example.com/").unwrap()),
            state: AccountState::Active,
            created: 1_700_000_000,
            external: false,
        }
    }

    #[test]
    fn generated_ids_are_valid_and_distinct() {
        let a = AccountId::generate();
        let b = AccountId::generate();
        assert!(AccountId::parse(a.as_str()).is_some());
        assert_ne!(a, b);
        assert!(AccountId::parse("../../etc/passwd").is_none());
        assert!(AccountId::parse("ABCDEF0123456789").is_none());
    }

    #[test]
    fn registry_persists_and_reloads_with_private_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nuxut/accounts.json");
        let mut reg = AccountRegistry::load(&path).unwrap();
        assert!(reg.accounts().is_empty());
        let id = AccountId::generate();
        reg.upsert(sample(id.clone())).unwrap();
        reg.set_state(&id, AccountState::NeedsReconnect { reason: "şifre değişti".into() }).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let reg = AccountRegistry::load(&path).unwrap();
        assert_eq!(reg.accounts().len(), 1);
        assert!(matches!(reg.get(&id).unwrap().state, AccountState::NeedsReconnect { .. }));
    }

    #[test]
    fn corrupt_file_is_an_error_not_an_empty_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.json");
        fs::write(&path, b"{ bozuk").unwrap();
        assert!(matches!(AccountRegistry::load(&path), Err(RegistryError::Corrupt(_))));
    }

    /// Elle düzenlenmiş/bozulmuş dosyadaki kimlik doğrulanır: kimlik dosya yolu ve D-Bus nesne
    /// yolunda kullanılır, `../` taşıyan kimlik yüklenmemeli.
    #[test]
    fn invalid_ids_in_file_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.json");
        for id in ["../../etc/passwd", "ABCDEF0123456789", "0123", ""] {
            let mut json = serde_json::to_value(FileFormat { version: FILE_VERSION, accounts: vec![sample(AccountId::generate())] }).unwrap();
            json["accounts"][0]["id"] = id.into();
            fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
            assert!(matches!(AccountRegistry::load(&path), Err(RegistryError::Corrupt(_))), "{id:?}");
        }
    }

    #[test]
    fn future_version_and_oversized_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.json");
        fs::write(&path, format!(r#"{{"version":{},"accounts":[]}}"#, FILE_VERSION + 1)).unwrap();
        assert!(matches!(AccountRegistry::load(&path), Err(RegistryError::Corrupt(_))));
        // Boyut sınırı ayrıştırmadan önce: dev dosya belleğe okunmaz.
        let mut big = br#"{"version":1,"accounts":[]}"#.to_vec();
        big.resize(MAX_FILE_BYTES as usize + 1, b' ');
        fs::write(&path, big).unwrap();
        assert!(matches!(AccountRegistry::load(&path), Err(RegistryError::Corrupt(_))));
    }

    #[test]
    fn files_without_external_field_load_as_user_entered() {
        // `external` sonradan eklendi: eski dosyalardaki hesaplar kullanıcı girişi sayılır.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.json");
        let mut json = serde_json::to_value(FileFormat { version: FILE_VERSION, accounts: vec![sample(AccountId::generate())] }).unwrap();
        json["accounts"][0].as_object_mut().unwrap().remove("external");
        fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        let reg = AccountRegistry::load(&path).unwrap();
        assert!(!reg.accounts()[0].external);
    }

    #[test]
    fn account_limit_is_enforced_but_updates_still_work() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.json");
        let mut reg = AccountRegistry::load(&path).unwrap();
        let ids: Vec<AccountId> = (0..MAX_ACCOUNTS).map(|_| AccountId::generate()).collect();
        for id in &ids {
            reg.upsert(sample(id.clone())).unwrap();
        }
        assert!(matches!(reg.upsert(sample(AccountId::generate())), Err(RegistryError::Corrupt(_))));
        assert_eq!(reg.accounts().len(), MAX_ACCOUNTS);
        // Var olan hesabı güncellemek sınıra takılmaz.
        let mut first = sample(ids[0].clone());
        first.display_name = "Güncel".into();
        reg.upsert(first).unwrap();
        assert_eq!(AccountRegistry::load(&path).unwrap().get(&ids[0]).unwrap().display_name, "Güncel");
        // Silinen hesap diskte de yok.
        reg.remove(&ids[1]).unwrap();
        assert!(AccountRegistry::load(&path).unwrap().get(&ids[1]).is_none());
        assert!(reg.remove(&ids[1]).unwrap().is_none());
    }
}
