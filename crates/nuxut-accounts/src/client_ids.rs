//! OAuth istemci kimlikleri — **tek yer** (ADR-0007 §5).
//!
//! Google Cloud projesi ve Microsoft Entra kaydı açılınca değerler aşağıdaki üç sabite yazılır;
//! başka hiçbir dosya değişmez. Öncelik (ilk dolu olan kazanır):
//! 1. çalışma zamanı ortam değişkeni (`NUXUT_GOOGLE_CLIENT_ID`, `NUXUT_GOOGLE_CLIENT_SECRET`,
//!    `NUXUT_MICROSOFT_CLIENT_ID`) — geliştirme ya da kendi Cloud projesini kullanan ileri kullanıcı;
//! 2. derleme ortamı (`option_env!`, aynı adlar) — dağıtım paketleri kendi kimliklerini verebilir;
//! 3. bu dosyadaki sabitler — Nuxut'un resmî kimlikleri.
//!
//! Hepsi boşsa sağlayıcı bu derlemede kapalıdır ve `AvailableProviders` listesinde görünmez
//! (kullanıcıya bozuk bir seçenek sunulmaz).
//!
//! **`client_secret` neden depoda durabilir:** Google "Desktop app" istemcisi token isteğinde
//! `client_secret` ister, ama Google'ın kendi belgesine göre yerel (kurulan) uygulamada bu değer
//! gizli **değildir** ("installed apps … cannot keep secrets"; RFC 8252 §8.5). İkiliye gömülen
//! her değer zaten çıkarılabilir. Güvenlik PKCE (S256, RFC 7636) + yalnızca loopback yönlendirme
//! (RFC 8252) + sabit zamanlı `state` denetimindedir: kodu ele geçiren biri doğrulayıcı olmadan
//! token alamaz. Değeri kopyalayan biri yalnızca kotamızı/itibarımızı kullanabilir; bu bir
//! gizlilik ya da hesap güvenliği açığı değildir. Microsoft public client'ta sır hiç yoktur.

/// Google OAuth istemci kimliği (`…apps.googleusercontent.com`). Boş = Google kapalı.
pub const GOOGLE_CLIENT_ID: &str = "";
/// Google "Desktop app" istemcisinin `client_secret`'ı (gizli değildir; yukarıya bakın).
pub const GOOGLE_CLIENT_SECRET: &str = "";
/// Microsoft Entra public client uygulama (istemci) kimliği (GUID). Boş = Microsoft kapalı.
pub const MICROSOFT_CLIENT_ID: &str = "";

/// Çözümlenmiş istemci kimlikleri. `None` = o değer bu derlemede yok.
#[derive(Debug, Clone, Default)]
pub struct ClientIds {
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub microsoft_client_id: Option<String>,
}

impl ClientIds {
    /// Çalışma zamanı ortamı > derleme ortamı > bu dosyadaki sabit.
    pub fn builtin() -> Self {
        Self {
            google_client_id: pick(
                std::env::var("NUXUT_GOOGLE_CLIENT_ID").ok(),
                option_env!("NUXUT_GOOGLE_CLIENT_ID"),
                GOOGLE_CLIENT_ID,
            ),
            google_client_secret: pick(
                std::env::var("NUXUT_GOOGLE_CLIENT_SECRET").ok(),
                option_env!("NUXUT_GOOGLE_CLIENT_SECRET"),
                GOOGLE_CLIENT_SECRET,
            ),
            microsoft_client_id: pick(
                std::env::var("NUXUT_MICROSOFT_CLIENT_ID").ok(),
                option_env!("NUXUT_MICROSOFT_CLIENT_ID"),
                MICROSOFT_CLIENT_ID,
            ),
        }
    }
}

/// İlk boş olmayan değer (boşluk dolu değer de boş sayılır).
fn pick(runtime: Option<String>, built: Option<&'static str>, constant: &'static str) -> Option<String> {
    [runtime.as_deref(), built, Some(constant)]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::pick;

    #[test]
    fn runtime_beats_build_beats_constant() {
        assert_eq!(pick(Some("rt".into()), Some("bt"), "c").as_deref(), Some("rt"));
        assert_eq!(pick(Some("  ".into()), Some("bt"), "c").as_deref(), Some("bt"));
        assert_eq!(pick(None, Some(""), "c").as_deref(), Some("c"));
        assert_eq!(pick(None, None, ""), None);
    }
}
