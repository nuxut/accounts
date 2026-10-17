//! OAuth 2.0 yerel uygulama akışı (RFC 8252): tarayıcı + loopback yönlendirme + PKCE (RFC 7636),
//! yedek olarak cihaz kodu akışı (RFC 8628).
//!
//! Akış (Google ve Microsoft aynı):
//! 1. [`AuthorizationSession::start`] `127.0.0.1` üzerinde rastgele bir porta bağlanır, PKCE
//!    doğrulayıcısı ve `state` üretir, yetkilendirme adresini verir.
//! 2. Çağıran adresi tarayıcıda açar ([`crate::browser`]); kullanıcı izin verir.
//! 3. [`AuthorizationSession::wait`] tarayıcının `GET /?code=…&state=…` isteğini bekler,
//!    `state`'i sabit zamanlı karşılaştırır, tarayıcıya "Nuxut'a dönebilirsiniz" sayfası döner.
//! 4. [`OAuthClient::exchange_code`] kodu token'lara çevirir (PKCE doğrulayıcısıyla).
//!
//! İstemci kimlikleri tek yerde: [`crate::client_ids`] ([`ClientIds::builtin`]; öncelik ortam
//! değişkeni, derleme ortamı, sabit). Masaüstü uygulamasında `client_secret` gizli **değildir**
//! (Google bunu açıkça belgeler); güvenlik PKCE + loopback'e dayanır.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::account::Provider;
use crate::http::{HttpClient, HttpError, Request};
use crate::secret::SecretString;

/// Kullanıcının tarayıcıda izin vermesi için tanınan süre.
pub const AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Token uç noktası yanıtının en büyük boyutu.
const MAX_TOKEN_RESPONSE: u64 = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("bu derlemede {0} için istemci kimliği yapılandırılmamış")]
    NotConfigured(&'static str),
    #[error("yerel yönlendirme portu açılamadı: {0}")]
    Listen(std::io::Error),
    #[error("kullanıcı izni reddetti")]
    Denied,
    #[error("izin süresi doldu")]
    TimedOut,
    #[error("iptal edildi")]
    Cancelled,
    #[error("güvenlik doğrulaması başarısız (state uyuşmadı)")]
    StateMismatch,
    /// Yenileme token'ı iptal edildi / süresi doldu (`invalid_grant`): yeniden bağlanmak gerekir.
    #[error("hesap izni geri alınmış ya da süresi dolmuş")]
    Revoked,
    /// Kullanıcı izin ekranında takvim kutucuklarını kaldırdı (Google granüler onay) ya da
    /// sağlayıcı takvim kapsamını vermedi. Alınan token iptal edildi (Google).
    #[error("takvim kapsamı verilmedi")]
    ScopeMissing,
    /// Kurumsal Microsoft hesabı: kullanıcı kendisi izin veremez, kiracı yöneticisinin onayı
    /// gerekir (`consent_required`/`access_denied`/`interaction_required` + AADSTS65001/90094/90095).
    #[error("kuruluş yöneticisinin onayı gerekiyor")]
    AdminConsent,
    #[error("sağlayıcı hatası: {0}")]
    Provider(String),
    #[error(transparent)]
    Http(#[from] HttpError),
}

/// Sağlayıcı uç noktaları ve istemci kaydı.
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub provider: Provider,
    pub authorize_url: Url,
    pub token_url: Url,
    pub device_url: Option<Url>,
    /// Token iptal uç noktası (Google); `None` = sağlayıcıda yok (Microsoft public client).
    pub revoke_url: Option<Url>,
    /// Kiracı yöneticisi onay uç noktası (Microsoft); bağlantı [`Self::admin_consent_link`] ile.
    pub admin_consent_url: Option<Url>,
    pub client_id: String,
    /// Masaüstü istemcilerde gizli değildir; Google "Desktop app" türü token isteğinde ister.
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    /// Yetkilendirme adresine eklenen sağlayıcıya özgü parametreler.
    pub extra_params: Vec<(String, String)>,
    /// Yönlendirme adresindeki ana makine adı: Google `127.0.0.1`, Microsoft `localhost`
    /// (Entra ID public client kaydında `http://localhost` portsuz kaydedilir, port serbesttir).
    pub redirect_host: &'static str,
}

/// İstemci kimlikleri tek yerde: [`crate::client_ids`].
pub use crate::client_ids::ClientIds;

pub const GOOGLE_SCOPES: &[&str] = &[
    "openid",
    "email",
    // Takvim listesi (renkler, adlar) — salt okuma.
    "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
    // Etkinlikleri okuma + basit oluşturma/düzenleme (Faz 2).
    "https://www.googleapis.com/auth/calendar.events",
];

pub const MICROSOFT_SCOPES: &[&str] =
    &["openid", "email", "profile", "offline_access", "https://graph.microsoft.com/Calendars.ReadWrite"];

/// Token yanıtındaki `scope` içinde bulunması zorunlu kapsamlar (ADR-0007 §1). Biri eksikse
/// senkron çalışamaz: akış [`OAuthError::ScopeMissing`] ile biter.
pub const GOOGLE_REQUIRED_SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
];
pub const MICROSOFT_REQUIRED_SCOPES: &[&str] = &["https://graph.microsoft.com/Calendars.ReadWrite"];

/// Google'ın geniş takvim kapsamı: verilmişse iki dar kapsamı da kapsar (kullanıcı önceden başka
/// bir uygulamaya değil, aynı istemciye geniş izin vermiş olabilir).
const GOOGLE_FULL_CALENDAR: &str = "https://www.googleapis.com/auth/calendar";

/// Yalnızca uçtan uca test: tüm sağlayıcı uç noktaları bu loopback kökün altına çevrilir.
/// `test-support` özelliği olmadan derlenmez (sürüm ikilisinde uç noktalar sabit https).
#[cfg(any(test, feature = "test-support"))]
static TEST_ENDPOINT_BASE: std::sync::OnceLock<Url> = std::sync::OnceLock::new();

/// **Yalnızca test** (daemon'un gizli `--test-oauth-base` seçeneği): Google ve Microsoft OAuth uç
/// noktalarını `base` altına çevirir (`google/auth`, `google/token`, `google/revoke`,
/// `microsoft/authorize`, `microsoft/token`, `microsoft/devicecode`, `microsoft/adminconsent`).
/// Yalnızca `http://127.0.0.1…`/`http://localhost…` kabul edilir. Süreçte bir kez ayarlanır.
///
/// `test-support` özelliği olmadan (sürüm derlemesi) çeviri kodu yoktur; bu işlev her zaman hata
/// döner — daemon seçeneği görünce açılmayı reddeder.
pub fn set_test_endpoint_base(base: Url) -> Result<(), &'static str> {
    if !is_test_loopback(&base) {
        return Err("test endpoint must be http loopback");
    }
    #[cfg(any(test, feature = "test-support"))]
    return TEST_ENDPOINT_BASE.set(base).map_err(|_| "test endpoint already set");
    #[cfg(not(any(test, feature = "test-support")))]
    Err("no test hook in this build (test-support disabled)")
}

/// Test kancalarının kabul ettiği sahte sunucu kökü: `http` + loopback ana makine.
pub fn is_test_loopback(base: &Url) -> bool {
    base.scheme() == "http" && matches!(base.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
}

fn endpoint(real: &str, test_path: &str) -> Url {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(base) = TEST_ENDPOINT_BASE.get() {
        return base.join(test_path).expect("sabit test yolu");
    }
    let _ = test_path;
    Url::parse(real).expect("sabit uç nokta")
}

impl OAuthConfig {
    pub fn google(ids: &ClientIds) -> Result<Self, OAuthError> {
        let client_id = ids.google_client_id.clone().ok_or(OAuthError::NotConfigured("Google"))?;
        Ok(Self {
            provider: Provider::Google,
            authorize_url: endpoint("https://accounts.google.com/o/oauth2/v2/auth", "google/auth"),
            token_url: endpoint("https://oauth2.googleapis.com/token", "google/token"),
            device_url: None,
            revoke_url: Some(endpoint("https://oauth2.googleapis.com/revoke", "google/revoke")),
            admin_consent_url: None,
            client_id,
            client_secret: ids.google_client_secret.clone(),
            scopes: GOOGLE_SCOPES.iter().map(|s| s.to_string()).collect(),
            // access_type=offline → yenileme token'ı; prompt=consent → yeniden bağlanırken de
            // yeni yenileme token'ı gelir (Google aksi halde yalnızca ilk izinde verir).
            extra_params: vec![("access_type".into(), "offline".into()), ("prompt".into(), "consent".into())],
            redirect_host: "127.0.0.1",
        })
    }

    pub fn microsoft(ids: &ClientIds) -> Result<Self, OAuthError> {
        let client_id = ids.microsoft_client_id.clone().ok_or(OAuthError::NotConfigured("Microsoft"))?;
        let base = "https://login.microsoftonline.com/common/oauth2/v2.0";
        Ok(Self {
            provider: Provider::Microsoft,
            authorize_url: endpoint(&format!("{base}/authorize"), "microsoft/authorize"),
            token_url: endpoint(&format!("{base}/token"), "microsoft/token"),
            device_url: Some(endpoint(&format!("{base}/devicecode"), "microsoft/devicecode")),
            // Public client için iptal uç noktası yok (kullanıcı account.live.com'dan kaldırır).
            revoke_url: None,
            // Yönetici onayı `common` kiracısında çalışmaz (hangi dizine onay verileceği belirsiz;
            // Entra "AADSTS90130/50194" türü hata verir). v2.0 adminconsent belgesi kiracı yerine
            // genel `organizations` takma adını kabul eder: yönetici giriş yapınca kendi kiracısı
            // seçilir. Kullanıcının kiracı kimliğini bilmiyoruz (yönlendirmede id_token yok), bu
            // yüzden en doğru genel biçim budur.
            admin_consent_url: Some(endpoint(
                "https://login.microsoftonline.com/organizations/v2.0/adminconsent",
                "microsoft/adminconsent",
            )),
            client_id,
            client_secret: None,
            scopes: MICROSOFT_SCOPES.iter().map(|s| s.to_string()).collect(),
            extra_params: vec![("prompt".into(), "select_account".into())],
            redirect_host: "localhost",
        })
    }

    fn scope_string(&self) -> String {
        self.scopes.join(" ")
    }

    fn required_scopes(&self) -> &'static [&'static str] {
        match self.provider {
            Provider::Google => GOOGLE_REQUIRED_SCOPES,
            Provider::Microsoft => MICROSOFT_REQUIRED_SCOPES,
            _ => &[],
        }
    }

    /// Token yanıtındaki `scope`'a göre eksik zorunlu kapsamlar. `scope` yoksa RFC 6749 §5.1
    /// gereği istenenin aynısı verilmiştir. Microsoft kapsamı kısa adla döndürebilir
    /// (`Calendars.ReadWrite`) ve büyük/küçük harf duyarsızdır; Google tam adresle döndürür.
    pub fn missing_scopes(&self, granted: Option<&str>) -> Vec<&'static str> {
        let Some(granted) = granted else { return Vec::new() };
        let granted: Vec<&str> = granted.split_whitespace().collect();
        self.required_scopes()
            .iter()
            .copied()
            .filter(|required| {
                !granted.iter().any(|g| match self.provider {
                    Provider::Microsoft => {
                        let short = required.rsplit('/').next().unwrap_or(required);
                        g.eq_ignore_ascii_case(required) || g.eq_ignore_ascii_case(short)
                    }
                    _ => g == required || *g == GOOGLE_FULL_CALENDAR,
                })
            })
            .collect()
    }

    /// Kiracı yöneticisinin açacağı onay bağlantısı (yalnızca Microsoft). Yönlendirme adresi
    /// kayıtlı portsuz `http://localhost`: yönetici onaydan sonra boş bir yerel sayfaya düşer
    /// (onay yine de kaydedilir); kullanıcı ardından hesabı yeniden ekler.
    pub fn admin_consent_link(&self) -> Option<Url> {
        let mut url = self.admin_consent_url.clone()?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("scope", &MICROSOFT_REQUIRED_SCOPES.join(" "))
            .append_pair("redirect_uri", &format!("http://{}", self.redirect_host));
        Some(url)
    }
}

/// Kuruluş yöneticisi onayı gerektiren Entra hata numaraları: 65001 (izin verilmedi),
/// 90094 (yönetici onayı gerekli), 90095 (yönetici onayı iş akışı / adım-yukarı onay).
const ADMIN_CONSENT_AADSTS: &[&str] = &["65001", "90094", "90095"];

/// `error` + isteğe bağlı açıklamadan yönetici onayı durumu mu?
fn is_admin_consent(error: &str, description: Option<&str>) -> bool {
    matches!(error, "consent_required" | "access_denied" | "interaction_required" | "invalid_grant")
        && description.and_then(aadsts_number).is_some_and(|n| ADMIN_CONSENT_AADSTS.contains(&n.as_str()))
}

/// PKCE doğrulayıcısı ve S256 meydan okuması.
#[derive(Debug, Clone)]
pub struct Pkce {
    pub verifier: SecretString,
    pub challenge: String,
}

impl Pkce {
    pub fn generate() -> Self {
        // 32 rastgele bayt → 43 karakter base64url (RFC 7636 §4.1 alt sınırı, 256 bit entropi).
        let verifier = random_token(32);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Self { verifier: SecretString::new(verifier), challenge }
    }
}

fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("işletim sistemi rastgelelik kaynağı");
    URL_SAFE_NO_PAD.encode(buf)
}

/// Sabit zamanlı eşitlik (state karşılaştırması).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// İptal bayrağı: UI "İptal"e basınca bekleme döngüsü en geç 100 ms içinde çıkar.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Tarayıcıya dönen yerel sayfanın bir metni (başlık + gövde).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageText {
    pub title: String,
    pub body: String,
}

impl PageText {
    pub fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        Self { title: title.into(), body: body.into() }
    }
}

/// Loopback sayfasının metinleri. Çağıran (daemon) kendi çeviri kataloğundan doldurur; bu
/// kütüphane kullanıcı metni barındırmaz. `Default` yalnızca yedek (İngilizce, kısa).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopbackPages {
    /// `<html lang>` değeri.
    pub lang: String,
    /// Kod alındı (çağıran ayrıca bir sayfa göndermezse bu gösterilir).
    pub done: PageText,
    /// Kullanıcı izni reddetti.
    pub denied: PageText,
    /// Kuruluş yöneticisinin onayı gerekiyor.
    pub admin_consent: PageText,
    /// Sağlayıcı başka bir hata döndürdü ya da kod yok.
    pub failed: PageText,
    /// `state` uyuşmadı (başka bir sürecin isteği).
    pub invalid_request: PageText,
    /// İlgisiz yol (`/favicon.ico`).
    pub not_found: PageText,
}

impl Default for LoopbackPages {
    fn default() -> Self {
        Self {
            lang: "en".into(),
            done: PageText::new("Account connected", "You can close this tab."),
            denied: PageText::new("Permission not granted", "No account was added. You can close this tab."),
            admin_consent: PageText::new("Administrator approval required", "You can close this tab."),
            failed: PageText::new("Connection failed", "You can close this tab."),
            invalid_request: PageText::new("Invalid request", "This link was not started by Nuxut."),
            not_found: PageText::new("Not found", ""),
        }
    }
}

/// Tek bir yetkilendirme denemesi: loopback dinleyici + PKCE + state.
#[derive(Debug)]
pub struct AuthorizationSession {
    listeners: Vec<TcpListener>,
    redirect_uri: String,
    state: String,
    pkce: Pkce,
    authorize_url: Url,
    pages: LoopbackPages,
}

/// Tarayıcıdan dönen yetkilendirme kodu. Tarayıcının isteği [`BrowserReply`] içinde açık
/// bekler: çağıran token değişimini (ve kapsam denetimini) yapıp sonucu sayfada gösterebilir.
#[derive(Debug)]
pub struct AuthorizationCode {
    pub code: SecretString,
    pub redirect_uri: String,
    pub verifier: SecretString,
    pub browser: BrowserReply,
}

/// Yanıt bekleyen tarayıcı isteği. [`Self::send`] çağrılmadan düşerse `done` sayfası gider.
pub struct BrowserReply {
    stream: Option<TcpStream>,
    lang: String,
    fallback: PageText,
}

impl std::fmt::Debug for BrowserReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserReply").field("pending", &self.stream.is_some()).finish()
    }
}

impl BrowserReply {
    /// Sonucu tarayıcıda gösterir.
    pub fn send(mut self, page: &PageText) {
        if let Some(stream) = self.stream.take() {
            respond(stream, 200, &self.lang, page);
        }
    }
}

impl Drop for BrowserReply {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            respond(stream, 200, &self.lang, &self.fallback);
        }
    }
}

impl AuthorizationSession {
    /// `login_hint`: yeniden bağlanırken kayıtlı hesap (e-posta); sağlayıcı hesap seçiciyi atlar.
    pub fn start(config: &OAuthConfig, login_hint: Option<&str>, pages: LoopbackPages) -> Result<Self, OAuthError> {
        let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(OAuthError::Listen)?;
        let port = v4.local_addr().map_err(OAuthError::Listen)?.port();
        let mut listeners = vec![v4];
        // `localhost` bazı tarayıcılarda önce ::1'e çözülür; aynı portu IPv6'da da dinle
        // (yoksa tarayıcı 127.0.0.1'e geri düşer, sorun değil).
        if let Ok(v6) = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))) {
            listeners.push(v6);
        }
        for l in &listeners {
            l.set_nonblocking(true).map_err(OAuthError::Listen)?;
        }
        let redirect_uri = format!("http://{}:{port}/", config.redirect_host);
        let state = random_token(24);
        let pkce = Pkce::generate();

        let mut url = config.authorize_url.clone();
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", &config.client_id)
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("scope", &config.scope_string())
                .append_pair("state", &state)
                .append_pair("code_challenge", &pkce.challenge)
                .append_pair("code_challenge_method", "S256");
            for (k, v) in &config.extra_params {
                q.append_pair(k, v);
            }
            // Google ve Microsoft ikisi de `login_hint` kabul eder (OIDC Core §3.1.2.1).
            if let Some(hint) = login_hint.map(str::trim).filter(|h| !h.is_empty() && h.len() <= 320) {
                q.append_pair("login_hint", hint);
            }
        }
        Ok(Self { listeners, redirect_uri, state, pkce, authorize_url: url, pages })
    }

    /// Tarayıcıda açılacak adres.
    pub fn authorize_url(&self) -> &Url {
        &self.authorize_url
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Tarayıcı yönlendirmesini bekler. İlgisiz istekler (`/favicon.ico`) 404 ile geçilir;
    /// `state` uyuşmayan istek reddedilir ve beklemeye devam edilir (başka bir yerel sürecin
    /// sahte isteği akışı bozamaz; yalnızca gerçek yanıt kabul edilir).
    pub fn wait(self, timeout: Duration, cancel: &CancelToken) -> Result<AuthorizationCode, OAuthError> {
        let deadline = Instant::now() + timeout;
        loop {
            if cancel.is_cancelled() {
                return Err(OAuthError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(OAuthError::TimedOut);
            }
            let mut accepted = None;
            for l in &self.listeners {
                match l.accept() {
                    Ok((stream, _)) => {
                        accepted = Some(stream);
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(OAuthError::Listen(e)),
                }
            }
            let Some(stream) = accepted else {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            };
            match self.handle(stream) {
                Some(Ok((code, stream))) => {
                    return Ok(AuthorizationCode {
                        code,
                        redirect_uri: self.redirect_uri.clone(),
                        verifier: self.pkce.verifier.clone(),
                        browser: BrowserReply {
                            stream: Some(stream),
                            lang: self.pages.lang.clone(),
                            fallback: self.pages.done.clone(),
                        },
                    });
                }
                Some(Err(e)) => return Err(e),
                None => continue,
            }
        }
    }

    /// `None`: bu istek yönlendirme değildi, beklemeye devam. Başarıda bağlantı açık döner.
    fn handle(&self, stream: TcpStream) -> Option<Result<(SecretString, TcpStream), OAuthError>> {
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut reader = BufReader::new(stream.try_clone().ok()?);
        let mut line = String::new();
        // İstek satırı en çok 8 KiB.
        if (&mut reader).take(8192).read_line(&mut line).ok()? == 0 {
            return None;
        }
        let target = line.split_whitespace().nth(1)?.to_string();
        // Başlıkları tüket (yanıtı yazmadan önce; bazı tarayıcılar aksi halde RST görür).
        let mut header = String::new();
        for _ in 0..100 {
            header.clear();
            if (&mut reader).take(8192).read_line(&mut header).ok()? == 0 || header == "\r\n" {
                break;
            }
        }
        let lang = &self.pages.lang;
        let url = Url::parse("http://loopback").ok()?.join(&target).ok()?;
        if url.path() != "/" {
            respond(stream, 404, lang, &self.pages.not_found);
            return None;
        }
        let param = |k: &str| url.query_pairs().find(|(key, _)| key == k).map(|(_, v)| v.into_owned());
        let state_ok = param("state").is_some_and(|s| ct_eq(s.as_bytes(), self.state.as_bytes()));
        if !state_ok {
            respond(stream, 400, lang, &self.pages.invalid_request);
            return None;
        }
        if let Some(error) = param("error") {
            // `error_description` yalnızca AADSTS numarası için okunur, hiçbir yere taşınmaz.
            let description = param("error_description");
            let (page, err) = if is_admin_consent(&error, description.as_deref()) {
                (&self.pages.admin_consent, OAuthError::AdminConsent)
            } else if error == "access_denied" {
                (&self.pages.denied, OAuthError::Denied)
            } else {
                (&self.pages.failed, OAuthError::Provider(error_code(&error, description.as_deref())))
            };
            respond(stream, 200, lang, page);
            return Some(Err(err));
        }
        let Some(code) = param("code").filter(|c| !c.is_empty() && c.len() <= 4096) else {
            respond(stream, 400, lang, &self.pages.failed);
            return Some(Err(OAuthError::Provider("missing_code".into())));
        };
        Some(Ok((SecretString::new(code), stream)))
    }
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn respond(mut stream: TcpStream, status: u16, lang: &str, page: &PageText) {
    let (lang, title, message) = (html_escape(lang), html_escape(&page.title), html_escape(&page.body));
    let body = format!(
        "<!doctype html><html lang=\"{lang}\"><meta charset=\"utf-8\"><title>{title}</title>\
         <body style=\"font-family:sans-serif;display:grid;place-items:center;height:90vh;margin:0\">\
         <div style=\"text-align:center\"><h1 style=\"font-weight:500\">{title}</h1><p>{message}</p></div></body></html>"
    );
    let head = format!(
        "HTTP/1.1 {status} OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\n\
         cache-control: no-store\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

/// Token uç noktasının verdiği küme.
#[derive(Debug, Clone)]
pub struct TokenSet {
    pub access_token: SecretString,
    /// Yenilemede sağlayıcı yenisini vermeyebilir; o zaman eskisi geçerli kalır.
    pub refresh_token: Option<SecretString>,
    /// Unix zamanı (sn); güvenlik payı düşülmüş.
    pub expires_at: i64,
    pub identity: Option<Identity>,
    /// Verilen kapsamlar (yanıttaki `scope`; yoksa `None` = istenenin aynısı).
    pub scope: Option<String>,
}

/// `id_token` içinden hesap kimliği (e-posta, ad). İmza doğrulanmaz: token TLS üzerinden
/// doğrudan token uç noktasından alındı (OIDC Core §3.1.3.7, madde 6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    pub email: Option<String>,
    pub name: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    id_token: Option<String>,
    scope: Option<String>,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IdClaims {
    email: Option<String>,
    preferred_username: Option<String>,
    name: Option<String>,
}

fn identity_from_id_token(token: &str) -> Option<Identity> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let claims: IdClaims = serde_json::from_slice(&bytes).ok()?;
    let email = claims.email.or(claims.preferred_username.filter(|u| u.contains('@')));
    Some(Identity { email, name: claims.name })
}

/// Cihaz kodu akışının ilk yanıtı (Microsoft yedeği: tarayıcı açılamıyorsa kullanıcı kodu
/// başka bir cihazda girer).
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    #[serde(default = "default_interval")]
    pub interval: u64,
}

fn default_interval() -> u64 {
    5
}

/// Token isteğinin türü: hata eşlemesi buna göre değişir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grant {
    /// İlk izin (yetkilendirme kodu, cihaz kodu): `invalid_grant` + AADSTS65001 yönetici onayıdır.
    Initial,
    /// Yenileme: `invalid_grant` her zaman "yeniden bağlan".
    Refresh,
}

/// İptal isteğinin süresi (en iyi çaba; hesap silmeyi uzun süre bekletmez).
pub const REVOKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Token uç noktası istemcisi.
#[derive(Debug, Clone)]
pub struct OAuthClient {
    pub config: OAuthConfig,
    http: HttpClient,
}

impl OAuthClient {
    pub fn new(config: OAuthConfig, http: HttpClient) -> Self {
        Self { config, http }
    }

    /// Kodu token'lara çevirir ve zorunlu kapsamları denetler (eksikse token iptal edilir,
    /// [`OAuthError::ScopeMissing`]).
    pub fn exchange_code(&self, code: &AuthorizationCode) -> Result<TokenSet, OAuthError> {
        let tokens = self.exchange_code_unchecked(code)?;
        self.check_grant(tokens, true)
    }

    /// Kodu token'lara çevirir; kapsam denetimi çağıranda ([`Self::check_grant`]). Kimliğe göre
    /// iptal kararı veren daemon içindir: Google'da iptal kullanıcının bu istemciye verdiği **tüm**
    /// izni düşürür, yani aynı Google hesabı Nuxut'ta zaten kayıtlıysa onu da bozar.
    pub fn exchange_code_unchecked(&self, code: &AuthorizationCode) -> Result<TokenSet, OAuthError> {
        let mut fields = vec![
            ("grant_type", "authorization_code"),
            ("code", code.code.expose()),
            ("redirect_uri", code.redirect_uri.as_str()),
            ("code_verifier", code.verifier.expose()),
        ];
        self.token_request(&mut fields, Grant::Initial)
    }

    /// Erişim token'ını yeniler. `invalid_grant` → [`OAuthError::Revoked`].
    pub fn refresh(&self, refresh_token: &SecretString) -> Result<TokenSet, OAuthError> {
        let scope = self.config.scope_string();
        let mut fields = vec![("grant_type", "refresh_token"), ("refresh_token", refresh_token.expose())];
        if self.config.provider == Provider::Microsoft {
            fields.push(("scope", scope.as_str()));
        }
        self.token_request(&mut fields, Grant::Refresh)
    }

    /// Token'ı sağlayıcıda iptal eder (Google: `POST /revoke`, form `token=`; yenileme token'ı
    /// iptal edilince tüm izin düşer). İptal uç noktası olmayan sağlayıcıda (Microsoft) hiçbir
    /// şey yapmaz. En iyi çaba, [`REVOKE_TIMEOUT`]; zaten geçersiz token (`invalid_token`) başarı sayılır.
    pub fn revoke(&self, token: &SecretString) -> Result<(), OAuthError> {
        let Some(url) = self.config.revoke_url.clone() else { return Ok(()) };
        let req = Request::post_form(url, &[("token", token.expose())])
            .max_body(MAX_TOKEN_RESPONSE)
            .timeout(REVOKE_TIMEOUT);
        let resp = self.http.send(req)?;
        if resp.is_success() {
            return Ok(());
        }
        match serde_json::from_slice::<ErrorResponse>(&resp.body) {
            Ok(e) if e.error == "invalid_token" => Ok(()),
            _ => Err(provider_error(&resp.body, Grant::Refresh)),
        }
    }

    /// Zorunlu kapsamlar verilmemişse hata döner; `revoke` ise token'ı da iptal eder (en iyi çaba).
    pub fn check_grant(&self, tokens: TokenSet, revoke: bool) -> Result<TokenSet, OAuthError> {
        let missing = self.config.missing_scopes(tokens.scope.as_deref());
        if missing.is_empty() {
            return Ok(tokens);
        }
        tracing::warn!(provider = self.config.provider.as_str(), missing = missing.len(), "zorunlu takvim kapsamı verilmedi");
        let token = tokens.refresh_token.as_ref().unwrap_or(&tokens.access_token);
        if revoke && let Err(e) = self.revoke(token) {
            tracing::warn!("kapsamı eksik token iptal edilemedi: {e}");
        }
        Err(OAuthError::ScopeMissing)
    }

    pub fn start_device_flow(&self) -> Result<DeviceCode, OAuthError> {
        let url = self.config.device_url.clone().ok_or(OAuthError::NotConfigured("cihaz kodu"))?;
        let scope = self.config.scope_string();
        let req = Request::post_form(url, &[("client_id", &self.config.client_id), ("scope", &scope)])
            .max_body(MAX_TOKEN_RESPONSE);
        let resp = self.http.send(req)?;
        if !resp.is_success() {
            return Err(provider_error(&resp.body, Grant::Initial));
        }
        serde_json::from_slice(&resp.body).map_err(|_| OAuthError::Provider("device_response_unparsable".into()))
    }

    /// Kullanıcı kodu girene kadar `interval` aralıkla yoklar (RFC 8628 §3.5). Kapsam denetimi
    /// [`Self::exchange_code`] ile aynıdır.
    pub fn poll_device_flow(&self, device: &DeviceCode, cancel: &CancelToken) -> Result<TokenSet, OAuthError> {
        let deadline = Instant::now() + Duration::from_secs(device.expires_in.min(30 * 60));
        let mut interval = Duration::from_secs(device.interval.clamp(1, 60));
        loop {
            sleep_cancellable(interval, cancel)?;
            if Instant::now() >= deadline {
                return Err(OAuthError::TimedOut);
            }
            let mut fields =
                vec![("grant_type", "urn:ietf:params:oauth:grant-type:device_code"), ("device_code", device.device_code.as_str())];
            match self.token_request(&mut fields, Grant::Initial) {
                Ok(tokens) => return self.check_grant(tokens, true),
                Err(OAuthError::Provider(e)) if e.starts_with("authorization_pending") => {}
                Err(OAuthError::Provider(e)) if e.starts_with("slow_down") => interval += Duration::from_secs(5),
                Err(OAuthError::Provider(e)) if e.starts_with("authorization_declined") => return Err(OAuthError::Denied),
                Err(OAuthError::Provider(e)) if e.starts_with("expired_token") => return Err(OAuthError::TimedOut),
                Err(e) => return Err(e),
            }
        }
    }

    fn token_request<'a>(&'a self, fields: &mut Vec<(&'a str, &'a str)>, grant: Grant) -> Result<TokenSet, OAuthError> {
        fields.push(("client_id", &self.config.client_id));
        if let Some(secret) = &self.config.client_secret {
            fields.push(("client_secret", secret));
        }
        let req = Request::post_form(self.config.token_url.clone(), fields)
            .header("accept", "application/json")
            .max_body(MAX_TOKEN_RESPONSE)
            .timeout(Duration::from_secs(30));
        let resp = self.http.send(req)?;
        if !resp.is_success() {
            return Err(provider_error(&resp.body, grant));
        }
        let parsed: TokenResponse =
            serde_json::from_slice(&resp.body).map_err(|_| OAuthError::Provider("token_response_unparsable".into()))?;
        let now = chrono::Utc::now().timestamp();
        // 60 sn güvenlik payı: süresi dolmak üzere olan token'la istek atılmaz.
        let expires_at = now + parsed.expires_in.unwrap_or(3600).clamp(60, 86_400) - 60;
        Ok(TokenSet {
            access_token: SecretString::new(parsed.access_token),
            refresh_token: parsed.refresh_token.filter(|t| !t.is_empty()).map(SecretString::new),
            expires_at,
            identity: parsed.id_token.as_deref().and_then(identity_from_id_token),
            scope: parsed.scope,
        })
    }
}

/// Sağlayıcı hatasını yalnızca **kodlara** indirger: `error` (RFC 6749 kodu) ve varsa
/// `error_description` içindeki `AADSTSnnnnn` numarası. Açıklamanın kendisi tutulmaz — Microsoft'unki
/// kullanıcının UPN'ini/e-postasını içerebilir (ör. AADSTS50020) ve bu değer loglara gider.
fn provider_error(body: &[u8], grant: Grant) -> OAuthError {
    match serde_json::from_slice::<ErrorResponse>(body) {
        Ok(e) if grant == Grant::Initial && is_admin_consent(&e.error, e.error_description.as_deref()) => {
            OAuthError::AdminConsent
        }
        Ok(e) if e.error == "invalid_grant" && grant == Grant::Refresh => OAuthError::Revoked,
        Ok(e) => OAuthError::Provider(error_code(&e.error, e.error_description.as_deref())),
        Err(_) => OAuthError::Provider("error_response_unparsable".into()),
    }
}

/// Güvenli hata kodu: `error` yalnızca `[a-z0-9_]` (en çok 64), ardından isteğe bağlı ` AADSTSnnnnn`.
pub(crate) fn error_code(error: &str, description: Option<&str>) -> String {
    let mut code: String = error
        .chars()
        .take(64)
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c.to_ascii_lowercase() } else { '?' })
        .collect();
    if code.is_empty() {
        code.push('?');
    }
    if let Some(n) = description.and_then(aadsts_number) {
        code.push_str(" AADSTS");
        code.push_str(&n);
    }
    code
}

/// `error_description` içindeki ilk `AADSTS` numarası (yalnızca rakamlar, en çok 9).
fn aadsts_number(description: &str) -> Option<String> {
    let rest = &description[description.find("AADSTS")? + "AADSTS".len()..];
    let digits: String = rest.chars().take_while(char::is_ascii_digit).take(9).collect();
    (!digits.is_empty()).then_some(digits)
}

fn sleep_cancellable(total: Duration, cancel: &CancelToken) -> Result<(), OAuthError> {
    let end = Instant::now() + total;
    while Instant::now() < end {
        if cancel.is_cancelled() {
            return Err(OAuthError::Cancelled);
        }
        std::thread::sleep(Duration::from_millis(100).min(end.saturating_duration_since(Instant::now())));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FakeServer, Reply};

    fn test_config(server: &FakeServer) -> OAuthConfig {
        OAuthConfig {
            provider: Provider::Google,
            authorize_url: server.url("/auth"),
            token_url: server.url("/token"),
            device_url: Some(server.url("/device")),
            revoke_url: Some(server.url("/revoke")),
            admin_consent_url: None,
            client_id: "cid".into(),
            client_secret: Some("public-secret".into()),
            scopes: vec!["openid".into(), "email".into()],
            extra_params: vec![("access_type".into(), "offline".into())],
            redirect_host: "127.0.0.1",
        }
    }

    fn microsoft_config(server: &FakeServer) -> OAuthConfig {
        OAuthConfig {
            provider: Provider::Microsoft,
            revoke_url: None,
            admin_consent_url: Some(server.url("/organizations/v2.0/adminconsent")),
            client_secret: None,
            redirect_host: "localhost",
            ..test_config(server)
        }
    }

    fn pages() -> LoopbackPages {
        LoopbackPages { lang: "tr".into(), done: PageText::new("Hesap bağlandı", "<kapat>"), ..Default::default() }
    }

    fn browser_get(url: &str) -> String {
        HttpClient::new().send(Request::get(Url::parse(url).unwrap())).unwrap().text()
    }

    fn query(url: &Url, k: &str) -> Option<String> {
        url.query_pairs().find(|(key, _)| key == k).map(|(_, v)| v.into_owned())
    }

    /// Oturumu başlatır, verilen sorguyla "tarayıcı" yönlendirmesini yapar, sonucu ve sayfayı döner.
    fn redirect_with(config: &OAuthConfig, query_tail: &str) -> (Result<AuthorizationCode, OAuthError>, std::thread::JoinHandle<String>) {
        let session = AuthorizationSession::start(config, None, pages()).unwrap();
        let auth = session.authorize_url().clone();
        let (redirect, state) = (query(&auth, "redirect_uri").unwrap(), query(&auth, "state").unwrap());
        let tail = query_tail.to_string();
        let browser = std::thread::spawn(move || browser_get(&format!("{redirect}?state={state}&{tail}")));
        (session.wait(Duration::from_secs(5), &CancelToken::default()), browser)
    }

    #[test]
    fn pkce_challenge_matches_rfc7636_appendix_b() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        let p = Pkce::generate();
        assert_eq!(p.verifier.expose().len(), 43);
    }

    #[test]
    fn full_loopback_flow_with_state_check_and_exchange() {
        let server = FakeServer::start(|req| {
            assert_eq!(req.path, "/token");
            assert_eq!(req.form("grant_type").as_deref(), Some("authorization_code"));
            assert_eq!(req.form("code").as_deref(), Some("the-code"));
            assert_eq!(req.form("client_secret").as_deref(), Some("public-secret"));
            let verifier = req.form("code_verifier").unwrap();
            assert_eq!(verifier.len(), 43);
            // id_token: {"email":"alice@example.com","name":"Alice"}
            let claims = URL_SAFE_NO_PAD.encode(br#"{"email":"alice@example.com","name":"Alice"}"#);
            Reply::status(200).json(&format!(
                r#"{{"access_token":"at","refresh_token":"rt","expires_in":3599,"id_token":"h.{claims}.s"}}"#
            ))
        });
        let config = test_config(&server);
        let session = AuthorizationSession::start(&config, Some("alice@example.com"), pages()).unwrap();
        let auth = session.authorize_url().clone();
        assert_eq!(query(&auth, "code_challenge_method").as_deref(), Some("S256"));
        assert_eq!(query(&auth, "access_type").as_deref(), Some("offline"));
        assert_eq!(query(&auth, "login_hint").as_deref(), Some("alice@example.com"));
        let redirect = query(&auth, "redirect_uri").unwrap();
        let state = query(&auth, "state").unwrap();

        // "Tarayıcı": önce favicon, sonra sahte state, sonra gerçek yönlendirme.
        let browser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            let _ = HttpClient::new().send(Request::get(Url::parse(&format!("{redirect}favicon.ico")).unwrap()));
            assert!(browser_get(&format!("{redirect}?code=evil&state=wrong")).contains("Invalid request"));
            browser_get(&format!("{redirect}?code=the-code&state={state}"))
        });
        let code = session.wait(Duration::from_secs(5), &CancelToken::default()).unwrap();
        assert_eq!(code.code.expose(), "the-code");

        let tokens = OAuthClient::new(config, HttpClient::new()).exchange_code(&code).unwrap();
        // Tarayıcı, çağıran sonucu gönderene (ya da yanıtı düşürene) dek bekler.
        drop(code);
        let page = browser.join().unwrap();
        assert!(page.contains("Hesap bağlandı") && page.contains("lang=\"tr\""), "{page}");
        assert!(page.contains("&lt;kapat&gt;"), "sayfa metni kaçışlanır");
        assert_eq!(tokens.access_token.expose(), "at");
        assert_eq!(tokens.refresh_token.unwrap().expose(), "rt");
        assert_eq!(tokens.identity.unwrap().email.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn caller_chooses_the_final_browser_page() {
        let server = FakeServer::start(|_| Reply::status(500));
        let (code, browser) = redirect_with(&test_config(&server), "code=c");
        code.unwrap().browser.send(&PageText::new("Takvim izni verilmedi", "Tekrar deneyin"));
        assert!(browser.join().unwrap().contains("Takvim izni verilmedi"));
    }

    #[test]
    fn login_hint_is_omitted_when_empty() {
        let server = FakeServer::start(|_| Reply::status(500));
        let session = AuthorizationSession::start(&test_config(&server), Some("  "), pages()).unwrap();
        assert_eq!(query(session.authorize_url(), "login_hint"), None);
    }

    #[test]
    fn user_denial_is_reported() {
        let server = FakeServer::start(|_| Reply::status(500));
        let (res, browser) = redirect_with(&test_config(&server), "error=access_denied");
        assert!(matches!(res, Err(OAuthError::Denied)));
        assert!(browser.join().unwrap().contains("Permission not granted"));
    }

    #[test]
    fn microsoft_admin_consent_is_recognised_from_redirect() {
        let server = FakeServer::start(|_| Reply::status(500));
        let config = microsoft_config(&server);
        for (error, n) in [("consent_required", "65001"), ("access_denied", "90094"), ("interaction_required", "90095")] {
            let tail = format!(
                "error={error}&error_description=AADSTS{n}%3A+ayse%40kurum.com+needs+admin+approval"
            );
            let (res, browser) = redirect_with(&config, &tail);
            assert!(matches!(res, Err(OAuthError::AdminConsent)), "{error}");
            assert!(browser.join().unwrap().contains("Administrator approval"));
        }
        // AADSTS numarası yoksa sıradan ret.
        let (res, _) = redirect_with(&config, "error=access_denied");
        assert!(matches!(res, Err(OAuthError::Denied)));
        // Başka numaralı hata yalnızca kod taşır; açıklama (UPN) sızmaz.
        let (res, _) = redirect_with(&config, "error=invalid_request&error_description=AADSTS50020%3A+ayse%40kurum.com");
        let Err(OAuthError::Provider(code)) = res else { panic!() };
        assert_eq!(code, "invalid_request AADSTS50020");

        let link = config.admin_consent_link().unwrap();
        assert!(link.path().ends_with("/organizations/v2.0/adminconsent"));
        assert_eq!(query(&link, "client_id").as_deref(), Some("cid"));
        assert_eq!(query(&link, "scope").as_deref(), Some("https://graph.microsoft.com/Calendars.ReadWrite"));
        assert_eq!(query(&link, "redirect_uri").as_deref(), Some("http://localhost"));
        assert_eq!(test_config(&server).admin_consent_link(), None);
    }

    #[test]
    fn admin_consent_at_token_endpoint_but_not_on_refresh() {
        let server = FakeServer::start(|_| {
            Reply::status(400).json(r#"{"error":"invalid_grant","error_description":"AADSTS65001: The user or administrator has not consented"}"#)
        });
        let client = OAuthClient::new(microsoft_config(&server), HttpClient::new());
        let (code, _browser) = redirect_with(&client.config, "code=c");
        assert!(matches!(client.exchange_code(&code.unwrap()), Err(OAuthError::AdminConsent)));
        // Yenilemede invalid_grant her zaman "yeniden bağlan".
        assert!(matches!(client.refresh(&"rt".into()), Err(OAuthError::Revoked)));
    }

    #[test]
    fn scope_matching_rules() {
        let server = FakeServer::start(|_| Reply::status(500));
        let google = test_config(&server);
        let full = "openid https://www.googleapis.com/auth/calendar.events https://www.googleapis.com/auth/calendar.calendarlist.readonly";
        assert!(google.missing_scopes(Some(full)).is_empty());
        assert!(google.missing_scopes(None).is_empty(), "scope yoksa istenenin aynısı (RFC 6749 §5.1)");
        assert_eq!(
            google.missing_scopes(Some("openid https://www.googleapis.com/auth/calendar.events")),
            vec!["https://www.googleapis.com/auth/calendar.calendarlist.readonly"]
        );
        assert!(google.missing_scopes(Some("https://www.googleapis.com/auth/calendar")).is_empty());
        let ms = microsoft_config(&server);
        assert!(ms.missing_scopes(Some("openid profile email Calendars.ReadWrite")).is_empty());
        assert!(ms.missing_scopes(Some("https://graph.microsoft.com/calendars.readwrite")).is_empty());
        assert_eq!(ms.missing_scopes(Some("openid User.Read Calendars.Read")).len(), 1);
    }

    #[test]
    fn missing_google_scope_revokes_the_token() {
        let server = FakeServer::start(|req| match req.path.as_str() {
            "/token" => Reply::status(200).json(
                r#"{"access_token":"at","refresh_token":"rt-partial","expires_in":3599,"scope":"openid email https://www.googleapis.com/auth/calendar.events"}"#,
            ),
            "/revoke" => Reply::status(200),
            _ => Reply::status(404),
        });
        let client = OAuthClient::new(test_config(&server), HttpClient::new());
        let (code, _browser) = redirect_with(&client.config, "code=c");
        assert!(matches!(client.exchange_code(&code.unwrap()), Err(OAuthError::ScopeMissing)));
        let revoke = server.requests().into_iter().find(|r| r.path == "/revoke").expect("token iptal edilmeli");
        assert_eq!(revoke.method, "POST");
        assert_eq!(revoke.form("token").as_deref(), Some("rt-partial"));

        // Kimlik zaten kayıtlıysa daemon iptal istemez: kayıtlı hesabın izni düşmez.
        let before = server.requests().len();
        let (code, _browser) = redirect_with(&client.config, "code=c2");
        let tokens = client.exchange_code_unchecked(&code.unwrap()).unwrap();
        assert!(matches!(client.check_grant(tokens, false), Err(OAuthError::ScopeMissing)));
        assert!(server.requests()[before..].iter().all(|r| r.path != "/revoke"));
    }

    #[test]
    fn revoke_posts_token_and_is_a_noop_without_endpoint() {
        let server = FakeServer::start(|req| match req.form("token").as_deref() {
            Some("gone") => Reply::status(400).json(r#"{"error":"invalid_token","error_description":"Token expired or revoked"}"#),
            Some(_) => Reply::status(200),
            None => Reply::status(400),
        });
        let google = OAuthClient::new(test_config(&server), HttpClient::new());
        google.revoke(&"rt".into()).unwrap();
        google.revoke(&"gone".into()).unwrap();
        let reqs = server.requests();
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().all(|r| r.path == "/revoke" && r.header("content-type").is_some_and(|c| c.contains("form"))));
        let ms = OAuthClient::new(microsoft_config(&server), HttpClient::new());
        ms.revoke(&"rt".into()).unwrap();
        assert_eq!(server.requests().len(), 2, "Microsoft'ta iptal isteği yok");
    }

    #[test]
    fn cancel_stops_waiting() {
        let server = FakeServer::start(|_| Reply::status(500));
        let session = AuthorizationSession::start(&test_config(&server), None, pages()).unwrap();
        let cancel = CancelToken::default();
        let c = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            c.cancel();
        });
        let t = Instant::now();
        assert!(matches!(session.wait(Duration::from_secs(30), &cancel), Err(OAuthError::Cancelled)));
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn invalid_grant_on_refresh_means_revoked() {
        let server = FakeServer::start(|_| {
            Reply::status(400).json(r#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#)
        });
        let client = OAuthClient::new(test_config(&server), HttpClient::new());
        assert!(matches!(client.refresh(&"rt".into()), Err(OAuthError::Revoked)));
    }

    #[test]
    fn provider_errors_keep_only_codes() {
        let body = br#"{"error":"invalid_request","error_description":"AADSTS50020: User account 'ayse@ornek.com' from identity provider 'live.com' does not exist in tenant. Trace ID: 1b2c"}"#;
        let OAuthError::Provider(code) = provider_error(body, Grant::Initial) else { panic!() };
        assert_eq!(code, "invalid_request AADSTS50020");
        let e = OAuthError::Provider(code);
        assert!(!format!("{e} {e:?}").contains("ayse"));
        // JSON olmayan gövde ve tuhaf kod da sızdırmaz.
        let OAuthError::Provider(raw) = provider_error(b"<html>ayse@ornek.com</html>", Grant::Initial) else { panic!() };
        assert!(!raw.contains("ayse"));
        assert_eq!(error_code("x y@z", None), "x?y?z");
        // Token yanıtı tipi bozuksa serde iletisi (değeri alıntılar) taşınmaz.
        let server = FakeServer::start(|_| Reply::status(200).json(r#"{"access_token":12345678}"#));
        let client = OAuthClient::new(test_config(&server), HttpClient::new());
        let Err(e) = client.refresh(&"rt".into()) else { panic!() };
        assert!(!format!("{e} {e:?}").contains("12345678"));
    }

    #[test]
    fn device_flow_polls_until_granted() {
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let p = Arc::clone(&polls);
        let server = FakeServer::start(move |req| match req.path.as_str() {
            "/device" => Reply::status(200).json(
                r#"{"device_code":"dc","user_code":"ABCD-EFGH","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":1}"#,
            ),
            "/token" if p.fetch_add(1, Ordering::SeqCst) == 0 => {
                Reply::status(400).json(r#"{"error":"authorization_pending"}"#)
            }
            "/token" => Reply::status(200).json(r#"{"access_token":"at","expires_in":3600,"scope":"Calendars.Read"}"#),
            _ => Reply::status(404),
        });
        let client = OAuthClient::new(test_config(&server), HttpClient::new());
        let device = client.start_device_flow().unwrap();
        assert_eq!(device.user_code, "ABCD-EFGH");
        let tokens = client.poll_device_flow(&device, &CancelToken::default()).unwrap_err();
        // Test yapılandırması Google: kapsam eksik → cihaz akışı da reddeder.
        assert!(matches!(tokens, OAuthError::ScopeMissing));
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        let ms = OAuthClient::new(microsoft_config(&server), HttpClient::new());
        let device = ms.start_device_flow().unwrap();
        let err = ms.poll_device_flow(&device, &CancelToken::default()).unwrap_err();
        assert!(matches!(err, OAuthError::ScopeMissing), "Calendars.Read ≠ Calendars.ReadWrite");
    }

    #[test]
    fn device_flow_with_full_scope_succeeds() {
        let server = FakeServer::start(move |req| match req.path.as_str() {
            "/device" => Reply::status(200).json(
                r#"{"device_code":"dc","user_code":"ABCD-EFGH","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":1}"#,
            ),
            "/token" => Reply::status(200).json(r#"{"access_token":"at","expires_in":3600,"scope":"openid Calendars.ReadWrite"}"#),
            _ => Reply::status(404),
        });
        let ms = OAuthClient::new(microsoft_config(&server), HttpClient::new());
        let device = ms.start_device_flow().unwrap();
        assert_eq!(ms.poll_device_flow(&device, &CancelToken::default()).unwrap().access_token.expose(), "at");
    }
}
