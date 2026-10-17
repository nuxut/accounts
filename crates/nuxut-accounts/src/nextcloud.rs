//! Nextcloud Login Flow v2: kullanıcı yalnızca sunucu adresini yazar, tarayıcıda "İzin ver"e
//! basar; Nextcloud bu cihaza özel bir **uygulama şifresi** üretir ve biz onu yoklayarak alırız.
//!
//! <https://docs.nextcloud.com/server/latest/developer_manual/client_apis/LoginFlow/index.html#login-flow-v2>
//!
//! 1. `POST <sunucu>/index.php/login/v2` → `{ poll: { token, endpoint }, login }`
//! 2. `login` tarayıcıda açılır.
//! 3. `POST <endpoint>` gövde `token=<token>`: onaya kadar 404, sonra
//!    `{ server, loginName, appPassword }` (tek seferlik).
//!
//! Güvenlik (uygulama şifresi bu akışta düz metin taşınır):
//! - Sunucu `https` olmalı; `http` yalnızca loopback + geliştirme bayrağıyla
//!   ([`Policy::allow_insecure_loopback`]).
//! - Akışın **kökeni** kullanıcının girdiği adresin kökenidir (şema + ana makine + port).
//!   Başlatma yanıtının son adresi (yönlendirme sonrası), `poll.endpoint`, `login` ve yoklama
//!   yanıtındaki `server` aynı kökende olmalı; değilse akış durur (token/şifre başka sunucuya
//!   gönderilmez, başka sunucunun adına kaydedilmez).
//! - Alanlar uzunluk ve karakter bakımından doğrulanır; şifre ve token yalnızca
//!   [`SecretString`] içinde taşınır (Debug'da görünmez, düşerken sıfırlanır), loglanmaz.

use std::fmt;
use std::time::{Duration, Instant};

use serde::Deserialize;
use url::{Origin, Url};

use crate::http::{HttpClient, HttpError, Policy, Request, is_loopback};
use crate::oauth::CancelToken;
use crate::secret::SecretString;

pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(20 * 60);
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);
const MAX_RESPONSE: u64 = 64 * 1024;
const MAX_TOKEN_LEN: usize = 512;
const MAX_LOGIN_LEN: usize = 256;
const MAX_PASSWORD_LEN: usize = 256;
const MAX_URL_LEN: usize = 2048;

#[derive(Debug, thiserror::Error)]
pub enum LoginFlowError {
    #[error("bu adreste Nextcloud bulunamadı")]
    NotNextcloud,
    #[error("sunucu şifrelenmemiş bağlantı (http) kullanıyor; https gerekli")]
    Insecure,
    #[error("sunucu yanıtı başka bir adrese işaret ediyor ({0}); güvenlik için durduruldu")]
    OriginMismatch(String),
    #[error("giriş süresi doldu")]
    TimedOut,
    #[error("iptal edildi")]
    Cancelled,
    #[error("sunucu yanıtı geçersiz: {0}")]
    BadResponse(&'static str),
    #[error(transparent)]
    Http(#[from] HttpError),
}

/// Başlatılmış giriş: tarayıcıda açılacak adres + yoklama bilgisi.
pub struct LoginFlow {
    pub login_url: Url,
    origin: Origin,
    poll_endpoint: Url,
    poll_token: SecretString,
}

impl fmt::Debug for LoginFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginFlow").field("origin", &self.origin.ascii_serialization()).finish_non_exhaustive()
    }
}

/// Onaydan sonra gelen kimlik bilgisi.
#[derive(Clone)]
pub struct NextcloudCredentials {
    /// Akışın kökenindeki Nextcloud kökü (yol önekiyle).
    pub server: Url,
    pub login_name: String,
    pub app_password: SecretString,
}

impl fmt::Debug for NextcloudCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NextcloudCredentials")
            .field("server", &self.server.as_str())
            .field("login_name", &self.login_name)
            .field("app_password", &"<gizli>")
            .finish()
    }
}

#[derive(Deserialize)]
struct StartResponse {
    poll: PollInfo,
    login: String,
}

#[derive(Deserialize)]
struct PollInfo {
    token: SecretString,
    endpoint: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PollResponse {
    server: String,
    login_name: String,
    app_password: SecretString,
}

/// Kullanıcının yazdığı adresi normalleştirir: şema yoksa `https://`, sondaki
/// `/index.php...` ve `/remote.php...` atılır.
pub fn normalize_server(input: &str) -> Option<Url> {
    let input = input.trim();
    if input.is_empty() || input.len() > MAX_URL_LEN {
        return None;
    }
    let with_scheme = if input.contains("://") { input.to_string() } else { format!("https://{input}") };
    let mut url = Url::parse(&with_scheme).ok()?;
    if !matches!(url.scheme(), "https" | "http") || url.host().is_none() || !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let path = url.path().to_string();
    let cut = ["/index.php", "/remote.php", "/apps/"].iter().filter_map(|m| path.find(m)).min();
    let mut base = match cut {
        Some(i) => path[..i].to_string(),
        None => path,
    };
    if !base.ends_with('/') {
        base.push('/');
    }
    url.set_path(&base);
    url.set_query(None);
    url.set_fragment(None);
    Some(url)
}

/// Uygulama şifresi taşıyan bağlantı yalnızca https (ya da geliştirme bayrağıyla loopback).
fn check_secure(url: &Url, policy: Policy) -> Result<(), LoginFlowError> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if policy.allow_insecure_loopback && is_loopback(url) => Ok(()),
        _ => Err(LoginFlowError::Insecure),
    }
}

fn same_origin(origin: &Origin, url: &Url) -> Result<(), LoginFlowError> {
    if &url.origin() == origin {
        Ok(())
    } else {
        Err(LoginFlowError::OriginMismatch(url.host_str().unwrap_or_default().chars().take(253).collect()))
    }
}

fn parse_url(s: &str, what: &'static str) -> Result<Url, LoginFlowError> {
    if s.len() > MAX_URL_LEN {
        return Err(LoginFlowError::BadResponse(what));
    }
    Url::parse(s).map_err(|_| LoginFlowError::BadResponse(what))
}

/// Yazdırılabilir, kontrol karakteri içermeyen, sınırlı uzunlukta.
fn valid_text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}

impl LoginFlow {
    pub fn start(http: &HttpClient, server: &Url) -> Result<Self, LoginFlowError> {
        check_secure(server, http.policy())?;
        let origin = server.origin();
        let url = server.join("index.php/login/v2").map_err(|_| LoginFlowError::BadResponse("url"))?;
        let resp = http.send(Request::new(crate::http::Method::POST, url).max_body(MAX_RESPONSE))?;
        // Yönlendirme başka bir kökene götürdüyse akış o sunucuyla sürdürülmez.
        same_origin(&origin, &resp.url)?;
        if !resp.is_success() {
            return Err(LoginFlowError::NotNextcloud);
        }
        let parsed: StartResponse = serde_json::from_slice(&resp.body).map_err(|_| LoginFlowError::NotNextcloud)?;
        if !valid_text(parsed.poll.token.expose(), MAX_TOKEN_LEN) {
            return Err(LoginFlowError::BadResponse("poll token"));
        }
        let login_url = parse_url(&parsed.login, "login url")?;
        let poll_endpoint = parse_url(&parsed.poll.endpoint, "poll url")?;
        same_origin(&origin, &login_url)?;
        same_origin(&origin, &poll_endpoint)?;
        check_secure(&poll_endpoint, http.policy())?;
        Ok(Self { login_url, origin, poll_endpoint, poll_token: parsed.poll.token })
    }

    /// Kullanıcı onaylayana kadar yoklar.
    pub fn wait(&self, http: &HttpClient, timeout: Duration, interval: Duration, cancel: &CancelToken) -> Result<NextcloudCredentials, LoginFlowError> {
        let deadline = Instant::now() + timeout;
        loop {
            if cancel.is_cancelled() {
                return Err(LoginFlowError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(LoginFlowError::TimedOut);
            }
            // Yoklama yönlendirilmez: token'ı taşıyan POST hiçbir yere taşınmaz.
            let req = Request::post_form(self.poll_endpoint.clone(), &[("token", self.poll_token.expose())])
                .max_body(MAX_RESPONSE)
                .timeout(Duration::from_secs(20))
                .no_redirects();
            match http.send(req) {
                Ok(resp) if resp.is_success() => return self.validate(&resp.body, http.policy()),
                // 404: henüz onaylanmadı. Geçici ağ hatası da beklemeyi bozmaz.
                Ok(resp) if resp.status.as_u16() == 404 => {}
                Ok(_) => return Err(LoginFlowError::BadResponse("poll status")),
                Err(e) if e.is_transient() => {}
                Err(e) => return Err(e.into()),
            }
            let wake = Instant::now() + interval;
            while Instant::now() < wake {
                if cancel.is_cancelled() {
                    return Err(LoginFlowError::Cancelled);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    fn validate(&self, body: &[u8], policy: Policy) -> Result<NextcloudCredentials, LoginFlowError> {
        let parsed: PollResponse = serde_json::from_slice(body).map_err(|_| LoginFlowError::BadResponse("credentials response"))?;
        if !valid_text(&parsed.login_name, MAX_LOGIN_LEN) {
            return Err(LoginFlowError::BadResponse("login name"));
        }
        let pw = parsed.app_password.expose();
        if pw.is_empty() || pw.len() > MAX_PASSWORD_LEN || !pw.chars().all(|c| c.is_ascii_graphic()) {
            return Err(LoginFlowError::BadResponse("app password"));
        }
        let server = normalize_server(&parsed.server).ok_or(LoginFlowError::BadResponse("server url"))?;
        same_origin(&self.origin, &server)?;
        check_secure(&server, policy)?;
        Ok(NextcloudCredentials { server, login_name: parsed.login_name, app_password: parsed.app_password })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::testing::{FakeServer, RecordedRequest, Reply};

    fn dev() -> HttpClient {
        HttpClient::with_policy(Policy { allow_insecure_loopback: true, ..Default::default() })
    }

    /// `poll_server`: yoklama yanıtındaki `server` alanı (`None` = kendi kökü).
    fn nextcloud(poll_server: Option<String>, endpoint: Option<String>) -> impl Fn(&RecordedRequest) -> Reply {
        let polls = Arc::new(AtomicUsize::new(0));
        move |req| {
            let base = format!("http://{}", req.header("host").unwrap());
            let endpoint = endpoint.clone().unwrap_or_else(|| format!("{base}/login/v2/poll"));
            match (req.method.as_str(), req.path.as_str()) {
                ("POST", "/index.php/login/v2") => Reply::status(200).json(&format!(
                    r#"{{"poll":{{"token":"tok","endpoint":"{endpoint}"}},"login":"{base}/login/v2/flow/abc"}}"#
                )),
                ("POST", "/login/v2/poll") => {
                    assert_eq!(req.form("token").as_deref(), Some("tok"));
                    if polls.fetch_add(1, Ordering::SeqCst) < 2 {
                        Reply::status(404).body("[]")
                    } else {
                        let server = poll_server.clone().unwrap_or(base);
                        Reply::status(200).json(&format!(r#"{{"server":"{server}","loginName":"alice","appPassword":"app-pw-123"}}"#))
                    }
                }
                _ => Reply::status(404),
            }
        }
    }

    fn run(server: &FakeServer, http: &HttpClient) -> Result<NextcloudCredentials, LoginFlowError> {
        let flow = LoginFlow::start(http, server.base())?;
        flow.wait(http, Duration::from_secs(10), Duration::from_millis(20), &CancelToken::default())
    }

    #[test]
    fn normalizes_user_input() {
        let n = |s| normalize_server(s).map(|u| u.to_string());
        assert_eq!(n("cloud.example.com").as_deref(), Some("https://cloud.example.com/"));
        assert_eq!(n("https://example.com/nextcloud/index.php/apps/files").as_deref(), Some("https://example.com/nextcloud/"));
        assert_eq!(n("https://example.com/remote.php/dav/").as_deref(), Some("https://example.com/"));
        assert_eq!(n("https://user:pw@example.com/").as_deref(), None);
        assert_eq!(n("  ").as_deref(), None);
        assert_eq!(n("ftp://x").as_deref(), None);
    }

    #[test]
    fn login_flow_v2_end_to_end() {
        let server = FakeServer::start(nextcloud(None, None));
        let creds = run(&server, &dev()).unwrap();
        assert_eq!(creds.login_name, "alice");
        assert_eq!(creds.app_password.expose(), "app-pw-123");
        assert_eq!(creds.server, *server.base());
    }

    #[test]
    fn plain_http_is_refused_without_dev_flag() {
        let server = FakeServer::start(nextcloud(None, None));
        assert!(matches!(LoginFlow::start(&HttpClient::new(), server.base()), Err(LoginFlowError::Insecure)));
        assert!(server.requests().is_empty(), "hiçbir istek gönderilmemeli");
        let lan = Url::parse("http://192.168.1.10/").unwrap();
        assert!(matches!(LoginFlow::start(&dev(), &lan), Err(LoginFlowError::Insecure)));
    }

    #[test]
    fn poll_endpoint_on_another_origin_is_refused() {
        let server = FakeServer::start(nextcloud(None, Some("https://evil.example/poll".into())));
        let err = LoginFlow::start(&dev(), server.base()).unwrap_err();
        assert!(matches!(err, LoginFlowError::OriginMismatch(ref h) if h == "evil.example"), "{err:?}");
    }

    #[test]
    fn returned_server_on_another_origin_is_refused() {
        let server = FakeServer::start(nextcloud(Some("https://evil.example".into()), None));
        assert!(matches!(run(&server, &dev()), Err(LoginFlowError::OriginMismatch(_))));
        // Aynı ana makine, farklı port da başka köken.
        let server = FakeServer::start(nextcloud(Some("http://127.0.0.1:1".into()), None));
        assert!(matches!(run(&server, &dev()), Err(LoginFlowError::OriginMismatch(_))));
    }

    #[test]
    fn oversized_or_malformed_fields_are_refused() {
        let handler = |pw: String| {
            move |req: &RecordedRequest| {
                let base = format!("http://{}", req.header("host").unwrap());
                match req.path.as_str() {
                    "/index.php/login/v2" => Reply::status(200).json(&format!(
                        r#"{{"poll":{{"token":"tok","endpoint":"{base}/p"}},"login":"{base}/l"}}"#
                    )),
                    _ => Reply::status(200).json(&format!(r#"{{"server":"{base}","loginName":"alice","appPassword":"{pw}"}}"#)),
                }
            }
        };
        for pw in ["x".repeat(300), String::new(), "a b\\u0000".into()] {
            let server = FakeServer::start(handler(pw.clone()));
            assert!(matches!(run(&server, &dev()), Err(LoginFlowError::BadResponse(_))), "{pw:?}");
        }
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let creds = NextcloudCredentials {
            server: Url::parse("https://x/").unwrap(),
            login_name: "alice".into(),
            app_password: SecretString::new("app-pw-SECRET".into()),
        };
        let flow = LoginFlow {
            login_url: Url::parse("https://x/l").unwrap(),
            origin: Url::parse("https://x/").unwrap().origin(),
            poll_endpoint: Url::parse("https://x/p").unwrap(),
            poll_token: SecretString::new("tok-SECRET".into()),
        };
        let shown = format!("{creds:?} {flow:?}");
        assert!(!shown.contains("SECRET"), "{shown}");
    }

    /// Kendisine gelen her isteği kaydeden "başka sunucu" (hiç istek almamalı).
    fn trap() -> FakeServer {
        FakeServer::start(|_| Reply::status(200).json(r#"{"server":"x","loginName":"x","appPassword":"x"}"#))
    }

    #[test]
    fn login_url_on_another_origin_is_refused() {
        // Tarayıcıda açılacak adres başka sunucudaysa kullanıcı orada "İzin ver"e basardı.
        let server = FakeServer::start(|req| {
            let base = format!("http://{}", req.header("host").unwrap());
            Reply::status(200).json(&format!(r#"{{"poll":{{"token":"tok","endpoint":"{base}/p"}},"login":"https://evil.example/l"}}"#))
        });
        let err = LoginFlow::start(&dev(), server.base()).unwrap_err();
        assert!(matches!(err, LoginFlowError::OriginMismatch(ref h) if h == "evil.example"), "{err:?}");
    }

    #[test]
    fn start_redirect_to_another_origin_stops_the_flow() {
        let trap = trap();
        let target = trap.url("/index.php/login/v2").to_string();
        let server = FakeServer::start(move |_| Reply::status(307).header("location", &target));
        let err = LoginFlow::start(&dev(), server.base()).unwrap_err();
        assert!(matches!(err, LoginFlowError::OriginMismatch(_)), "{err:?}");
        // Gövdesiz başlatma isteği yönlendirmeyi izleyebilir (kimlik/gizli bilgi taşımaz; üretimde
        // sunucunun seçtiği köken yalnızca genel internet), ama akış o sunucuyla sürdürülmez:
        // yoklama/token hiç gitmez.
        let reqs = trap.requests();
        assert!(reqs.iter().all(|r| r.body.is_empty() && r.header("authorization").is_none()), "{reqs:?}");
        assert!(reqs.len() <= 1, "akış başka sunucuda sürdürülmemeli: {reqs:?}");
    }

    #[test]
    fn poll_is_never_redirected_and_token_stays_home() {
        let trap = trap();
        let target = trap.url("/steal").to_string();
        let server = FakeServer::start(move |req| {
            let base = format!("http://{}", req.header("host").unwrap());
            match req.path.as_str() {
                "/index.php/login/v2" => Reply::status(200).json(&format!(
                    r#"{{"poll":{{"token":"tok-SECRET","endpoint":"{base}/p"}},"login":"{base}/l"}}"#
                )),
                // Yoklama başka sunucuya yönlendirilmek istenir: token oraya taşınmamalı.
                _ => Reply::status(307).header("location", &target),
            }
        });
        let flow = LoginFlow::start(&dev(), server.base()).unwrap();
        let err = flow.wait(&dev(), Duration::from_secs(10), Duration::from_millis(20), &CancelToken::default()).unwrap_err();
        assert!(matches!(err, LoginFlowError::BadResponse("poll status")), "{err:?}");
        assert!(trap.requests().is_empty(), "yoklama token'ı başka sunucuya gitti");
    }

    #[test]
    fn unexpected_poll_status_ends_the_wait() {
        // 404 dışındaki yanıt (ör. 500 ya da 403) sonsuz yoklamaya dönüşmez.
        for status in [403u16, 500] {
            let server = FakeServer::start(move |req| {
                let base = format!("http://{}", req.header("host").unwrap());
                match req.path.as_str() {
                    "/index.php/login/v2" => Reply::status(200).json(&format!(
                        r#"{{"poll":{{"token":"tok","endpoint":"{base}/p"}},"login":"{base}/l"}}"#
                    )),
                    _ => Reply::status(status),
                }
            });
            let flow = LoginFlow::start(&dev(), server.base()).unwrap();
            let err = flow.wait(&dev(), Duration::from_secs(10), Duration::from_millis(20), &CancelToken::default()).unwrap_err();
            assert!(matches!(err, LoginFlowError::BadResponse("poll status")), "{status}: {err:?}");
        }
    }

    /// Hiç onaylanmayan akış: yoklama hep 404.
    fn never_approved() -> FakeServer {
        FakeServer::start(|req| {
            let base = format!("http://{}", req.header("host").unwrap());
            match req.path.as_str() {
                "/index.php/login/v2" => Reply::status(200).json(&format!(
                    r#"{{"poll":{{"token":"tok","endpoint":"{base}/p"}},"login":"{base}/l"}}"#
                )),
                _ => Reply::status(404).body("[]"),
            }
        })
    }

    #[test]
    fn cancel_stops_waiting_promptly() {
        let server = never_approved();
        let flow = LoginFlow::start(&dev(), server.base()).unwrap();
        let cancel = CancelToken::default();
        let started = Instant::now();
        let err = std::thread::scope(|s| {
            let waiter = s.spawn(|| flow.wait(&dev(), Duration::from_secs(60), Duration::from_secs(30), &cancel));
            // İlk yoklama gidene kadar bekle (koşul; sınırlı).
            let deadline = Instant::now() + Duration::from_secs(10);
            while server.requests().iter().all(|r| r.path != "/p") {
                assert!(Instant::now() < deadline, "yoklama başlamadı");
                std::thread::sleep(Duration::from_millis(10));
            }
            cancel.cancel();
            waiter.join().unwrap().unwrap_err()
        });
        assert!(matches!(err, LoginFlowError::Cancelled), "{err:?}");
        // Yoklama aralığı 30 sn; iptal en geç ~100 ms'lik dilimde fark edilir.
        assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    }

    #[test]
    fn unapproved_flow_times_out() {
        let server = never_approved();
        let flow = LoginFlow::start(&dev(), server.base()).unwrap();
        let err = flow.wait(&dev(), Duration::from_millis(300), Duration::from_millis(20), &CancelToken::default()).unwrap_err();
        assert!(matches!(err, LoginFlowError::TimedOut), "{err:?}");
        // Hata metni token ya da adres taşımaz.
        assert!(!format!("{err} {err:?}").contains("tok"));
    }

    #[test]
    fn non_nextcloud_server_is_detected() {
        let server = FakeServer::start(|_| Reply::status(200).body("<html>hello</html>"));
        let err = LoginFlow::start(&dev(), server.base()).unwrap_err();
        assert!(matches!(err, LoginFlowError::NotNextcloud));
    }
}
