//! Adresi kullanıcının varsayılan tarayıcısında açma.
//!
//! Önce XDG masaüstü portalı (`org.freedesktop.portal.OpenURI`): Flatpak içinde de çalışır,
//! kullanıcının seçtiği tarayıcıya saygı duyar. Portal yoksa `xdg-open` (kabuk **olmadan**,
//! adres tek argüman olarak). `open` crate'i de aynı `xdg-open`'ı çağırdığından ek bağımlılık
//! getirmez; portal yolunu biz yazıyoruz (bkz. ADR-0006).
//!
//! Yalnızca `https://` ve `http://` açılır; yerel dosya veya özel şema açılmaz.

use std::collections::HashMap;
use std::process::{Command, Stdio};

use url::Url;
use zbus::zvariant::Value;

#[derive(Debug, thiserror::Error)]
pub enum BrowserError {
    #[error("yalnızca http(s) adresleri açılır")]
    Scheme,
    #[error("tarayıcı açılamadı: {0}")]
    Failed(String),
}

pub fn open(url: &Url) -> Result<(), BrowserError> {
    if !matches!(url.scheme(), "https" | "http") {
        return Err(BrowserError::Scheme);
    }
    match open_portal(url) {
        Ok(()) => Ok(()),
        Err(portal_err) => {
            tracing::debug!("portal OpenURI başarısız ({portal_err}); xdg-open deneniyor");
            Command::new("xdg-open")
                .arg(url.as_str())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map(drop)
                .map_err(|e| BrowserError::Failed(e.to_string()))
        }
    }
}

fn open_portal(url: &Url) -> zbus::Result<()> {
    let conn = zbus::blocking::Connection::session()?;
    let options: HashMap<&str, Value<'_>> = HashMap::new();
    conn.call_method(
        Some("org.freedesktop.portal.Desktop"),
        "/org/freedesktop/portal/desktop",
        Some("org.freedesktop.portal.OpenURI"),
        "OpenURI",
        &("", url.as_str(), options),
    )?;
    Ok(())
}
