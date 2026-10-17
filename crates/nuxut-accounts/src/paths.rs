//! XDG dizinleri. Göreli (geçersiz) XDG değerleri yok sayılır (XDG Base Directory kuralı).

use std::path::PathBuf;

fn xdg(var: &str, fallback: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from).filter(|p| p.is_absolute()).map(|h| h.join(fallback)))
}

/// `$XDG_DATA_HOME/nuxut`.
pub fn data_dir() -> Option<PathBuf> {
    xdg("XDG_DATA_HOME", ".local/share").map(|p| p.join("nuxut"))
}

/// `$XDG_CACHE_HOME/nuxut`.
pub fn cache_dir() -> Option<PathBuf> {
    xdg("XDG_CACHE_HOME", ".cache").map(|p| p.join("nuxut"))
}

/// `$XDG_CONFIG_HOME/nuxut`.
pub fn config_dir() -> Option<PathBuf> {
    xdg("XDG_CONFIG_HOME", ".config").map(|p| p.join("nuxut"))
}
