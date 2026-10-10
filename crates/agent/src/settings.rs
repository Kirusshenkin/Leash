//! Ключи `storage.local`. Хранятся только списки сайтов.

pub(crate) const KEY_ALLOW_ORIGINS: &str = "allow_origins";
pub(crate) const KEY_DENY_HOSTS: &str = "deny_hosts";

/// Ключи прежних версий (ключ API, модель, лимит ответа): удаляются при
/// открытии настроек, чтобы в профиле не оставалось ключа.
pub(crate) const LEGACY_KEYS: &[&str] = &["api_key", "api_key_hint", "model", "max_tokens"];
