//! Настройки: ключ API, модель, лимит токенов. Разбор в типы, без сырых строк.

use std::fmt;

/// Ключи хранилищ. Ключ API и подсказка к нему — в `storage.session`
/// (недоступна content-скриптам, очищается при закрытии Firefox), остальное —
/// в `storage.local`.
pub(crate) const KEY_API_KEY: &str = "api_key";
pub(crate) const KEY_API_KEY_HINT: &str = "api_key_hint";
pub(crate) const KEY_MODEL: &str = "model";
pub(crate) const KEY_MAX_TOKENS: &str = "max_tokens";
pub(crate) const KEY_ALLOW_ORIGINS: &str = "allow_origins";
pub(crate) const KEY_DENY_HOSTS: &str = "deny_hosts";

/// Разрешённые модели. Первая используется по умолчанию: агентный цикл делает
/// много запросов, поэтому по умолчанию не самая дорогая.
pub(crate) const MODELS: &[&str] = &["claude-sonnet-5-5", "claude-opus-5-5", "claude-haiku-5-5"];

pub(crate) const MAX_TOKENS_MIN: u32 = 256;
/// Потолок ответа: при большем длинный ответ рискует не уложиться в таймаут
/// запроса (ответ без стриминга).
pub(crate) const MAX_TOKENS_MAX: u32 = 8_192;
pub(crate) const MAX_TOKENS_DEFAULT: u32 = 4_096;

const KEY_PREFIX: &str = "sk-ant-";
const ADMIN_KEY_PREFIX: &str = "sk-ant-admin";
const KEY_MIN_LEN: usize = 40;
const KEY_MAX_LEN: usize = 256;

/// Ключ API. `Debug` не печатает значение; доступ только через `expose`.
pub(crate) struct ApiKey(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyError {
    Empty,
    WrongPrefix,
    AdminKey,
    BadLength,
    BadChars,
}

impl ApiKey {
    pub(crate) fn parse(input: &str) -> Result<Self, KeyError> {
        let key = input.trim();
        if key.is_empty() {
            return Err(KeyError::Empty);
        }
        // Админ-ключ управляет всей организацией; в браузере ему не место.
        if key.starts_with(ADMIN_KEY_PREFIX) {
            return Err(KeyError::AdminKey);
        }
        if !key.starts_with(KEY_PREFIX) {
            return Err(KeyError::WrongPrefix);
        }
        if !(KEY_MIN_LEN..=KEY_MAX_LEN).contains(&key.len()) {
            return Err(KeyError::BadLength);
        }
        if !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(KeyError::BadChars);
        }
        Ok(Self(key.to_owned()))
    }

    /// Единственное место, где значение ключа покидает тип.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    /// Последние 4 символа для показа «ключ задан, …abcd».
    pub(crate) fn hint(&self) -> String {
        let start = self.0.len().saturating_sub(4);
        self.0[start..].to_owned()
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiKey(***)")
    }
}

impl KeyError {
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::Empty => "Ключ пустой.",
            Self::WrongPrefix => "Ключ должен начинаться с sk-ant-.",
            Self::AdminKey => {
                "Это админ-ключ организации. Используйте обычный ключ API с лимитом расходов."
            }
            Self::BadLength => "Неверная длина ключа.",
            Self::BadChars => "Ключ содержит недопустимые символы.",
        }
    }
}

/// Модель из списка разрешённых; всё остальное отклоняется.
pub(crate) fn parse_model(input: &str) -> Option<&'static str> {
    MODELS.iter().copied().find(|m| *m == input)
}

/// Модель из хранилища: при любом мусоре берётся модель по умолчанию.
pub(crate) fn model_from_storage(value: Option<&str>) -> &'static str {
    value.and_then(parse_model).unwrap_or(MODELS[0])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MaxTokensError {
    NotANumber,
    OutOfRange,
}

/// Лимит токенов из поля ввода настроек.
pub(crate) fn parse_max_tokens(input: &str) -> Result<u32, MaxTokensError> {
    let n: u32 = input
        .trim()
        .parse()
        .map_err(|_| MaxTokensError::NotANumber)?;
    if (MAX_TOKENS_MIN..=MAX_TOKENS_MAX).contains(&n) {
        Ok(n)
    } else {
        Err(MaxTokensError::OutOfRange)
    }
}

/// Лимит токенов из хранилища: при любом мусоре берётся значение по умолчанию.
pub(crate) fn max_tokens_from_storage(value: Option<f64>) -> u32 {
    match value {
        Some(v)
            if v.fract() == 0.0
                && v >= f64::from(MAX_TOKENS_MIN)
                && v <= f64::from(MAX_TOKENS_MAX) =>
        {
            // Диапазон проверен выше, усечения нет.
            v as u32
        }
        _ => MAX_TOKENS_DEFAULT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_of(len: usize) -> String {
        let mut k = String::from(KEY_PREFIX);
        k.push_str(&"a".repeat(len - KEY_PREFIX.len()));
        k
    }

    #[test]
    fn api_key() {
        let ok = key_of(108);
        assert_eq!(
            ApiKey::parse(&ok).map(|k| k.expose().to_owned()),
            Ok(ok.clone())
        );
        assert!(
            ApiKey::parse(&format!("  {ok}\n")).is_ok(),
            "пробелы по краям при вставке"
        );

        let cases: &[(String, KeyError)] = &[
            (String::new(), KeyError::Empty),
            ("   ".into(), KeyError::Empty),
            (
                format!("sk-ant-admin01-{}", "a".repeat(80)),
                KeyError::AdminKey,
            ),
            (format!("sk-proj-{}", "a".repeat(80)), KeyError::WrongPrefix),
            (format!("SK-ANT-{}", "a".repeat(80)), KeyError::WrongPrefix),
            (key_of(KEY_MIN_LEN - 1), KeyError::BadLength),
            (key_of(KEY_MAX_LEN + 1), KeyError::BadLength),
            (format!("{}\"x", key_of(60)), KeyError::BadChars),
            (format!("{} x", key_of(60)), KeyError::BadChars),
            (format!("{}\r\nX-Evil: 1", key_of(60)), KeyError::BadChars),
            (format!("{}я", key_of(60)), KeyError::BadChars),
        ];
        for (input, expected) in cases {
            assert_eq!(ApiKey::parse(input).err(), Some(*expected), "{input:?}");
        }
    }

    #[test]
    fn api_key_does_not_leak_through_debug() {
        let raw = key_of(60);
        let key = ApiKey::parse(&raw).unwrap();
        let printed = format!("{key:?}");
        assert!(!printed.contains(&raw[KEY_PREFIX.len()..]));
        assert_eq!(key.hint(), "aaaa");
    }

    #[test]
    fn models() {
        assert_eq!(parse_model("claude-opus-5-5"), Some("claude-opus-5-5"));
        for bad in [
            "",
            "claude-opus-5-5 ",
            "CLAUDE-OPUS-5-5",
            "claude-opus-5-5-20260401",
            "gpt-5",
            "claude-opus-5-5\0",
        ] {
            assert_eq!(parse_model(bad), None, "{bad:?}");
        }
        assert_eq!(model_from_storage(None), MODELS[0]);
        assert_eq!(model_from_storage(Some("evil")), MODELS[0]);
        assert_eq!(
            model_from_storage(Some("claude-haiku-5-5")),
            "claude-haiku-5-5"
        );
    }

    #[test]
    fn max_tokens() {
        assert_eq!(parse_max_tokens("4096"), Ok(4096));
        assert_eq!(parse_max_tokens(" 256 "), Ok(256));
        assert_eq!(parse_max_tokens("8192"), Ok(8_192));
        assert_eq!(parse_max_tokens("255"), Err(MaxTokensError::OutOfRange));
        assert_eq!(parse_max_tokens("8193"), Err(MaxTokensError::OutOfRange));
        for bad in ["", "-1", "1e4", "4096.5", "0x100", "99999999999"] {
            assert_eq!(
                parse_max_tokens(bad),
                Err(MaxTokensError::NotANumber),
                "{bad:?}"
            );
        }

        assert_eq!(max_tokens_from_storage(Some(1024.0)), 1024);
        for bad in [
            None,
            Some(f64::NAN),
            Some(f64::INFINITY),
            Some(-1.0),
            Some(100.5),
            Some(1e9),
        ] {
            assert_eq!(max_tokens_from_storage(bad), MAX_TOKENS_DEFAULT, "{bad:?}");
        }
    }
}
