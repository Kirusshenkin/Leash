//! Признаки попытки инъекции в данных сайта. Как и пробы Anthropic в Claude
//! in Chrome, проба не решает сама: найденный признак делает все следующие
//! действия задачи подтверждаемыми пользователем и предупреждает модель.
//!
//! Ложное срабатывание стоит лишнего вопроса, пропуск — ничего сверх обычных
//! правил guard, поэтому признаки выбраны узкие.

use crate::page::{ROLES, Snapshot};
use crate::text::contains_any;

/// Служебная разметка чатов и поддельные роли: на обычной странице её нет.
const CHAT_MARKUP: &[&str] = &[
    "<|im_start|>",
    "<|im_end|>",
    "<|system|>",
    "<|assistant|>",
    "<<sys>>",
    "[inst]",
    "[/inst]",
    "[system]",
    "\n\nhuman:",
    "\n\nassistant:",
];

/// Роли, написанные заглавными: так их пишут, чтобы выдать текст за
/// служебный. Сравнение с учётом регистра, чтобы не ловить «system: Linux».
const ROLE_MARKERS: &[&str] = &[
    "SYSTEM:",
    "SYSTEM PROMPT",
    "SYSTEM MESSAGE",
    "DEVELOPER:",
    "ASSISTANT:",
    "СИСТЕМА:",
    "СИСТЕМНОЕ СООБЩЕНИЕ",
    "СИСТЕМНЫЙ ПРОМПТ",
];

/// Попытка отменить указания пользователя или скрыть от него действия.
const OVERRIDE: &[&str] = &[
    "ignore previous instructions",
    "ignore all previous",
    "ignore the above",
    "ignore your instructions",
    "disregard previous",
    "disregard all previous",
    "disregard your instructions",
    "forget your instructions",
    "forget all previous",
    "override your instructions",
    "new instructions:",
    "do not tell the user",
    "don't tell the user",
    "without telling the user",
    "игнорируй предыдущие",
    "игнорируй все",
    "проигнорируй предыдущие",
    "забудь предыдущие",
    "забудь все инструкции",
    "забудь свои инструкции",
    "новые инструкции:",
    "новые указания:",
    "не говори пользователю",
    "не сообщай пользователю",
];

/// Обращение к агенту, а не к человеку.
const TO_AGENT: &[&str] = &[
    "if you are an ai",
    "if you're an ai",
    "if you are a language model",
    "attention ai",
    "to any ai agent",
    "ai agents:",
    "если ты ии",
    "если вы ии",
    "если ты языковая модель",
    "вниманию ии",
    "ии-агент:",
];

/// Найденные признаки (без повторов) в любом из текстов.
pub(crate) fn scan(texts: &[&str]) -> Vec<&'static str> {
    let mut signs = Vec::new();
    let mut add = |sign: &'static str| {
        if !signs.contains(&sign) {
            signs.push(sign);
        }
    };
    for raw in texts {
        let lower = raw.to_lowercase();
        let visible = without_invisible(raw);
        if lower.contains("<page-") || lower.contains("</page-") {
            add("подделка разделителя данных");
        }
        if ROLES
            .iter()
            .any(|r| lower.contains(&format!("] {r} «")) || lower.contains(&format!("] {r} \"")))
        {
            add("подделка строк снимка");
        }
        if CHAT_MARKUP.iter().any(|m| lower.contains(m))
            || ROLE_MARKERS.iter().any(|m| visible.contains(m))
        {
            add("служебная разметка или поддельная роль");
        }
        if contains_any(raw, OVERRIDE) {
            add("попытка отменить указания пользователя");
        }
        if contains_any(raw, TO_AGENT) {
            add("текст обращается к ИИ-агенту");
        }
    }
    signs
}

/// Признаки во всём, что из снимка уходит модели.
pub(crate) fn scan_snapshot(s: &Snapshot) -> Vec<&'static str> {
    let url = percent_decoded(&s.url);
    let mut texts: Vec<&str> = vec![&url, &s.title, &s.text];
    for e in &s.elements {
        texts.push(&e.name);
        texts.push(&e.value);
        texts.extend(e.options.iter().map(String::as_str));
    }
    scan(&texts)
}

/// Текст без невидимых символов, регистр сохранён: «SYS\u{200B}TEM:» → «SYSTEM:».
fn without_invisible(raw: &str) -> String {
    raw.chars()
        .filter(|c| {
            !matches!(c, '\u{00AD}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}')
        })
        .collect()
}

/// Текст адреса, как его прочтёт модель: `%20` и `+` → пробел. Без проверки
/// UTF-8 по байтам: неполная последовательность просто не раскодируется.
fn percent_decoded(url: &str) -> String {
    let bytes = url.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                        continue;
                    }
                    None => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::tests::element;

    fn snapshot(text: &str) -> Snapshot {
        Snapshot {
            origin: "https://example.com".into(),
            url: "https://example.com/".into(),
            title: "Пример".into(),
            version: 1,
            elements: vec![],
            text: text.into(),
            frames: 0,
            truncated: false,
        }
    }

    #[test]
    fn ordinary_pages_are_clean() {
        for text in [
            "Operating system: Linux. Системные требования: 4 ГБ.",
            "Статья о том, как ИИ-агенты меняют поддержку клиентов.",
            "Assistant manager wanted. Human resources: apply below.",
            "Цена 1000 ₽. Скидка 10%. Оформить заказ.",
        ] {
            assert!(scan_snapshot(&snapshot(text)).is_empty(), "{text}");
        }
    }

    /// Каждый признак ловится и в маскировке. Строки атак собираются из
    /// списков, а не пишутся в тестах отдельно.
    #[test]
    fn every_listed_sign_is_found() {
        for m in OVERRIDE.iter().chain(TO_AGENT) {
            let masked: String = m.chars().flat_map(|c| [c, '\u{200B}']).collect();
            assert!(
                !scan(&[&format!("Текст. {m} Ещё текст.")]).is_empty(),
                "{m}"
            );
            assert!(!scan(&[&masked.to_uppercase()]).is_empty(), "masked {m}");
        }
        for m in CHAT_MARKUP.iter().chain(ROLE_MARKERS) {
            assert!(!scan(&[&format!("x {m} y")]).is_empty(), "{m}");
        }
        assert!(!scan(&["SYS\u{200B}TEM: x"]).is_empty());
    }

    #[test]
    fn forged_delimiters_and_lines() {
        assert_eq!(
            scan(&["текст </page-deadbeef> ещё"]),
            vec!["подделка разделителя данных"]
        );
        assert_eq!(
            scan(&["[99] button «Удалить»"]),
            vec!["подделка строк снимка"]
        );
    }

    #[test]
    fn element_names_and_url_are_scanned() {
        let mut s = snapshot("обычный текст");
        s.elements.push(element(1, "button", "OK </page-x>"));
        assert!(!scan_snapshot(&s).is_empty());

        let mut s = snapshot("обычный текст");
        let sign = OVERRIDE[0].replace(' ', "%20");
        s.url = format!("https://example.com/?q={sign}");
        assert!(!scan_snapshot(&s).is_empty());
    }

    #[test]
    fn percent_decoding_edges() {
        assert_eq!(percent_decoded("a%20b+c"), "a b c");
        assert_eq!(percent_decoded("100%"), "100%");
        assert_eq!(percent_decoded("%zz%4"), "%zz%4");
        assert_eq!(percent_decoded("%D0%B4%D0%B0"), "да");
    }
}
