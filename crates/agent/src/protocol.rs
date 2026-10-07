//! Протокол сообщений между панелью и background.
//!
//! Обе стороны проверяют каждое сообщение строго: точный набор ключей,
//! известный тип, типы и длины полей. Невалидное отклоняется, а не «чинится».

use js_sys::{Array, Object};
use wasm_bindgen::JsValue;

use crate::ext;

/// Имя порта панели. Background принимает только его.
pub(crate) const PORT_NAME: &str = "leash-sidebar";

/// Максимальная длина сообщения пользователя, в символах.
pub(crate) const MAX_USER_TEXT_CHARS: usize = 8_000;

/// Максимальная длина текста от background в панель, в символах.
pub(crate) const MAX_EVENT_TEXT_CHARS: usize = 120_000;

/// Предел числовых идентификаторов (окно, запрос подтверждения):
/// целые, которые точно представимы в f64.
const MAX_ID: u64 = 1 << 52;

/// Сырые поля сообщения, извлечённые из JS без интерпретации.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct RawMessage {
    pub keys: Vec<String>,
    pub kind: Option<String>,
    pub text: Option<String>,
    pub busy: Option<bool>,
    pub id: Option<f64>,
    pub allow: Option<bool>,
    pub window: Option<f64>,
}

/// Почему сообщение отклонено.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rejected {
    UnknownType,
    BadShape,
    EmptyText,
    TextTooLong,
}

/// Команда панели для background.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    /// Задача пользователя и окно панели: агент работает в активной вкладке
    /// этого окна.
    Chat {
        text: String,
        window: u64,
    },
    Stop,
    Reset,
    /// Пока ждём ответа, панель шлёт ping: входящее сообщение сбрасывает
    /// idle-таймер event page, иначе Firefox выгрузит background посреди запроса.
    Ping,
    /// Ответ пользователя на запрос подтверждения.
    Confirm {
        id: u64,
        allow: bool,
    },
}

/// Событие background для панели.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    Ready,
    Busy(bool),
    Reply(String),
    Error(String),
    Notice(String),
    /// Шаг агента: что он делает.
    Step(String),
    /// Нужно согласие пользователя на действие.
    Confirm {
        id: u64,
        text: String,
    },
}

fn id_of(value: Option<f64>) -> Result<u64, Rejected> {
    match value {
        // Диапазон и целость проверены до приведения.
        Some(n) if n.fract() == 0.0 && n >= 0.0 && n <= MAX_ID as f64 => Ok(n as u64),
        _ => Err(Rejected::BadShape),
    }
}

fn bounded_text(raw: &RawMessage, max: usize) -> Result<&str, Rejected> {
    let text = raw.text.as_deref().ok_or(Rejected::BadShape)?;
    if text.chars().count() > max {
        return Err(Rejected::TextTooLong);
    }
    Ok(text)
}

pub(crate) fn parse_command(raw: &RawMessage) -> Result<Command, Rejected> {
    match raw.kind.as_deref() {
        Some("chat") => {
            exact_keys(raw, &["type", "text", "window"])?;
            let window = id_of(raw.window)?;
            let text = bounded_text(raw, MAX_USER_TEXT_CHARS)?.trim();
            if text.is_empty() {
                return Err(Rejected::EmptyText);
            }
            Ok(Command::Chat {
                text: text.to_owned(),
                window,
            })
        }
        Some("stop") => exact_keys(raw, &["type"]).map(|()| Command::Stop),
        Some("reset") => exact_keys(raw, &["type"]).map(|()| Command::Reset),
        Some("ping") => exact_keys(raw, &["type"]).map(|()| Command::Ping),
        Some("confirm") => {
            exact_keys(raw, &["type", "id", "allow"])?;
            Ok(Command::Confirm {
                id: id_of(raw.id)?,
                allow: raw.allow.ok_or(Rejected::BadShape)?,
            })
        }
        Some(_) => Err(Rejected::UnknownType),
        None => Err(Rejected::BadShape),
    }
}

pub(crate) fn parse_event(raw: &RawMessage) -> Result<Event, Rejected> {
    let text = || -> Result<String, Rejected> {
        exact_keys(raw, &["type", "text"])?;
        bounded_text(raw, MAX_EVENT_TEXT_CHARS).map(str::to_owned)
    };
    match raw.kind.as_deref() {
        Some("ready") => exact_keys(raw, &["type"]).map(|()| Event::Ready),
        Some("busy") => {
            exact_keys(raw, &["type", "busy"])?;
            raw.busy.map(Event::Busy).ok_or(Rejected::BadShape)
        }
        Some("reply") => text().map(Event::Reply),
        Some("error") => text().map(Event::Error),
        Some("notice") => text().map(Event::Notice),
        Some("step") => text().map(Event::Step),
        Some("confirm") => {
            exact_keys(raw, &["type", "id", "text"])?;
            Ok(Event::Confirm {
                id: id_of(raw.id)?,
                text: bounded_text(raw, MAX_EVENT_TEXT_CHARS)?.to_owned(),
            })
        }
        Some(_) => Err(Rejected::UnknownType),
        None => Err(Rejected::BadShape),
    }
}

/// Ключи сообщения должны совпадать с ожидаемыми в точности.
fn exact_keys(raw: &RawMessage, expected: &[&str]) -> Result<(), Rejected> {
    let same = raw.keys.len() == expected.len()
        && expected.iter().all(|e| raw.keys.iter().any(|k| k == e));
    if same {
        Ok(())
    } else {
        Err(Rejected::BadShape)
    }
}

/// Отправитель порта, как его описал браузер.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct SenderInfo {
    pub id: Option<String>,
    pub url: Option<String>,
    pub has_tab: bool,
}

/// Порт принимается, только если его открыла наша панель: наш ID
/// расширения, точный URL панели, не из вкладки (не content-скрипт).
pub(crate) fn is_sidebar_sender(
    port_name: &str,
    sender: &SenderInfo,
    own_id: &str,
    sidebar_url: &str,
) -> bool {
    !own_id.is_empty()
        && !sidebar_url.is_empty()
        && port_name == PORT_NAME
        && sender.id.as_deref() == Some(own_id)
        && sender.url.as_deref() == Some(sidebar_url)
        && !sender.has_tab
}

// --- Мост к JS ---

pub(crate) fn raw_from_js(value: &JsValue) -> Option<RawMessage> {
    if !value.is_object() || Array::is_array(value) {
        return None;
    }
    let keys = Object::keys(&Object::from(value.clone()))
        .iter()
        .map(|k| k.as_string())
        .collect::<Option<Vec<_>>>()?;
    Some(RawMessage {
        keys,
        kind: ext::get(value, "type").and_then(|v| v.as_string()),
        text: ext::get(value, "text").and_then(|v| v.as_string()),
        busy: ext::get(value, "busy").and_then(|v| v.as_bool()),
        id: ext::get(value, "id").and_then(|v| v.as_f64()),
        allow: ext::get(value, "allow").and_then(|v| v.as_bool()),
        window: ext::get(value, "window").and_then(|v| v.as_f64()),
    })
}

pub(crate) fn sender_from_js(sender: &JsValue) -> SenderInfo {
    SenderInfo {
        id: ext::get(sender, "id").and_then(|v| v.as_string()),
        url: ext::get(sender, "url").and_then(|v| v.as_string()),
        has_tab: ext::get(sender, "tab").is_some(),
    }
}

fn message(kind: &str) -> Object {
    let obj = Object::new();
    ext::set(&obj, "type", &JsValue::from_str(kind));
    obj
}

pub(crate) fn command_to_js(cmd: &Command) -> JsValue {
    match cmd {
        Command::Chat { text, window } => {
            let obj = message("chat");
            ext::set(&obj, "text", &JsValue::from_str(text));
            // MAX_ID гарантирует точное представление в f64.
            ext::set(&obj, "window", &JsValue::from_f64(*window as f64));
            obj.into()
        }
        Command::Stop => message("stop").into(),
        Command::Ping => message("ping").into(),
        Command::Reset => message("reset").into(),
        Command::Confirm { id, allow } => {
            let obj = message("confirm");
            ext::set(&obj, "id", &JsValue::from_f64(*id as f64));
            ext::set(&obj, "allow", &JsValue::from_bool(*allow));
            obj.into()
        }
    }
}

pub(crate) fn event_to_js(event: &Event) -> JsValue {
    let with_text = |kind: &str, text: &str| {
        let obj = message(kind);
        ext::set(&obj, "text", &JsValue::from_str(text));
        obj
    };
    match event {
        Event::Ready => message("ready").into(),
        Event::Busy(busy) => {
            let obj = message("busy");
            ext::set(&obj, "busy", &JsValue::from_bool(*busy));
            obj.into()
        }
        Event::Reply(text) => with_text("reply", text).into(),
        Event::Error(text) => with_text("error", text).into(),
        Event::Notice(text) => with_text("notice", text).into(),
        Event::Step(text) => with_text("step", text).into(),
        Event::Confirm { id, text } => {
            let obj = with_text("confirm", text);
            ext::set(&obj, "id", &JsValue::from_f64(*id as f64));
            obj.into()
        }
    }
}

/// Текст для показа: управляющие символы направления (BiDi) заменяются на
/// видимый U+FFFD, чтобы ответ не мог визуально переставить текст.
pub(crate) fn display_text(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}' => '\u{FFFD}',
            c => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(
        keys: &[&str],
        kind: Option<&str>,
        text: Option<&str>,
        busy: Option<bool>,
    ) -> RawMessage {
        RawMessage {
            keys: keys.iter().map(|k| (*k).to_owned()).collect(),
            kind: kind.map(str::to_owned),
            text: text.map(str::to_owned),
            busy,
            ..RawMessage::default()
        }
    }

    fn chat(text: &str, window: Option<f64>) -> RawMessage {
        RawMessage {
            window,
            ..raw(&["type", "text", "window"], Some("chat"), Some(text), None)
        }
    }

    #[test]
    fn commands() {
        let cases: &[(RawMessage, Result<Command, Rejected>)] = &[
            (
                chat("привет", Some(3.0)),
                Ok(Command::Chat {
                    text: "привет".into(),
                    window: 3,
                }),
            ),
            (
                chat("  x \n", Some(0.0)),
                Ok(Command::Chat {
                    text: "x".into(),
                    window: 0,
                }),
            ),
            (raw(&["type"], Some("stop"), None, None), Ok(Command::Stop)),
            (raw(&["type"], Some("ping"), None, None), Ok(Command::Ping)),
            (
                raw(&["type"], Some("reset"), None, None),
                Ok(Command::Reset),
            ),
            (
                RawMessage {
                    id: Some(7.0),
                    allow: Some(true),
                    ..raw(&["type", "id", "allow"], Some("confirm"), None, None)
                },
                Ok(Command::Confirm { id: 7, allow: true }),
            ),
            // окно обязательно и целое
            (chat("x", None), Err(Rejected::BadShape)),
            (chat("x", Some(1.5)), Err(Rejected::BadShape)),
            (chat("x", Some(-1.0)), Err(Rejected::BadShape)),
            (chat("x", Some(f64::NAN)), Err(Rejected::BadShape)),
            // подтверждение без ответа или с дробным номером
            (
                RawMessage {
                    id: Some(7.0),
                    ..raw(&["type", "id", "allow"], Some("confirm"), None, None)
                },
                Err(Rejected::BadShape),
            ),
            (
                RawMessage {
                    id: Some(7.5),
                    allow: Some(true),
                    ..raw(&["type", "id", "allow"], Some("confirm"), None, None)
                },
                Err(Rejected::BadShape),
            ),
            // лишний ключ
            (
                RawMessage {
                    window: Some(1.0),
                    ..raw(
                        &["type", "text", "window", "model"],
                        Some("chat"),
                        Some("x"),
                        None,
                    )
                },
                Err(Rejected::BadShape),
            ),
            (
                raw(&["type", "text"], Some("stop"), Some("x"), None),
                Err(Rejected::BadShape),
            ),
            (raw(&[], None, None, None), Err(Rejected::BadShape)),
            // неизвестные команды, включая попытки менять настройки
            (
                raw(&["type"], Some("set_settings"), None, None),
                Err(Rejected::UnknownType),
            ),
            (
                raw(&["type"], Some("Chat"), None, None),
                Err(Rejected::UnknownType),
            ),
            (chat(" \n\t ", Some(1.0)), Err(Rejected::EmptyText)),
        ];
        for (input, expected) in cases {
            assert_eq!(&parse_command(input), expected, "{input:?}");
        }
    }

    #[test]
    fn chat_length_limit_in_chars_not_bytes() {
        let ok = "я".repeat(MAX_USER_TEXT_CHARS);
        let long = "я".repeat(MAX_USER_TEXT_CHARS + 1);
        assert!(parse_command(&chat(&ok, Some(1.0))).is_ok());
        assert_eq!(
            parse_command(&chat(&long, Some(1.0))),
            Err(Rejected::TextTooLong)
        );
    }

    #[test]
    fn events() {
        let cases: &[(RawMessage, Result<Event, Rejected>)] = &[
            (raw(&["type"], Some("ready"), None, None), Ok(Event::Ready)),
            (
                raw(&["type", "busy"], Some("busy"), None, Some(true)),
                Ok(Event::Busy(true)),
            ),
            (
                raw(&["type", "text"], Some("reply"), Some("a"), None),
                Ok(Event::Reply("a".into())),
            ),
            (
                raw(&["type", "text"], Some("error"), Some("e"), None),
                Ok(Event::Error("e".into())),
            ),
            (
                raw(&["type", "text"], Some("notice"), Some("n"), None),
                Ok(Event::Notice("n".into())),
            ),
            (
                raw(&["type", "text"], Some("step"), Some("s"), None),
                Ok(Event::Step("s".into())),
            ),
            (
                RawMessage {
                    id: Some(2.0),
                    ..raw(&["type", "id", "text"], Some("confirm"), Some("c"), None)
                },
                Ok(Event::Confirm {
                    id: 2,
                    text: "c".into(),
                }),
            ),
            (
                raw(&["type", "text"], Some("confirm"), Some("c"), None),
                Err(Rejected::BadShape),
            ),
            (
                raw(&["type", "busy"], Some("busy"), None, None),
                Err(Rejected::BadShape),
            ),
            (
                raw(&["type", "text", "html"], Some("reply"), Some("a"), None),
                Err(Rejected::BadShape),
            ),
            (
                raw(&["type"], Some("html"), None, None),
                Err(Rejected::UnknownType),
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(&parse_event(input), expected, "{input:?}");
        }
    }

    #[test]
    fn bidi_controls_are_neutralised() {
        assert_eq!(display_text("a\u{202E}b\u{2066}c"), "a\u{FFFD}b\u{FFFD}c");
        assert_eq!(display_text("обычный текст\n"), "обычный текст\n");
    }

    #[test]
    fn sender_check() {
        let id = "leash@localhost";
        let url = "moz-extension://uuid/sidebar/sidebar.html";
        let good = SenderInfo {
            id: Some(id.into()),
            url: Some(url.into()),
            has_tab: false,
        };
        assert!(is_sidebar_sender(PORT_NAME, &good, id, url));

        let cases = [
            // content-скрипт во вкладке
            (
                PORT_NAME,
                SenderInfo {
                    has_tab: true,
                    ..good.clone()
                },
            ),
            (
                PORT_NAME,
                SenderInfo {
                    id: Some("other@ext".into()),
                    ..good.clone()
                },
            ),
            (
                PORT_NAME,
                SenderInfo {
                    id: None,
                    ..good.clone()
                },
            ),
            (
                PORT_NAME,
                SenderInfo {
                    url: Some("moz-extension://uuid/options/options.html".into()),
                    ..good.clone()
                },
            ),
            (
                PORT_NAME,
                SenderInfo {
                    url: Some(format!("{url}?x")),
                    ..good.clone()
                },
            ),
            (
                PORT_NAME,
                SenderInfo {
                    url: Some("https://evil.example/sidebar/sidebar.html".into()),
                    ..good.clone()
                },
            ),
            (
                PORT_NAME,
                SenderInfo {
                    url: None,
                    ..good.clone()
                },
            ),
            ("other-port", good.clone()),
        ];
        for (name, sender) in &cases {
            assert!(
                !is_sidebar_sender(name, sender, id, url),
                "{name} {sender:?}"
            );
        }
        // пустые эталоны никогда не совпадают
        let empty = SenderInfo {
            id: Some(String::new()),
            url: Some(String::new()),
            has_tab: false,
        };
        assert!(!is_sidebar_sender(PORT_NAME, &empty, "", ""));
    }

    // ID граница: 2^52 (MAX_ID) точна в f64, 2^52+1 нет.
    #[test]
    fn id_boundaries() {
        // 2^52 = 4503599627370496 точно представим в f64.
        assert_eq!(id_of(Some(4503599627370496.0)), Ok(4503599627370496));

        // 2^52 + 1 > MAX_ID, должен отклониться.
        assert_eq!(id_of(Some(4503599627370497.0)), Err(Rejected::BadShape));

        // Дробные отклоняются.
        assert_eq!(id_of(Some(3.5)), Err(Rejected::BadShape));

        // Отрицательные отклоняются.
        assert_eq!(id_of(Some(-1.0)), Err(Rejected::BadShape));

        // NaN отклоняется.
        assert_eq!(id_of(Some(f64::NAN)), Err(Rejected::BadShape));

        // Бесконечность отклоняется.
        assert_eq!(id_of(Some(f64::INFINITY)), Err(Rejected::BadShape));

        // -0.0 принимается как 0.
        assert_eq!(id_of(Some(-0.0)), Ok(0));

        // Отсутствующее значение отклоняется.
        assert_eq!(id_of(None), Err(Rejected::BadShape));
    }

    // Текст граница: chars count, not bytes; мультибайтовые и emoji.
    #[test]
    fn text_length_in_chars() {
        // Кириллица: по 2-4 байта, но 1 символ.
        let ok_cyrillic = "я".repeat(MAX_USER_TEXT_CHARS);
        assert!(bounded_text(&chat(&ok_cyrillic, Some(1.0)), MAX_USER_TEXT_CHARS).is_ok());

        let long_cyrillic = "я".repeat(MAX_USER_TEXT_CHARS + 1);
        assert_eq!(
            bounded_text(&chat(&long_cyrillic, Some(1.0)), MAX_USER_TEXT_CHARS),
            Err(Rejected::TextTooLong)
        );

        // Emoji: может быть 1 код, но несколько units; chars() считает коды.
        let emoji = "👨‍👩‍👧‍👦"; // ZWJ sequence, несколько кодов.
        let ok_emoji = format!(
            "{}{}",
            emoji,
            "a".repeat(MAX_USER_TEXT_CHARS - emoji.chars().count())
        );
        assert!(bounded_text(&chat(&ok_emoji, Some(1.0)), MAX_USER_TEXT_CHARS).is_ok());

        // Пустой текст после trim — EmptyText.
        assert_eq!(
            parse_command(&chat("  \n\t  ", Some(1.0))),
            Err(Rejected::EmptyText)
        );
    }

    // Все BiDi управляющие символы заменяются на U+FFFD.
    #[test]
    fn bidi_controls_comprehensive() {
        // LTR mark (U+200E).
        assert_eq!(display_text("a\u{200E}b"), "a\u{FFFD}b");

        // RTL mark (U+200F).
        assert_eq!(display_text("a\u{200F}b"), "a\u{FFFD}b");

        // LTR embedding (U+202A).
        assert_eq!(display_text("a\u{202A}b"), "a\u{FFFD}b");

        // RTL embedding (U+202B).
        assert_eq!(display_text("a\u{202B}b"), "a\u{FFFD}b");

        // Pop directional formatting (U+202C).
        assert_eq!(display_text("a\u{202C}b"), "a\u{FFFD}b");

        // LTR override (U+202D).
        assert_eq!(display_text("a\u{202D}b"), "a\u{FFFD}b");

        // RTL override (U+202E).
        assert_eq!(display_text("a\u{202E}b"), "a\u{FFFD}b");

        // LTR isolate (U+2066).
        assert_eq!(display_text("a\u{2066}b"), "a\u{FFFD}b");

        // RTL isolate (U+2067).
        assert_eq!(display_text("a\u{2067}b"), "a\u{FFFD}b");

        // First strong isolate (U+2068).
        assert_eq!(display_text("a\u{2068}b"), "a\u{FFFD}b");

        // Pop directional isolate (U+2069).
        assert_eq!(display_text("a\u{2069}b"), "a\u{FFFD}b");

        // Множественные управляющие.
        assert_eq!(
            display_text("start\u{202E}reversed\u{202C}normal"),
            "start\u{FFFD}reversed\u{FFFD}normal"
        );

        // Обычные символы не меняются (включая другие невидимые).
        assert_eq!(display_text("обычный текст"), "обычный текст");
        assert_eq!(display_text("text\nwith\nnewlines"), "text\nwith\nnewlines");
        assert_eq!(display_text("zero\u{200B}width"), "zero\u{200B}width"); // ZWS не в списке.
    }

    // Команды и события по отдельности; round-trip через JS невозможен без WASM.
    #[test]
    fn command_event_exhaustive() {
        // Chat со всеми вариантами.
        let tests: &[(RawMessage, Result<Command, Rejected>)] = &[
            (
                chat("hello", Some(0.0)),
                Ok(Command::Chat {
                    text: "hello".into(),
                    window: 0,
                }),
            ),
            (
                chat("hello", Some(MAX_ID as f64)),
                Ok(Command::Chat {
                    text: "hello".into(),
                    window: MAX_ID,
                }),
            ),
            // Окно требуется для Chat.
            (
                raw(&["type", "text"], Some("chat"), Some("x"), None),
                Err(Rejected::BadShape),
            ),
        ];
        for (input, expected) in tests {
            assert_eq!(&parse_command(input), expected, "command {input:?}");
        }

        // Все типы событий со строгой валидацией ключей.
        let event_tests: &[(RawMessage, Result<Event, Rejected>)] = &[
            (raw(&["type"], Some("ready"), None, None), Ok(Event::Ready)),
            (
                raw(&["type", "busy"], Some("busy"), None, Some(true)),
                Ok(Event::Busy(true)),
            ),
            (
                raw(&["type", "busy"], Some("busy"), None, Some(false)),
                Ok(Event::Busy(false)),
            ),
            // Busy требует ключ busy.
            (
                raw(&["type"], Some("busy"), None, None),
                Err(Rejected::BadShape),
            ),
        ];
        for (input, expected) in event_tests {
            assert_eq!(&parse_event(input), expected, "event {input:?}");
        }
    }

    // Лишние ключи отклоняются.
    #[test]
    fn exact_keys_validation() {
        // Лишний ключ: отклоняется.
        let extra = RawMessage {
            keys: vec!["type".into(), "text".into(), "extra".into()],
            kind: Some("stop".into()),
            ..RawMessage::default()
        };
        assert_eq!(parse_command(&extra), Err(Rejected::BadShape));

        // Недостающий ключ: отклоняется.
        let missing = RawMessage {
            keys: vec!["type".into()],
            kind: Some("chat".into()),
            text: Some("x".into()),
            window: Some(1.0),
            ..RawMessage::default()
        };
        assert_eq!(parse_command(&missing), Err(Rejected::BadShape));

        // Неправильный порядок ключей — не проверяется (JSON).
        // Дублирующиеся ключи в JSON — браузер не позволяет.
    }

    // Confirm и Event::Confirm строго требуют значения.
    #[test]
    fn confirm_edge_cases() {
        // Confirm требует id И allow.
        let only_id = RawMessage {
            keys: vec!["type".into(), "id".into()],
            kind: Some("confirm".into()),
            id: Some(1.0),
            ..RawMessage::default()
        };
        assert_eq!(parse_command(&only_id), Err(Rejected::BadShape));

        let only_allow = RawMessage {
            keys: vec!["type".into(), "allow".into()],
            kind: Some("confirm".into()),
            allow: Some(true),
            ..RawMessage::default()
        };
        assert_eq!(parse_command(&only_allow), Err(Rejected::BadShape));

        // Event::Confirm требует id И text.
        let event_missing_text = RawMessage {
            keys: vec!["type".into(), "id".into()],
            kind: Some("confirm".into()),
            id: Some(5.0),
            ..RawMessage::default()
        };
        assert_eq!(parse_event(&event_missing_text), Err(Rejected::BadShape));
    }
}
