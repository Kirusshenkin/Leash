//! Протоколы сообщений background: с панелью, с окном подтверждения и с
//! мостом (native messaging).
//!
//! Каждое сообщение проверяется строго: точный набор ключей, известный тип,
//! типы и длины полей. Невалидное отклоняется, а не «чинится».

use wasm_bindgen::JsValue;

use crate::ext;
use crate::tools;
use crate::value::Value;

/// Имена портов. Background принимает только их, и только от своих страниц.
pub(crate) const SIDEBAR_PORT: &str = "leash-sidebar";
pub(crate) const CONFIRM_PORT: &str = "leash-confirm";

/// Предел текста события и вопроса, в символах.
pub(crate) const MAX_EVENT_TEXT_CHARS: usize = 20_000;

/// Предел числовых идентификаторов: целые, точно представимые в f64.
const MAX_ID: u64 = 1 << 52;

/// Команда панели.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    /// Остановить: текущее действие прерывается, новые вызовы отклоняются.
    Stop,
    /// Снова принимать вызовы.
    Resume,
    /// Подключиться к мосту заново.
    Connect,
    /// Забыть сеансы: прочитанные сайты и признаки инъекций.
    Reset,
}

/// Событие для панели.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    Status {
        connected: bool,
        paused: bool,
        text: String,
    },
    /// Что делает Claude.
    Step(String),
    Notice(String),
    Error(String),
}

/// Сообщение моста.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Native {
    Call {
        id: u64,
        session: u64,
        tool: String,
        input: Value,
    },
    /// MCP-процесс сеанса завершился.
    End { session: u64 },
    /// Мост запущен и готов.
    Hello { version: String },
}

fn kind(v: &Value) -> Option<&str> {
    v.get("type").and_then(Value::as_str)
}

fn id_of(v: &Value, key: &str) -> Option<u64> {
    v.get(key)?.as_uint(MAX_ID)
}

fn text_of(v: &Value) -> Option<String> {
    let t = v.get("text")?.as_str()?;
    (t.chars().count() <= MAX_EVENT_TEXT_CHARS).then(|| t.to_owned())
}

pub(crate) fn parse_command(v: &Value) -> Option<Command> {
    if !v.has_exact_keys(&["type"]) {
        return None;
    }
    match kind(v)? {
        "stop" => Some(Command::Stop),
        "resume" => Some(Command::Resume),
        "connect" => Some(Command::Connect),
        "reset" => Some(Command::Reset),
        _ => None,
    }
}

pub(crate) fn command_value(cmd: Command) -> Value {
    let kind = match cmd {
        Command::Stop => "stop",
        Command::Resume => "resume",
        Command::Connect => "connect",
        Command::Reset => "reset",
    };
    Value::obj(vec![("type", Value::str(kind))])
}

pub(crate) fn parse_event(v: &Value) -> Option<Event> {
    match kind(v)? {
        "status" => {
            if !v.has_exact_keys(&["type", "connected", "paused", "text"]) {
                return None;
            }
            Some(Event::Status {
                connected: v.get("connected")?.as_bool()?,
                paused: v.get("paused")?.as_bool()?,
                text: text_of(v)?,
            })
        }
        k @ ("step" | "notice" | "error") => {
            if !v.has_exact_keys(&["type", "text"]) {
                return None;
            }
            let text = text_of(v)?;
            Some(match k {
                "step" => Event::Step(text),
                "notice" => Event::Notice(text),
                _ => Event::Error(text),
            })
        }
        _ => None,
    }
}

pub(crate) fn event_value(event: &Event) -> Value {
    let text = |kind: &str, text: &str| {
        Value::obj(vec![("type", Value::str(kind)), ("text", Value::str(text))])
    };
    match event {
        Event::Status {
            connected,
            paused,
            text,
        } => Value::obj(vec![
            ("type", Value::str("status")),
            ("connected", Value::Bool(*connected)),
            ("paused", Value::Bool(*paused)),
            ("text", Value::str(text)),
        ]),
        Event::Step(t) => text("step", t),
        Event::Notice(t) => text("notice", t),
        Event::Error(t) => text("error", t),
    }
}

/// Вопрос в окно подтверждения.
pub(crate) fn show_value(text: &str) -> Value {
    Value::obj(vec![
        ("type", Value::str("show")),
        ("text", Value::str(text)),
    ])
}

pub(crate) fn parse_show(v: &Value) -> Option<String> {
    (v.has_exact_keys(&["type", "text"]) && kind(v) == Some("show"))
        .then(|| text_of(v))
        .flatten()
}

/// Ответ окна подтверждения.
pub(crate) fn answer_value(allow: bool) -> Value {
    Value::obj(vec![
        ("type", Value::str("answer")),
        ("allow", Value::Bool(allow)),
    ])
}

pub(crate) fn parse_answer(v: &Value) -> Option<bool> {
    if !v.has_exact_keys(&["type", "allow"]) || kind(v) != Some("answer") {
        return None;
    }
    v.get("allow")?.as_bool()
}

pub(crate) fn parse_native(v: &Value) -> Option<Native> {
    match kind(v)? {
        "call" => {
            if !v.has_exact_keys(&["type", "id", "session", "tool", "input"]) {
                return None;
            }
            let tool = v.get("tool")?.as_str()?;
            if !tools::definitions().iter().any(|t| t.name == tool) {
                return None;
            }
            let input = v.get("input")?;
            if !matches!(input, Value::Obj(_)) {
                return None;
            }
            Some(Native::Call {
                id: id_of(v, "id")?,
                session: id_of(v, "session")?,
                tool: tool.to_owned(),
                input: input.clone(),
            })
        }
        "hello" => {
            if !v.has_exact_keys(&["type", "version"]) {
                return None;
            }
            let version = v.get("version")?.as_str()?;
            (version.len() <= 32
                && version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
            .then(|| Native::Hello {
                version: version.to_owned(),
            })
        }
        "end" => {
            if !v.has_exact_keys(&["type", "session"]) {
                return None;
            }
            Some(Native::End {
                session: id_of(v, "session")?,
            })
        }
        _ => None,
    }
}

pub(crate) fn native_reply(id: u64, text: &str, is_error: bool) -> Value {
    Value::obj(vec![
        // MAX_ID гарантирует точное представление в f64.
        ("id", Value::Num(id as f64)),
        ("text", Value::str(text)),
        ("isError", Value::Bool(is_error)),
    ])
}

/// Отправитель порта, как его описал браузер.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct SenderInfo {
    pub id: Option<String>,
    pub url: Option<String>,
    pub has_tab: bool,
}

/// Порт панели: наш ID расширения, точный URL панели, не из вкладки.
pub(crate) fn is_sidebar_sender(
    port_name: &str,
    sender: &SenderInfo,
    own_id: &str,
    sidebar_url: &str,
) -> bool {
    !own_id.is_empty()
        && !sidebar_url.is_empty()
        && port_name == SIDEBAR_PORT
        && sender.id.as_deref() == Some(own_id)
        && sender.url.as_deref() == Some(sidebar_url)
        && !sender.has_tab
}

/// Порт окна подтверждения: наш ID, URL окна с номером вопроса после `#`,
/// открыт во вкладке (окно — popup). Возвращает номер вопроса.
pub(crate) fn confirm_sender(
    port_name: &str,
    sender: &SenderInfo,
    own_id: &str,
    confirm_url: &str,
) -> Option<u64> {
    if own_id.is_empty()
        || confirm_url.is_empty()
        || port_name != CONFIRM_PORT
        || sender.id.as_deref() != Some(own_id)
        || !sender.has_tab
    {
        return None;
    }
    let digits = sender
        .url
        .as_deref()?
        .strip_prefix(confirm_url)?
        .strip_prefix('#')?;
    if digits.is_empty() || digits.len() > 15 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

pub(crate) fn sender_from_js(sender: &JsValue) -> SenderInfo {
    SenderInfo {
        id: ext::get(sender, "id").and_then(|v| v.as_string()),
        url: ext::get(sender, "url").and_then(|v| v.as_string()),
        has_tab: ext::get(sender, "tab").is_some(),
    }
}

/// Значение в объект JS для `postMessage`.
pub(crate) fn to_js(v: &Value) -> JsValue {
    js_sys::JSON::parse(&v.to_json()).unwrap_or(JsValue::NULL)
}

/// Текст для показа: управляющие символы направления (BiDi) заменяются на
/// видимый U+FFFD, чтобы текст не мог визуально переставить сам себя.
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
    use leash_core::json::parse_json;

    fn v(text: &str) -> Value {
        parse_json(text).unwrap()
    }

    #[test]
    fn commands_roundtrip_and_reject_extras() {
        for cmd in [
            Command::Stop,
            Command::Resume,
            Command::Connect,
            Command::Reset,
        ] {
            assert_eq!(parse_command(&command_value(cmd)), Some(cmd));
        }
        for bad in [
            r#"{"type":"stop","x":1}"#,
            r#"{"type":"chat"}"#,
            r#"{"type":1}"#,
            r#"[]"#,
            r#"{}"#,
        ] {
            assert_eq!(parse_command(&v(bad)), None, "{bad}");
        }
    }

    #[test]
    fn events_roundtrip() {
        let events = [
            Event::Status {
                connected: true,
                paused: false,
                text: "Мост подключён".into(),
            },
            Event::Step("читаю страницу".into()),
            Event::Notice("n".into()),
            Event::Error("e".into()),
        ];
        for e in events {
            assert_eq!(parse_event(&event_value(&e)), Some(e));
        }
        let long = "x".repeat(MAX_EVENT_TEXT_CHARS + 1);
        assert_eq!(parse_event(&event_value(&Event::Step(long))), None);
        assert_eq!(parse_event(&v(r#"{"type":"step","text":"a","x":1}"#)), None);
        assert_eq!(
            parse_event(&v(
                r#"{"type":"status","connected":1,"paused":false,"text":""}"#
            )),
            None
        );
    }

    #[test]
    fn confirm_messages() {
        assert_eq!(
            parse_show(&show_value("Разрешить?")),
            Some("Разрешить?".into())
        );
        assert_eq!(parse_answer(&answer_value(true)), Some(true));
        assert_eq!(parse_answer(&answer_value(false)), Some(false));
        assert_eq!(parse_answer(&v(r#"{"type":"answer","allow":"yes"}"#)), None);
        assert_eq!(
            parse_answer(&v(r#"{"type":"answer","allow":true,"id":1}"#)),
            None
        );
        assert_eq!(parse_show(&v(r#"{"type":"answer","text":"x"}"#)), None);
    }

    #[test]
    fn native_messages() {
        assert_eq!(
            parse_native(&v(
                r#"{"type":"call","id":7,"session":2,"tool":"click","input":{"element":1}}"#
            )),
            Some(Native::Call {
                id: 7,
                session: 2,
                tool: "click".into(),
                input: v(r#"{"element":1}"#),
            })
        );
        assert_eq!(
            parse_native(&v(r#"{"type":"hello","version":"0.1.0"}"#)),
            Some(Native::Hello {
                version: "0.1.0".into()
            })
        );
        assert_eq!(
            parse_native(&v(r#"{"type":"hello","version":"<b>"}"#)),
            None
        );
        assert_eq!(
            parse_native(&v(r#"{"type":"end","session":2}"#)),
            Some(Native::End { session: 2 })
        );
        for bad in [
            r#"{"type":"call","id":7,"session":2,"tool":"eval","input":{}}"#,
            r#"{"type":"call","id":7,"session":2,"tool":"click","input":[]}"#,
            r#"{"type":"call","id":-1,"session":2,"tool":"click","input":{}}"#,
            r#"{"type":"call","id":1.5,"session":2,"tool":"click","input":{}}"#,
            r#"{"type":"call","id":7,"tool":"click","input":{}}"#,
            r#"{"type":"end","session":2,"x":0}"#,
            r#"{"type":"exec"}"#,
        ] {
            assert_eq!(parse_native(&v(bad)), None, "{bad}");
        }
        assert_eq!(
            native_reply(3, "ok", false).to_json(),
            r#"{"id":3,"text":"ok","isError":false}"#
        );
    }

    #[test]
    fn senders() {
        let own = "leash@kirusshenkin.github.io";
        let sidebar = "moz-extension://u/sidebar/sidebar.html";
        let confirm = "moz-extension://u/confirm/confirm.html";
        let s = |url: &str, tab: bool| SenderInfo {
            id: Some(own.into()),
            url: Some(url.into()),
            has_tab: tab,
        };
        assert!(is_sidebar_sender(
            SIDEBAR_PORT,
            &s(sidebar, false),
            own,
            sidebar
        ));
        assert!(!is_sidebar_sender(
            SIDEBAR_PORT,
            &s(sidebar, true),
            own,
            sidebar
        ));
        assert!(!is_sidebar_sender(
            CONFIRM_PORT,
            &s(sidebar, false),
            own,
            sidebar
        ));

        let url = format!("{confirm}#42");
        assert_eq!(
            confirm_sender(CONFIRM_PORT, &s(&url, true), own, confirm),
            Some(42)
        );
        for bad in [
            format!("{confirm}#"),
            format!("{confirm}#4a"),
            format!("{confirm}?x#4"),
            format!("{confirm}#{}", "9".repeat(16)),
            confirm.to_owned(),
            format!("{sidebar}#4"),
        ] {
            assert_eq!(
                confirm_sender(CONFIRM_PORT, &s(&bad, true), own, confirm),
                None,
                "{bad}"
            );
        }
        assert_eq!(
            confirm_sender(CONFIRM_PORT, &s(&url, false), own, confirm),
            None
        );
        assert_eq!(
            confirm_sender(SIDEBAR_PORT, &s(&url, true), own, confirm),
            None
        );
        let mut other = s(&url, true);
        other.id = Some("evil@example".into());
        assert_eq!(confirm_sender(CONFIRM_PORT, &other, own, confirm), None);
    }

    #[test]
    fn bidi_is_neutralised() {
        assert_eq!(display_text("a\u{202E}b\u{2066}c"), "a\u{FFFD}b\u{FFFD}c");
    }
}
