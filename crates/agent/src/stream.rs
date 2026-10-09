//! Потоковый ответ Messages API (SSE).
//!
//! Байты потока собираются в то же JSON-сообщение, что приходит без
//! стриминга, и проверяются тем же `api::parse_response`: поток не добавляет
//! своих путей в историю диалога. Здесь только порядок событий, бюджет и
//! текст для показа по ходу ответа. Чистый код, тестируется без браузера.

use crate::api::{self, ApiError, ErrorKind, Reply};
use crate::value::{self, Value};

/// Предел всего потока в байтах.
const MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;
/// Предел одного события (строк `data:` до пустой строки).
const MAX_EVENT_BYTES: usize = 1024 * 1024;
/// Сколько блоков допускается в одном ответе.
const MAX_BLOCKS: usize = 64;

#[derive(Debug)]
enum Kind {
    Text(String),
    Tool {
        id: Value,
        name: Value,
        /// `input` из `content_block_start`, если дельт не было.
        start: Value,
        json: String,
    },
    /// Блок, который в диалог не возвращается (например, thinking).
    Other(Value),
}

#[derive(Debug)]
struct Block {
    kind: Kind,
    done: bool,
}

#[derive(Debug, Default)]
pub(crate) struct Stream {
    /// Байты, не сложившиеся в целый символ UTF-8.
    pending: Vec<u8>,
    /// Начало строки без конца строки.
    line: String,
    data: String,
    has_data: bool,
    bytes: usize,
    started: bool,
    stopped: bool,
    stop_reason: Option<Value>,
    usage: Vec<(String, Value)>,
    blocks: Vec<Block>,
}

impl Stream {
    /// Очередная порция байтов тела ответа.
    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Result<(), ApiError> {
        self.bytes += chunk.len();
        if self.bytes > MAX_STREAM_BYTES {
            return Err(ApiError::BadResponse);
        }
        self.pending.extend_from_slice(chunk);
        let valid = match std::str::from_utf8(&self.pending) {
            Ok(s) => s.len(),
            // Обрыв посреди символа — ждём продолжения; иное — мусор.
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            Err(_) => return Err(ApiError::BadResponse),
        };
        let rest = self.pending.split_off(valid);
        let text = String::from_utf8(std::mem::replace(&mut self.pending, rest))
            .map_err(|_| ApiError::BadResponse)?;
        self.lines(&text)
    }

    fn lines(&mut self, text: &str) -> Result<(), ApiError> {
        let mut rest = text;
        // `\r` в конце порции может оказаться началом `\r\n`.
        if self.line.ends_with('\r') {
            self.line.pop();
            let line = std::mem::take(&mut self.line);
            self.line_done(&line)?;
            rest = rest.strip_prefix('\n').unwrap_or(rest);
        }
        while let Some(end) = rest.find(['\n', '\r']) {
            if rest[end..].starts_with('\r') && end + 1 == rest.len() {
                break;
            }
            let mut line = std::mem::take(&mut self.line);
            line.push_str(&rest[..end]);
            self.line_done(&line)?;
            let skip = if rest[end..].starts_with("\r\n") {
                2
            } else {
                1
            };
            rest = &rest[end + skip..];
        }
        self.line.push_str(rest);
        if self.line.len() > MAX_EVENT_BYTES {
            return Err(ApiError::BadResponse);
        }
        Ok(())
    }

    fn line_done(&mut self, line: &str) -> Result<(), ApiError> {
        if line.is_empty() {
            if std::mem::take(&mut self.has_data) {
                let data = std::mem::take(&mut self.data);
                let event = value::parse_json(&data).ok_or(ApiError::BadResponse)?;
                self.event(&event)?;
            }
            return Ok(());
        }
        let (field, val) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };
        // Комментарии (`: ping`), `event:`, `id:`, `retry:` не нужны:
        // тип события берётся из самих данных.
        if field == "data" {
            if self.has_data {
                self.data.push('\n');
            }
            self.data.push_str(val);
            self.has_data = true;
            if self.data.len() > MAX_EVENT_BYTES {
                return Err(ApiError::BadResponse);
            }
        }
        Ok(())
    }

    fn event(&mut self, ev: &Value) -> Result<(), ApiError> {
        let bad = Err(ApiError::BadResponse);
        let kind = ev.get("type").and_then(Value::as_str);
        if self.stopped {
            // После message_stop допустимы только ping и неизвестные типы.
            return match kind {
                Some(
                    "message_start"
                    | "content_block_start"
                    | "content_block_delta"
                    | "content_block_stop"
                    | "message_delta"
                    | "message_stop",
                ) => bad,
                Some("error") => Err(stream_error(ev)),
                _ => Ok(()),
            };
        }
        match kind {
            Some("message_start") => {
                let msg = ev.get("message");
                if self.started
                    || msg.and_then(|m| m.get("role")).and_then(Value::as_str) != Some("assistant")
                {
                    return bad;
                }
                self.started = true;
                self.merge_usage(msg.and_then(|m| m.get("usage")));
            }
            // До message_start допустима только ошибка.
            _ if !self.started => {
                return match kind {
                    Some("error") => Err(stream_error(ev)),
                    _ => bad,
                };
            }
            Some("content_block_start") => {
                if self.index(ev) != Some(self.blocks.len()) || self.blocks.len() >= MAX_BLOCKS {
                    return bad;
                }
                let block = ev.get("content_block").ok_or(ApiError::BadResponse)?;
                let kind = match block.get("type").and_then(Value::as_str) {
                    Some("text") => Kind::Text(
                        block
                            .get("text")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned(),
                    ),
                    Some("tool_use") => Kind::Tool {
                        id: block.get("id").cloned().unwrap_or(Value::Null),
                        name: block.get("name").cloned().unwrap_or(Value::Null),
                        start: block.get("input").cloned().unwrap_or(Value::Null),
                        json: String::new(),
                    },
                    Some(_) => Kind::Other(block.clone()),
                    None => return bad,
                };
                self.blocks.push(Block { kind, done: false });
            }
            Some("content_block_delta") => {
                let i = self.index(ev).ok_or(ApiError::BadResponse)?;
                let block = self
                    .blocks
                    .get_mut(i)
                    .filter(|b| !b.done)
                    .ok_or(ApiError::BadResponse)?;
                let delta = ev.get("delta").ok_or(ApiError::BadResponse)?;
                let piece = |k| {
                    delta
                        .get(k)
                        .and_then(Value::as_str)
                        .ok_or(ApiError::BadResponse)
                };
                match (delta.get("type").and_then(Value::as_str), &mut block.kind) {
                    (Some("text_delta"), Kind::Text(t)) => t.push_str(piece("text")?),
                    (Some("input_json_delta"), Kind::Tool { json, .. }) => {
                        json.push_str(piece("partial_json")?);
                    }
                    (Some("text_delta" | "input_json_delta"), _) => return bad,
                    // Дельты чужих блоков (thinking, citations) не нужны.
                    _ => {}
                }
            }
            Some("content_block_stop") => {
                let i = self.index(ev).ok_or(ApiError::BadResponse)?;
                let block = self
                    .blocks
                    .get_mut(i)
                    .filter(|b| !b.done)
                    .ok_or(ApiError::BadResponse)?;
                block.done = true;
            }
            Some("message_delta") => {
                if let Some(r) = ev.get("delta").and_then(|d| d.get("stop_reason"))
                    && !matches!(r, Value::Null)
                {
                    self.stop_reason = Some(r.clone());
                }
                self.merge_usage(ev.get("usage"));
            }
            Some("message_stop") => self.stopped = true,
            Some("error") => return Err(stream_error(ev)),
            // ping и типы, добавленные API позже, пропускаются.
            Some(_) => {}
            None => return bad,
        }
        Ok(())
    }

    fn index(&self, ev: &Value) -> Option<usize> {
        let i = ev.get("index")?.as_uint(MAX_BLOCKS as u64)?;
        usize::try_from(i).ok()
    }

    fn merge_usage(&mut self, usage: Option<&Value>) {
        let Some(Value::Obj(fields)) = usage else {
            return;
        };
        for (k, v) in fields {
            match self.usage.iter_mut().find(|(seen, _)| seen == k) {
                Some((_, old)) => *old = v.clone(),
                None => self.usage.push((k.clone(), v.clone())),
            }
        }
    }

    /// Текст ответа, собранный к этому моменту (для показа по ходу).
    pub(crate) fn text(&self) -> String {
        let parts: Vec<&str> = self
            .blocks
            .iter()
            .filter_map(|b| match &b.kind {
                Kind::Text(t) if !t.is_empty() => Some(t.as_str()),
                _ => None,
            })
            .collect();
        let text = parts.join("\n\n");
        text.chars().take(api::MAX_REPLY_CHARS).collect()
    }

    /// Поток закончился: собрать сообщение и проверить его как обычный ответ.
    pub(crate) fn finish(mut self) -> Result<Reply, ApiError> {
        // `\r` в самом конце потока уже не станет `\r\n`.
        self.lines("")?;
        if !self.pending.is_empty() || !self.stopped || self.blocks.iter().any(|b| !b.done) {
            return Err(ApiError::BadResponse);
        }
        let mut content = Vec::new();
        for block in self.blocks {
            content.push(match block.kind {
                Kind::Text(t) => {
                    Value::obj(vec![("type", Value::str("text")), ("text", Value::Str(t))])
                }
                Kind::Tool {
                    id,
                    name,
                    start,
                    json,
                } => {
                    let input = if json.is_empty() {
                        start
                    } else {
                        value::parse_json(&json).ok_or(ApiError::BadResponse)?
                    };
                    Value::obj(vec![
                        ("type", Value::str("tool_use")),
                        ("id", id),
                        ("name", name),
                        ("input", input),
                    ])
                }
                Kind::Other(v) => v,
            });
        }
        let mut fields = vec![
            ("content", Value::Arr(content)),
            ("usage", Value::Obj(self.usage)),
        ];
        if let Some(r) = self.stop_reason {
            fields.push(("stop_reason", r));
        }
        api::parse_response(&Value::obj(fields))
    }
}

fn stream_error(ev: &Value) -> ApiError {
    let kind: Option<ErrorKind> = ev
        .get("error")
        .and_then(|e| e.get("type"))
        .and_then(Value::as_str)
        .and_then(api::parse_error_kind);
    ApiError::Stream(kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{Content, Stop};

    fn sse(events: &[&str]) -> String {
        events
            .iter()
            .map(|e| format!("event: x\ndata: {e}\n\n"))
            .collect()
    }

    const START: &str = r#"{"type":"message_start","message":{"role":"assistant","usage":{"input_tokens":10,"output_tokens":1}}}"#;
    const STOP: &str = r#"{"type":"message_stop"}"#;

    fn run(body: &str) -> Result<Reply, ApiError> {
        let mut s = Stream::default();
        s.feed(body.as_bytes())?;
        s.finish()
    }

    fn text_events() -> Vec<&'static str> {
        vec![
            START,
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
            r#"{"type":"ping"}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"При"}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"вет"}}"#,
            r#"{"type":"content_block_stop","index":0}"#,
            r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}"#,
            STOP,
        ]
    }

    #[test]
    fn text_reply() {
        let r = run(&sse(&text_events())).unwrap();
        assert_eq!(r.content, vec![Content::Text("Привет".into())]);
        assert_eq!(r.stop, Stop::EndTurn);
        assert_eq!((r.usage.input, r.usage.output), (10, 7));
    }

    #[test]
    fn tool_reply() {
        let body = sse(&[
            START,
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":"Смотрю."}}"#,
            r#"{"type":"content_block_stop","index":0}"#,
            r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t1","name":"click","input":{}}}"#,
            r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"ele"}}"#,
            r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"ment\": 3}"}}"#,
            r#"{"type":"content_block_stop","index":1}"#,
            r#"{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"t2","name":"read_page","input":{}}}"#,
            r#"{"type":"content_block_stop","index":2}"#,
            r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":20}}"#,
            STOP,
        ]);
        let r = run(&body).unwrap();
        assert_eq!(r.stop, Stop::ToolUse);
        let calls: Vec<_> = r
            .calls()
            .map(|(id, n, i)| (id.to_owned(), n.to_owned(), i.clone()))
            .collect();
        assert_eq!(
            calls,
            vec![
                (
                    "t1".into(),
                    "click".into(),
                    Value::obj(vec![("element", Value::Num(3.0))])
                ),
                ("t2".into(), "read_page".into(), Value::Obj(vec![])),
            ]
        );
    }

    #[test]
    fn any_chunking_and_line_endings() {
        let lf = sse(&text_events());
        for body in [lf.clone(), lf.replace('\n', "\r\n"), lf.replace('\n', "\r")] {
            let bytes = body.as_bytes();
            for size in [1, 2, 3, 7, 64] {
                let mut s = Stream::default();
                for chunk in bytes.chunks(size) {
                    s.feed(chunk).unwrap();
                }
                let r = s.finish().unwrap();
                assert_eq!(r.text(), "Привет", "size {size}");
            }
        }
    }

    #[test]
    fn partial_text_while_streaming() {
        let mut s = Stream::default();
        let events = text_events();
        s.feed(sse(&events[..4]).as_bytes()).unwrap();
        assert_eq!(s.text(), "При");
        s.feed(sse(&events[4..5]).as_bytes()).unwrap();
        assert_eq!(s.text(), "Привет");
    }

    #[test]
    fn comments_and_multiline_data() {
        let body = format!(
            ": comment\n\ndata: {}\n\ndata: {{\"type\":\n\
             data: \"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"text\",\"text\":\"a\"}}}}\n\n{}",
            START,
            sse(&text_events()[5..])
        );
        assert_eq!(run(&body).unwrap().text(), "a");
    }

    #[test]
    fn stream_errors() {
        let overloaded = r#"{"type":"error","error":{"type":"overloaded_error","message":"x"}}"#;
        let mut events = text_events();
        events.insert(3, overloaded);
        assert_eq!(
            run(&sse(&events)),
            Err(ApiError::Stream(Some(ErrorKind::Overloaded)))
        );
        assert_eq!(
            run(&sse(&[r#"{"type":"error","error":{"type":"new_kind"}}"#])),
            Err(ApiError::Stream(None))
        );
    }

    #[test]
    fn malformed_streams() {
        let e = text_events();
        let without = |i: usize| {
            let mut v = e.clone();
            v.remove(i);
            sse(&v)
        };
        let with = |i: usize, ev: &'static str| {
            let mut v = e.clone();
            v.insert(i, ev);
            sse(&v)
        };
        let cases = [
            ("no start", without(0)),
            ("no block stop", without(5)),
            ("no message stop", without(7)),
            ("no stop reason", without(6)),
            ("empty", String::new()),
            ("garbage json", "data: {nope\n\n".to_owned()),
            ("not json obj type", "data: 1\n\n".to_owned()),
            ("second start", with(1, START)),
            (
                "skipped index",
                with(
                    1,
                    r#"{"type":"content_block_start","index":5,"content_block":{"type":"text"}}"#,
                ),
            ),
            (
                "delta to unknown block",
                with(
                    3,
                    r#"{"type":"content_block_delta","index":4,"delta":{"type":"text_delta","text":"x"}}"#,
                ),
            ),
            (
                "delta after stop",
                with(
                    6,
                    r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"x"}}"#,
                ),
            ),
            (
                "json delta to text",
                with(
                    3,
                    r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}"#,
                ),
            ),
            (
                "double block stop",
                with(6, r#"{"type":"content_block_stop","index":0}"#),
            ),
            ("event after message stop", {
                let mut v = e.clone();
                v.push(
                    r#"{"type":"content_block_start","index":1,"content_block":{"type":"text"}}"#,
                );
                sse(&v)
            }),
            (
                "wrong role",
                sse(&[
                    r#"{"type":"message_start","message":{"role":"user"}}"#,
                    STOP,
                ]),
            ),
        ];
        for (name, body) in cases {
            assert!(run(&body).is_err(), "{name}");
        }
        // Невалидный UTF-8.
        let mut s = Stream::default();
        assert_eq!(s.feed(b"data: \xff\n\n"), Err(ApiError::BadResponse));
    }

    #[test]
    fn bad_tool_json_and_ids() {
        let tool = |id: &str, json: &str| {
            let start = format!(
                r#"{{"type":"content_block_start","index":0,"content_block":{{"type":"tool_use","id":"{id}","name":"click","input":{{}}}}}}"#
            );
            let delta = format!(
                r#"{{"type":"content_block_delta","index":0,"delta":{{"type":"input_json_delta","partial_json":{}}}}}"#,
                Value::str(json).to_json()
            );
            let events = [
                START.to_owned(),
                start,
                delta,
                r#"{"type":"content_block_stop","index":0}"#.to_owned(),
                r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"}}"#.to_owned(),
                STOP.to_owned(),
            ];
            let refs: Vec<&str> = events.iter().map(String::as_str).collect();
            run(&sse(&refs))
        };
        assert!(tool("t1", r#"{"element":1}"#).is_ok());
        assert!(tool("t1", r#"{"element":"#).is_err());
        assert!(tool("t1", "[1]").is_err());
        assert!(tool("t1", r#"{"a":1,"a":2}"#).is_err());
        assert!(tool("bad id!", r#"{"element":1}"#).is_err());
    }

    #[test]
    fn budgets() {
        let mut s = Stream::default();
        let line = format!("data: {}", "x".repeat(MAX_EVENT_BYTES + 1));
        assert!(s.feed(line.as_bytes()).is_err());

        let mut s = Stream::default();
        let chunk = vec![b':'; 1024 * 1024];
        let mut failed = false;
        for _ in 0..=MAX_STREAM_BYTES / chunk.len() {
            // Комментарий без конца строки упирается в предел строки раньше,
            // поэтому каждая порция — законченная строка.
            let mut c = chunk.clone();
            *c.last_mut().unwrap() = b'\n';
            if s.feed(&c).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed);

        let mut events = vec![START.to_owned()];
        for i in 0..=MAX_BLOCKS {
            events.push(format!(
                r#"{{"type":"content_block_start","index":{i},"content_block":{{"type":"text","text":"a"}}}}"#
            ));
            events.push(format!(r#"{{"type":"content_block_stop","index":{i}}}"#));
        }
        let refs: Vec<&str> = events.iter().map(String::as_str).collect();
        let mut s = Stream::default();
        assert!(s.feed(sse(&refs).as_bytes()).is_err());
    }

    #[test]
    fn thinking_blocks_are_skipped() {
        let body = sse(&[
            START,
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hm"}}"#,
            r#"{"type":"content_block_stop","index":0}"#,
            r#"{"type":"content_block_start","index":1,"content_block":{"type":"text","text":"ok"}}"#,
            r#"{"type":"content_block_stop","index":1}"#,
            r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"}}"#,
            STOP,
        ]);
        let r = run(&body).unwrap();
        assert_eq!(r.content, vec![Content::Text("ok".into())]);
    }
}
