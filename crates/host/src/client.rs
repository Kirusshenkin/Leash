//! MCP-процесс (`leash-host mcp`): stdio от Claude, сокет/канал к мосту в Firefox.

use std::io::{self, BufReader, Write};
use std::path::PathBuf;

use leash_core::json::{Value, parse_json};

use crate::frame;
use crate::mcp;

const NOT_CONNECTED: &str = "Firefox с расширением Leash не подключён. Попроси пользователя открыть \
Firefox; если он открыт — проверить, что мост установлен (leash-host install) и Firefox \
перезапущен после установки.";

/// Соединение с мостом в Firefox; открывается по первому вызову и заново
/// после обрыва (Firefox перезапустили).
#[cfg(unix)]
pub struct Firefox {
    socket: PathBuf,
    conn: Option<(BufReader<std::os::unix::net::UnixStream>, std::os::unix::net::UnixStream)>,
    next: u64,
}

#[cfg(windows)]
pub struct Firefox {
    socket: PathBuf,
    conn: Option<std::io::Cursor<Vec<u8>>>, // Placeholder для Windows
    next: u64,
}

impl Firefox {
    pub fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            conn: None,
            next: 1,
        }
    }

    pub fn call(&mut self, tool: &str, input: &Value) -> (String, bool) {
        match self.try_call(tool, input) {
            Ok(r) => r,
            Err(_) => {
                self.conn = None;
                (NOT_CONNECTED.into(), true)
            }
        }
    }

    #[cfg(unix)]
    fn try_call(&mut self, tool: &str, input: &Value) -> io::Result<(String, bool)> {
        use std::os::unix::net::UnixStream;

        if self.conn.is_none() {
            let s = UnixStream::connect(&self.socket)?;
            self.conn = Some((BufReader::new(s.try_clone()?), s));
        }
        let id = self.next;
        self.next += 1;
        let Some((reader, writer)) = self.conn.as_mut() else {
            return Err(io::Error::other("нет соединения"));
        };
        frame::write_line(
            writer,
            &Value::obj(vec![
                ("id", Value::Num(id as f64)),
                ("tool", Value::str(tool)),
                ("input", input.clone()),
            ]),
        )?;
        let line =
            frame::read_line(reader)?.ok_or_else(|| io::Error::other("мост закрыл соединение"))?;
        let reply = parse_json(&line).ok_or_else(|| io::Error::other("ответ моста не JSON"))?;
        if reply.get("id").and_then(Value::as_f64) != Some(id as f64) {
            return Err(io::Error::other("ответ не на этот вызов"));
        }
        match (
            reply.get("text").and_then(Value::as_str),
            reply.get("isError").and_then(Value::as_bool),
        ) {
            (Some(t), Some(e)) => Ok((t.to_owned(), e)),
            _ => Err(io::Error::other("некорректный ответ моста")),
        }
    }

    #[cfg(windows)]
    fn try_call(&mut self, tool: &str, input: &Value) -> io::Result<(String, bool)> {
        // Windows implementation placeholder
        Err(io::Error::other("Windows IPC not yet implemented"))
    }
}

/// Цикл MCP по stdio до закрытия stdin клиентом.
pub fn run(socket: PathBuf) -> io::Result<()> {
    let mut firefox = Firefox::new(socket);
    let mut input = io::stdin().lock();
    let mut out = io::stdout().lock();
    while let Some(line) = frame::read_line(&mut input)? {
        if line.trim().is_empty() {
            continue;
        }
        let reply = match parse_json(&line) {
            Some(msg) => mcp::handle(&msg, &mut |tool, args| firefox.call(tool, args)),
            None => Some(mcp::parse_error()),
        };
        if let Some(reply) = reply {
            frame::write_line(&mut out, &reply)?;
        }
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_bridge_is_a_tool_error_not_a_crash() {
        let mut ff = Firefox::new(PathBuf::from("/tmp/leash-no-such-dir/host.sock"));
        let (text, is_error) = ff.call("read_page", &Value::Obj(vec![]));
        assert!(is_error);
        assert!(text.contains("leash-host install"), "{text}");
    }
}
