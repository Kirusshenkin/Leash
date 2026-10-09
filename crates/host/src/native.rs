//! Мост со стороны Firefox. Firefox запускает его через native messaging и
//! держит, пока открыт порт расширения; мост слушает unix-сокет, к которому
//! подключаются MCP-процессы (`leash-host mcp`).
//!
//! Вызовы идут в расширение строго по одному: действия в браузере
//! последовательны, а подтверждение пользователя не должно смешиваться с
//! чужим вызовом. Каждое подключение — свой сеанс: расширение ведёт для него
//! отдельное состояние (рабочая вкладка, прочитанные сайты, признаки инъекций).

use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{fs, thread};

use leash_core::json::{Value, parse_json};
use leash_core::tools;

use crate::frame;
use crate::paths;

/// Дольше, чем расширение ждёт подтверждения пользователя (5 минут).
const CALL_TIMEOUT: Duration = Duration::from_secs(330);

/// Общее состояние: канал в Firefox и ожидающие ответа вызовы.
struct Hub<W> {
    to_firefox: Mutex<W>,
    pending: Mutex<HashMap<u64, Sender<Value>>>,
    /// Один вызов в Firefox за раз.
    turn: Mutex<()>,
    next: AtomicU64,
}

/// Запуск из Firefox: сокет в `~/.leash`, кадры через stdin/stdout.
pub fn run(home: &Path) -> io::Result<()> {
    let dir = paths::state_dir(home);
    paths::ensure_private_dir(&dir, home)?;
    let sock = paths::socket_path(home)?;
    if UnixStream::connect(&sock).is_ok() {
        return Err(io::Error::other(
            "мост уже запущен другим экземпляром Firefox",
        ));
    }
    let _ = fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)?;
    fs::set_permissions(&sock, fs::Permissions::from_mode(0o600))?;
    let result = serve(listener, io::stdin().lock(), io::stdout());
    let _ = fs::remove_file(&sock);
    result
}

/// Обслуживание до закрытия канала Firefox.
pub fn serve<R, W>(listener: UnixListener, mut from_firefox: R, to_firefox: W) -> io::Result<()>
where
    R: Read,
    W: Write + Send + 'static,
{
    let hub = Arc::new(Hub {
        to_firefox: Mutex::new(to_firefox),
        pending: Mutex::new(HashMap::new()),
        turn: Mutex::new(()),
        next: AtomicU64::new(1),
    });
    // Приветствие: расширение показывает «мост подключён» только после него.
    hub.send(&Value::obj(vec![
        ("type", Value::str("hello")),
        ("version", Value::str(env!("CARGO_PKG_VERSION"))),
    ]));
    let accept_hub = Arc::clone(&hub);
    thread::spawn(move || {
        let sessions = AtomicU64::new(1);
        for conn in listener.incoming() {
            let Ok(conn) = conn else { continue };
            let hub = Arc::clone(&accept_hub);
            let session = sessions.fetch_add(1, Ordering::Relaxed);
            thread::spawn(move || {
                let _ = client(&hub, conn, session);
                hub.send(&Value::obj(vec![
                    ("type", Value::str("end")),
                    ("session", Value::Num(session as f64)),
                ]));
            });
        }
    });
    // Ответы расширения раздаются ждущим вызовам. Конец канала — Firefox
    // закрыл порт: мост завершается.
    while let Some(msg) = frame::read_native(&mut from_firefox)? {
        let Some(id) = msg.get("id").and_then(|v| v.as_uint(u64::MAX >> 11)) else {
            continue;
        };
        let waiter = hub.pending.lock().ok().and_then(|mut p| p.remove(&id));
        if let Some(tx) = waiter {
            let _ = tx.send(msg);
        }
    }
    Ok(())
}

impl<W: Write> Hub<W> {
    fn send(&self, msg: &Value) -> bool {
        match self.to_firefox.lock() {
            Ok(mut w) => frame::write_native(&mut *w, msg).is_ok(),
            Err(_) => false,
        }
    }

    /// Вызов инструмента в расширении; ответ — текст и признак ошибки.
    fn call(&self, session: u64, tool: &str, input: &Value) -> (String, bool) {
        let Ok(_turn) = self.turn.lock() else {
            return ("Мост в неисправном состоянии.".into(), true);
        };
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel();
        if let Ok(mut p) = self.pending.lock() {
            p.insert(id, tx);
        }
        let sent = self.send(&Value::obj(vec![
            ("type", Value::str("call")),
            ("id", Value::Num(id as f64)),
            ("session", Value::Num(session as f64)),
            ("tool", Value::str(tool)),
            ("input", input.clone()),
        ]));
        let reply = if sent {
            rx.recv_timeout(CALL_TIMEOUT).ok()
        } else {
            None
        };
        if let Ok(mut p) = self.pending.lock() {
            p.remove(&id);
        }
        let Some(reply) = reply else {
            return ("Firefox не ответил на вызов.".into(), true);
        };
        let text = reply.get("text").and_then(Value::as_str);
        let is_error = reply.get("isError").and_then(Value::as_bool);
        match (text, is_error) {
            (Some(t), Some(e)) => (t.to_owned(), e),
            _ => ("Некорректный ответ расширения.".into(), true),
        }
    }
}

/// Один MCP-процесс: строки `{"id","tool","input"}` → `{"id","text","isError"}`.
fn client<W: Write>(hub: &Hub<W>, conn: UnixStream, session: u64) -> io::Result<()> {
    let mut out = conn.try_clone()?;
    let mut lines = BufReader::new(conn);
    while let Some(line) = frame::read_line(&mut lines)? {
        let Some(req) = parse_json(&line) else {
            return Ok(());
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let tool = req.get("tool").and_then(Value::as_str).unwrap_or_default();
        let input = req.get("input").cloned().unwrap_or(Value::Obj(Vec::new()));
        // Имя проверяется и здесь: в расширение уходят только известные вызовы.
        let (text, is_error) = if tools::definitions().iter().any(|t| t.name == tool)
            && matches!(input, Value::Obj(_))
        {
            hub.call(session, tool, &input)
        } else {
            ("Неизвестный вызов.".into(), true)
        };
        frame::write_line(
            &mut out,
            &Value::obj(vec![
                ("id", id),
                ("text", Value::str(text)),
                ("isError", Value::Bool(is_error)),
            ]),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Firefox;
    use crate::paths::tests::TempHome;

    /// Расширение-заглушка: отвечает на вызовы и записывает всё, что получило.
    fn fake_extension(mut ext: UnixStream, seen: Arc<Mutex<Vec<Value>>>) {
        thread::spawn(move || {
            let mut reader = ext.try_clone().unwrap();
            while let Ok(Some(msg)) = frame::read_native(&mut reader) {
                seen.lock().unwrap().push(msg.clone());
                if msg.get("type").and_then(Value::as_str) != Some("call") {
                    continue;
                }
                let tool = msg.get("tool").and_then(Value::as_str).unwrap().to_owned();
                let reply = Value::obj(vec![
                    ("id", msg.get("id").unwrap().clone()),
                    ("text", Value::str(format!("ok {tool}"))),
                    ("isError", Value::Bool(tool == "click")),
                ]);
                frame::write_native(&mut ext, &reply).unwrap();
            }
        });
    }

    #[test]
    fn calls_reach_extension_and_come_back() {
        let home = TempHome::new("nv");
        let sock = home.0.join("s.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let (host_side, ext_side) = UnixStream::pair().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        fake_extension(ext_side, Arc::clone(&seen));
        let reader = host_side.try_clone().unwrap();
        thread::spawn(move || serve(listener, reader, host_side));

        let mut ff = Firefox::new(sock.clone());
        assert_eq!(
            ff.call("read_page", &Value::Obj(vec![])),
            ("ok read_page".into(), false)
        );
        let input = Value::obj(vec![("element", Value::Num(3.0))]);
        assert_eq!(ff.call("click", &input), ("ok click".into(), true));
        // Неизвестный вызов до расширения не доходит.
        assert!(ff.call("run_js", &Value::Obj(vec![])).1);

        // Второй клиент — другой сеанс; закрытие первого — сообщение end.
        let mut other = Firefox::new(sock);
        other.call("list_tabs", &Value::Obj(vec![]));
        drop(ff);
        thread::sleep(Duration::from_millis(200));
        let seen = seen.lock().unwrap();
        let calls: Vec<_> = seen
            .iter()
            .filter(|m| m.get("type").and_then(Value::as_str) == Some("call"))
            .collect();
        assert_eq!(calls.len(), 3);
        assert_ne!(calls[0].get("session"), calls[2].get("session"));
        assert!(
            calls
                .iter()
                .all(|c| c.get("tool").and_then(Value::as_str) != Some("run_js"))
        );
        assert!(
            seen.iter()
                .any(|m| m.get("type").and_then(Value::as_str) == Some("end")
                    && m.get("session") == calls[0].get("session"))
        );
    }

    #[test]
    fn host_exits_when_firefox_closes() {
        let home = TempHome::new("cl");
        let listener = UnixListener::bind(home.0.join("s.sock")).unwrap();
        let (host_side, ext_side) = UnixStream::pair().unwrap();
        drop(ext_side);
        let reader = host_side.try_clone().unwrap();
        assert!(serve(listener, reader, host_side).is_ok());
    }
}
