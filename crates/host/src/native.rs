//! Мост со стороны Firefox. Firefox запускает его через native messaging и
//! держит, пока открыт порт расширения; мост слушает канал `ipc`, к которому
//! подключаются MCP-процессы (`leash-host mcp`).
//!
//! Вызовы идут в расширение строго по одному: действия в браузере
//! последовательны, а подтверждение пользователя не должно смешиваться с
//! чужим вызовом. Каждое подключение — свой сеанс: расширение ведёт для него
//! отдельное состояние (рабочая вкладка, прочитанные сайты, признаки инъекций).

use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use leash_core::json::{Value, parse_json};
use leash_core::tools;

use crate::frame;
use crate::ipc::{self, Listener, Stream};
use crate::paths;

/// Дольше, чем расширение ждёт подтверждения пользователя (5 минут).
const CALL_TIMEOUT: Duration = Duration::from_secs(330);
/// Как часто во время вызова проверяется, жив ли MCP-клиент.
const WATCH_EVERY: Duration = Duration::from_millis(250);

/// Общее состояние: канал в Firefox и ожидающие ответа вызовы.
struct Hub<W> {
    to_firefox: Mutex<W>,
    pending: Mutex<HashMap<u64, Sender<Value>>>,
    /// Один вызов в Firefox за раз.
    turn: Mutex<()>,
    next: AtomicU64,
}

/// Запуск из Firefox: канал в каталоге состояния, кадры через stdin/stdout.
pub fn run(home: &Path) -> io::Result<()> {
    paths::ensure_private_dir(&paths::state_dir(home), home)?;
    let endpoint = paths::socket_path(home)?;
    let listener = ipc::bind(&endpoint)?;
    let result = serve(listener, io::stdin().lock(), io::stdout());
    let _ = std::fs::remove_file(&endpoint);
    result
}

/// Обслуживание до закрытия канала Firefox.
pub fn serve<R, W>(listener: Listener, mut from_firefox: R, to_firefox: W) -> io::Result<()>
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
        loop {
            let Ok(conn) = listener.accept() else {
                continue;
            };
            let hub = Arc::clone(&accept_hub);
            let session = sessions.fetch_add(1, Ordering::Relaxed);
            thread::spawn(move || {
                let _ = client(&hub, conn, session);
                hub.end(session);
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
    fn end(&self, session: u64) {
        self.send(&Value::obj(vec![
            ("type", Value::str("end")),
            ("session", Value::Num(session as f64)),
        ]));
    }

    /// Ответ расширения или `None` по таймауту. Ушедший клиент не прерывает
    /// ожидание: после `end` расширение ответит быстро, и очередь освободится
    /// в согласованном состоянии.
    fn wait(
        &self,
        rx: &mpsc::Receiver<Value>,
        session: u64,
        client: &Stream,
        ended: &mut bool,
    ) -> Option<Value> {
        let deadline = Instant::now() + CALL_TIMEOUT;
        loop {
            match rx.recv_timeout(WATCH_EVERY) {
                Ok(reply) => return Some(reply),
                Err(mpsc::RecvTimeoutError::Disconnected) => return None,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if Instant::now() >= deadline {
                return None;
            }
            if !*ended && ipc::gone(client) {
                *ended = true;
                self.end(session);
            }
        }
    }

    fn send(&self, msg: &Value) -> bool {
        match self.to_firefox.lock() {
            Ok(mut w) => frame::write_native(&mut *w, msg).is_ok(),
            Err(_) => false,
        }
    }

    /// Вызов инструмента в расширении; ответ — текст и признак ошибки.
    /// Пока вызов идёт, `client` проверяется: если MCP-клиент ушёл, расширение
    /// сразу узнаёт об этом (`end`) и закрывает вопросы этого сеанса, а не
    /// держит очередь до таймаута подтверждения. `None` — сеанс окончен.
    fn call(
        &self,
        session: u64,
        tool: &str,
        input: &Value,
        client: &Stream,
    ) -> Option<(String, bool)> {
        let Ok(_turn) = self.turn.lock() else {
            return Some(("Мост в неисправном состоянии.".into(), true));
        };
        let mut ended = false;
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
            self.wait(&rx, session, client, &mut ended)
        } else {
            None
        };
        if let Ok(mut p) = self.pending.lock() {
            p.remove(&id);
        }
        if ended {
            return None;
        }
        let Some(reply) = reply else {
            return Some(("Firefox не ответил на вызов.".into(), true));
        };
        let text = reply.get("text").and_then(Value::as_str);
        let is_error = reply.get("isError").and_then(Value::as_bool);
        Some(match (text, is_error) {
            (Some(t), Some(e)) => (t.to_owned(), e),
            _ => ("Некорректный ответ расширения.".into(), true),
        })
    }
}

/// Один MCP-процесс: строки `{"id","tool","input"}` → `{"id","text","isError"}`.
fn client<W: Write>(hub: &Hub<W>, conn: Stream, session: u64) -> io::Result<()> {
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
            match hub.call(session, tool, &input, lines.get_ref()) {
                Some(reply) => reply,
                // Клиент ушёл посреди вызова. end уже отправлен; второй, после
                // выхода из client, расширение примет как повтор и ничего не сделает.
                None => return Ok(()),
            }
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

    /// Пара соединённых потоков вместо stdin/stdout Firefox.
    #[cfg(unix)]
    fn pair() -> (Stream, Stream) {
        Stream::pair().unwrap()
    }

    #[cfg(windows)]
    fn pair() -> (Stream, Stream) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let a = Stream::connect(l.local_addr().unwrap()).unwrap();
        (a, l.accept().unwrap().0)
    }

    /// Расширение-заглушка: отвечает на вызовы и записывает всё, что получило.
    fn fake_extension(mut ext: Stream, seen: Arc<Mutex<Vec<Value>>>) {
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
        let listener = ipc::bind(&sock).unwrap();
        let (host_side, ext_side) = pair();
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
    fn client_gone_mid_call_ends_session_at_once() {
        let home = TempHome::new("gn");
        let sock = home.0.join("s.sock");
        let listener = ipc::bind(&sock).unwrap();
        let (host_side, mut ext) = pair();
        let reader = host_side.try_clone().unwrap();
        thread::spawn(move || serve(listener, reader, host_side));

        // Клиент шлёт вызов и уходит, не дождавшись ответа (вопрос висит).
        let mut a = ipc::connect(&sock).unwrap();
        let req = Value::obj(vec![
            ("id", Value::Num(1.0)),
            ("tool", Value::str("click")),
            ("input", Value::obj(vec![("element", Value::Num(1.0))])),
        ]);
        frame::write_line(&mut a, &req).unwrap();
        let mut from_host = ext.try_clone().unwrap();
        let mut next = || frame::read_native(&mut from_host).unwrap().unwrap();
        assert_eq!(next().get("type").and_then(Value::as_str), Some("hello"));
        let call = next();
        let session = call.get("session").cloned();
        drop(a);

        // end приходит, пока вызов ещё не отвечен.
        let end = next();
        assert_eq!(end.get("type").and_then(Value::as_str), Some("end"));
        assert_eq!(end.get("session").cloned(), session);

        // Расширение отвечает отказом — очередь свободна для другого сеанса.
        let reply = Value::obj(vec![
            ("id", call.get("id").unwrap().clone()),
            ("text", Value::str("отклонено")),
            ("isError", Value::Bool(true)),
        ]);
        frame::write_native(&mut ext, &reply).unwrap();
        let mut b = Firefox::new(sock);
        let answer = thread::spawn(move || b.call("read_page", &Value::Obj(vec![])));
        let msg = loop {
            let m = next();
            if m.get("type").and_then(Value::as_str) == Some("call") {
                break m;
            }
        };
        assert_ne!(msg.get("session").cloned(), session);
        let ok = Value::obj(vec![
            ("id", msg.get("id").unwrap().clone()),
            ("text", Value::str("ok")),
            ("isError", Value::Bool(false)),
        ]);
        frame::write_native(&mut ext, &ok).unwrap();
        assert_eq!(answer.join().unwrap(), ("ok".into(), false));
    }

    #[test]
    fn host_exits_when_firefox_closes() {
        let home = TempHome::new("cl");
        let listener = ipc::bind(&home.0.join("s.sock")).unwrap();
        let (host_side, ext_side) = pair();
        drop(ext_side);
        let reader = host_side.try_clone().unwrap();
        assert!(serve(listener, reader, host_side).is_ok());
    }
}
