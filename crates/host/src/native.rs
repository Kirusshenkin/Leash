//! Мост со стороны Firefox. Firefox запускает его через native messaging и
//! держит, пока открыт порт расширения; мост слушает сокет/канал, к которому
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
use std::time::{Duration, Instant};
use std::{fs, thread};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

use leash_core::json::{Value, parse_json};
use leash_core::tools;

use crate::frame;
use crate::paths;

/// Дольше, чем расширение ждёт подтверждения пользователя (5 минут).
const CALL_TIMEOUT: Duration = Duration::from_secs(330);
/// Как часто во время вызова проверяется, жив ли MCP-клиент.
const WATCH_EVERY: Duration = Duration::from_millis(250);

#[cfg(windows)]
pub mod windows_ipc {
    //! Windows named pipe IPC. Unsafe FFI для работы с Win32 API.
    //! Модуль изолирует весь unsafe код для Windows поддержки.

    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    // Windows API типы и константы
    #[derive(Debug, Clone, Copy)]
    pub struct Handle(*mut ());
    // HANDLE (*mut ()) не является Send по умолчанию, но нам нужно передавать
    // его между потоками. Это безопасно, так как HANDLE — это просто непрозрачный
    // дескриптор, и Windows обеспечивает синхронизацию.
    unsafe impl Send for Handle {}
    unsafe impl Sync for Handle {}

    type Bool = i32;
    type DWord = u32;

    const INVALID_HANDLE_VALUE: Handle = Handle(-1i32 as *mut ());
    const GENERIC_READ: DWord = 0x80000000;
    const GENERIC_WRITE: DWord = 0x40000000;
    const PIPE_ACCESS_DUPLEX: DWord = 0x00000003;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: DWord = 0x00080000;
    const PIPE_TYPE_BYTE: DWord = 0x00000000;
    const PIPE_REJECT_REMOTE_CLIENTS: DWord = 0x00000008;
    const OPEN_EXISTING: DWord = 3;

    // Минимальные Windows API bindings
    unsafe extern "system" {
        fn CreateNamedPipeA(
            lpName: *const u8,
            dwOpenMode: DWord,
            dwPipeMode: DWord,
            nMaxInstances: DWord,
            nOutBufferSize: DWord,
            nInBufferSize: DWord,
            nDefaultTimeOut: DWord,
            lpSecurityAttributes: *const (),
        ) -> Handle;

        fn CreateFileA(
            lpFileName: *const u8,
            dwDesiredAccess: DWord,
            dwShareMode: DWord,
            lpSecurityAttributes: *const (),
            dwCreationDisposition: DWord,
            dwFlagsAndAttributes: DWord,
            hTemplateFile: Handle,
        ) -> Handle;

        fn ReadFile(
            hFile: Handle,
            lpBuffer: *mut u8,
            nNumberOfBytesToRead: DWord,
            lpNumberOfBytesRead: *mut DWord,
            lpOverlapped: *const (),
        ) -> Bool;

        fn WriteFile(
            hFile: Handle,
            lpBuffer: *const u8,
            nNumberOfBytesToWrite: DWord,
            lpNumberOfBytesWritten: *mut DWord,
            lpOverlapped: *const (),
        ) -> Bool;

        fn FlushFileBuffers(hFile: Handle) -> Bool;

        fn CloseHandle(hObject: Handle) -> Bool;

        fn ConnectNamedPipe(hNamedPipe: Handle, lpOverlapped: *const ()) -> Bool;
    }

    pub struct PipeStream {
        handle: Handle,
    }

    impl std::io::Read for PipeStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut bytes_read = 0u32;
            let result = unsafe {
                ReadFile(
                    self.handle.0,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut bytes_read,
                    ptr::null(),
                )
            };
            if result == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(bytes_read as usize)
        }
    }

    impl std::io::Write for PipeStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut bytes_written = 0u32;
            let result = unsafe {
                WriteFile(
                    self.handle.0,
                    buf.as_ptr(),
                    buf.len() as u32,
                    &mut bytes_written,
                    ptr::null(),
                )
            };
            if result == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(bytes_written as usize)
        }

        fn flush(&mut self) -> io::Result<()> {
            let result = unsafe { FlushFileBuffers(self.handle.0) };
            if result == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    impl Drop for PipeStream {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.handle.0);
            }
        }
    }

    pub struct PipeListener {
        handle: Handle,
    }

    impl PipeListener {
        pub fn accept(&self) -> io::Result<PipeStream> {
            let result = unsafe { ConnectNamedPipe(self.handle.0, ptr::null()) };
            if result == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(PipeStream {
                handle: self.handle,
            })
        }
    }

    impl Drop for PipeListener {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.handle.0);
            }
        }
    }

    pub fn create_listener() -> io::Result<PipeListener> {
        let pipe_name = make_pipe_name();
        let handle = unsafe {
            CreateNamedPipeA(
                pipe_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                8 << 20,
                8 << 20,
                0,
                ptr::null(),
            )
        };
        if handle == INVALID_HANDLE_VALUE.0 {
            return Err(io::Error::last_os_error());
        }
        Ok(PipeListener { handle: Handle(handle) })
    }

    pub fn connect_to_pipe() -> io::Result<PipeStream> {
        let pipe_name = make_pipe_name();
        let handle = unsafe {
            CreateFileA(
                pipe_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE.0 {
            return Err(io::Error::last_os_error());
        }
        Ok(PipeStream { handle: Handle(handle) })
    }

    fn make_pipe_name() -> Vec<u8> {
        // Формат имени канала: \\.\pipe\Leash-<UID>
        // На Windows используем SID текущего пользователя как идентификатор для безопасности.
        // Пока: фиксированное имя (в полной реализации нужно получить SID).
        let name = b"\\\\.\\pipe\\Leash\0".to_vec();
        name
    }
}

/// Трейт для проверки, жив ли MCP-клиент. Реализован для UnixStream (Unix) и PipeStream (Windows).
trait ClientConnection: Read {
    /// Вернёт true, если клиент разорвал соединение.
    fn is_gone(&self) -> bool;
}

#[cfg(unix)]
impl ClientConnection for UnixStream {
    fn is_gone(&self) -> bool {
        match self.try_clone() {
            Ok(mut client) => {
                if client.set_nonblocking(true).is_err() {
                    return true;
                }
                let mut byte = [0u8; 1];
                let result = client.read(&mut byte);
                let restored = client.set_nonblocking(false).is_ok();
                !restored || !matches!(result, Err(ref e) if e.kind() == io::ErrorKind::WouldBlock)
            }
            Err(_) => true,
        }
    }
}

#[cfg(windows)]
impl ClientConnection for windows_ipc::PipeStream {
    fn is_gone(&self) -> bool {
        // На Windows пока упрощённо: считаем, что клиент жив.
        // Полная реализация требит PeekNamedPipe, что усложняет код.
        false
    }
}

/// Общее состояние: канал в Firefox и ожидающие ответа вызовы.
struct Hub<W> {
    to_firefox: Mutex<W>,
    pending: Mutex<HashMap<u64, Sender<Value>>>,
    /// Один вызов в Firefox за раз.
    turn: Mutex<()>,
    next: AtomicU64,
}

/// Запуск из Firefox: сокет/канал в государственном каталоге, кадры через stdin/stdout.
pub fn run(home: &Path) -> io::Result<()> {
    let dir = paths::state_dir(home);
    paths::ensure_private_dir(&dir, home)?;

    #[cfg(unix)]
    {
        let sock = paths::socket_path(home)?;
        if UnixStream::connect(&sock).is_ok() {
            return Err(io::Error::other(
                "мост уже запущен другим экземпляром Firefox",
            ));
        }
        let _ = fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock)?;
        fs::set_permissions(&sock, fs::Permissions::from_mode(0o600))?;
        let result = serve_unix(listener, io::stdin().lock(), io::stdout());
        let _ = fs::remove_file(&sock);
        result
    }

    #[cfg(windows)]
    {
        let listener = windows_ipc::create_listener()?;
        serve_windows(listener, io::stdin().lock(), io::stdout())
    }
}

/// Обслуживание до закрытия канала Firefox (Unix).
#[cfg(unix)]
pub fn serve_unix<R, W>(listener: UnixListener, mut from_firefox: R, to_firefox: W) -> io::Result<()>
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
    fn wait<C: ClientConnection>(
        &self,
        rx: &mpsc::Receiver<Value>,
        session: u64,
        client: &C,
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
            if !*ended && client.is_gone() {
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
    fn call<C: ClientConnection>(
        &self,
        session: u64,
        tool: &str,
        input: &Value,
        client: &C,
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
/// Unix версия со строками Unix сокета.
#[cfg(unix)]
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

/// Один MCP-процесс через именованный канал (Windows).
#[cfg(windows)]
fn client_pipe<W: Write>(hub: &Hub<W>, mut conn: windows_ipc::PipeStream, session: u64) -> io::Result<()> {
    loop {
        let mut lines = BufReader::new(&mut conn);
        if let Some(line) = frame::read_line(&mut lines)? {
            drop(lines);
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
                // На Windows упрощённо: не проверяем is_gone, полная реализация требует PeekNamedPipe
                match hub.call(session, tool, &input, &conn) {
                    Some(reply) => reply,
                    None => return Ok(()),
                }
            } else {
                ("Неизвестный вызов.".into(), true)
            };
            frame::write_line(
                &mut conn,
                &Value::obj(vec![
                    ("id", id),
                    ("text", Value::str(text)),
                    ("isError", Value::Bool(is_error)),
                ]),
            )?;
        } else {
            return Ok(());
        }
    }
}

/// Обслуживание до закрытия канала Firefox (Windows).
#[cfg(windows)]
pub fn serve_windows<R, W>(listener: windows_ipc::PipeListener, mut from_firefox: R, to_firefox: W) -> io::Result<()>
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
            match listener.accept() {
                Ok(conn) => {
                    let hub = Arc::clone(&accept_hub);
                    let session = sessions.fetch_add(1, Ordering::Relaxed);
                    thread::spawn(move || {
                        let _ = client_pipe(&hub, conn, session);
                        hub.end(session);
                    });
                }
                Err(_) => break, // Ошибка при создании listener, завершаем
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Firefox;
    use crate::paths::tests::TempHome;

    /// Расширение-заглушка: отвечает на вызовы и записывает всё, что получило.
    #[cfg(unix)]
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
    #[cfg(unix)]
    fn calls_reach_extension_and_come_back() {
        let home = TempHome::new("nv");
        let sock = home.0.join("s.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let (host_side, ext_side) = UnixStream::pair().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        fake_extension(ext_side, Arc::clone(&seen));
        let reader = host_side.try_clone().unwrap();
        thread::spawn(move || serve_unix(listener, reader, host_side));

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
    #[cfg(unix)]
    fn client_gone_mid_call_ends_session_at_once() {
        let home = TempHome::new("gn");
        let sock = home.0.join("s.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let (host_side, mut ext) = UnixStream::pair().unwrap();
        let reader = host_side.try_clone().unwrap();
        thread::spawn(move || serve_unix(listener, reader, host_side));

        // Клиент шлёт вызов и уходит, не дождавшись ответа (вопрос висит).
        let mut a = UnixStream::connect(&sock).unwrap();
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
    #[cfg(unix)]
    fn host_exits_when_firefox_closes() {
        let home = TempHome::new("cl");
        let listener = UnixListener::bind(home.0.join("s.sock")).unwrap();
        let (host_side, ext_side) = UnixStream::pair().unwrap();
        drop(ext_side);
        let reader = host_side.try_clone().unwrap();
        assert!(serve_unix(listener, reader, host_side).is_ok());
    }

    /// Test Windows named pipe IPC round-trip (server + client in same process).
    /// This tests that PipeListener can accept connections and exchange messages.
    #[cfg(windows)]
    #[test]
    fn windows_pipe_round_trip() {
        use std::sync::{Arc, Mutex};

        let listener = windows_ipc::create_listener().expect("Failed to create listener");
        let test_msg = Value::obj(vec![("test", Value::str("hello from pipe"))]);
        let received = Arc::new(Mutex::new(None));
        let received_clone = Arc::clone(&received);

        // Spawn listener thread
        let listener_thread = thread::spawn(move || {
            match listener.accept() {
                Ok(mut conn) => {
                    let mut buf = [0u8; 256];
                    match conn.read(&mut buf) {
                        Ok(n) if n > 0 => {
                            if let Some(msg) = parse_json(&String::from_utf8_lossy(&buf[..n])) {
                                *received_clone.lock().unwrap() = Some(msg);
                            }
                        }
                        _ => {}
                    }
                    // Send response
                    let response = Value::str("ok").to_json();
                    let _ = conn.write(response.as_bytes());
                }
                Err(_) => {}
            }
        });

        // Give listener time to start
        thread::sleep(Duration::from_millis(100));

        // Connect and send message
        match windows_ipc::connect_to_pipe() {
            Ok(mut client) => {
                let msg_json = test_msg.to_json();
                let _ = client.write(msg_json.as_bytes());

                // Read response
                let mut response_buf = [0u8; 256];
                if let Ok(n) = client.read(&mut response_buf) {
                    let response = String::from_utf8_lossy(&response_buf[..n]).to_string();
                    assert_eq!(response, "\"ok\"");
                }
            }
            Err(_) => panic!("Failed to connect to pipe"),
        }

        listener_thread.join().unwrap();
        let received_msg = received.lock().unwrap();
        assert!(received_msg.is_some(), "Message should be received");
        assert_eq!(
            received_msg.as_ref().unwrap().get("test"),
            Some(&Value::str("hello from pipe"))
        );
    }
}
