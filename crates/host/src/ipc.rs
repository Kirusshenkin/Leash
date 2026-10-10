//! Канал между MCP-процессами и мостом в Firefox.
//!
//! macOS, Linux: unix-сокет 0600 в каталоге 0700 (см. `paths`).
//!
//! Windows: TCP только на 127.0.0.1 со случайным портом. Порт и токен лежат
//! в файле в `%LOCALAPPDATA%\Leash`, который по умолчанию доступен только
//! этому пользователю (и администраторам). Клиент первой строкой шлёт токен;
//! без него соединение закрывается, ничего не прочитав. Граница доверия та
//! же, что у сокета: учётная запись пользователя. Так обходится без WinAPI и
//! `unsafe`: в std нет именованных каналов.

use std::io;

#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;

/// Ушёл ли собеседник. Пока идёт вызов, MCP-клиент ничего не шлёт (он ждёт
/// ответа), поэтому конец потока, ошибка или лишние данные — «сеанс кончен».
pub fn gone(conn: &Stream) -> bool {
    use std::io::Read;
    if conn.set_nonblocking(true).is_err() {
        return true;
    }
    let mut byte = [0u8; 1];
    let result = (&*conn).read(&mut byte);
    let restored = conn.set_nonblocking(false).is_ok();
    !restored || !matches!(result, Err(ref e) if e.kind() == io::ErrorKind::WouldBlock)
}

/// Слушатель канала. Адрес (`endpoint`) убирает тот, кто вызвал `bind`.
pub struct Listener {
    inner: Inner,
}

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;

    pub type Stream = UnixStream;
    pub(super) type Inner = UnixListener;

    /// Слушать `endpoint`. Отказ, если там уже отвечает другой мост.
    pub fn bind(endpoint: &Path) -> io::Result<super::Listener> {
        if UnixStream::connect(endpoint).is_ok() {
            return Err(io::Error::other(
                "мост уже запущен другим экземпляром Firefox",
            ));
        }
        let _ = fs::remove_file(endpoint);
        let inner = UnixListener::bind(endpoint)?;
        fs::set_permissions(endpoint, fs::Permissions::from_mode(0o600))?;
        Ok(super::Listener { inner })
    }

    pub fn connect(endpoint: &Path) -> io::Result<Stream> {
        UnixStream::connect(endpoint)
    }

    impl super::Listener {
        pub fn accept(&self) -> io::Result<Stream> {
            self.inner.accept().map(|(s, _)| s)
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::collections::hash_map::RandomState;
    use std::fs;
    use std::hash::{BuildHasher, Hasher};
    use std::io::{self, Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::path::Path;
    use std::time::Duration;

    pub type Stream = TcpStream;
    pub(super) type Inner = (TcpListener, String);

    /// Сколько ждать токен от только что подключившегося клиента.
    const AUTH_WAIT: Duration = Duration::from_secs(2);
    const TOKEN_LEN: usize = 64;

    /// 256 бит выхода SipHash с ключами `RandomState`. std берёт ключи из
    /// системного генератора (ProcessPrng) один раз на поток и дальше меняет
    /// только k0; k1 остаётся секретным, поэтому без ключей выход не угадать.
    fn token() -> String {
        (0..4)
            .map(|i| {
                let mut h = RandomState::new().build_hasher();
                h.write_u64(i);
                format!("{:016x}", h.finish())
            })
            .collect()
    }

    /// Порт и токен из файла адреса: `"<порт> <токен>\n"`.
    fn read_endpoint(endpoint: &Path) -> io::Result<(u16, String)> {
        let meta = fs::symlink_metadata(endpoint)?;
        if !meta.is_file() {
            return Err(io::Error::other("файл адреса моста не обычный файл"));
        }
        let text = fs::read_to_string(endpoint)?;
        let mut parts = text.split_whitespace();
        let port = parts.next().and_then(|p| p.parse().ok());
        let token = parts.next().filter(|t| t.len() == TOKEN_LEN);
        match (port, token) {
            (Some(port), Some(token)) => Ok((port, token.to_owned())),
            _ => Err(io::Error::other("файл адреса моста повреждён")),
        }
    }

    fn connect_to(port: u16, token: &str) -> io::Result<Stream> {
        let mut s = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
        s.set_nodelay(true)?;
        s.write_all(format!("{token}\n").as_bytes())?;
        Ok(s)
    }

    pub fn connect(endpoint: &Path) -> io::Result<Stream> {
        let (port, token) = read_endpoint(endpoint)?;
        connect_to(port, &token)
    }

    /// Слушать 127.0.0.1 и записать адрес в `endpoint`. Отказ, если по
    /// старому адресу ещё отвечает другой мост.
    pub fn bind(endpoint: &Path) -> io::Result<super::Listener> {
        if let Ok((port, _)) = read_endpoint(endpoint)
            && TcpStream::connect_timeout(
                &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                Duration::from_millis(300),
            )
            .is_ok()
        {
            return Err(io::Error::other(
                "мост уже запущен другим экземпляром Firefox",
            ));
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        let token = token();
        let _ = fs::remove_file(endpoint);
        // create_new: если между удалением и записью кто-то подложил файл
        // или ссылку, запись не пойдёт по ней.
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(endpoint)?;
        f.write_all(format!("{port} {token}\n").as_bytes())?;
        Ok(super::Listener {
            inner: (listener, token),
        })
    }

    /// Первая строка соединения должна быть токеном. Читается побайтно, чтобы
    /// не забрать в буфер начало первого запроса.
    fn authenticated(s: &mut Stream, token: &str) -> bool {
        if s.set_read_timeout(Some(AUTH_WAIT)).is_err() {
            return false;
        }
        let mut got = Vec::with_capacity(TOKEN_LEN);
        let mut byte = [0u8; 1];
        loop {
            match s.read(&mut byte) {
                Ok(1) if byte[0] == b'\n' => break,
                Ok(1) if got.len() < TOKEN_LEN => got.push(byte[0]),
                _ => return false,
            }
        }
        // Сравнение без раннего выхода.
        let same = got.len() == token.len()
            && got
                .iter()
                .zip(token.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0;
        same && s.set_read_timeout(None).is_ok()
    }

    impl super::Listener {
        /// Следующее соединение с верным токеном; остальные закрываются.
        pub fn accept(&self) -> io::Result<Stream> {
            let (listener, token) = &self.inner;
            loop {
                let (mut s, peer) = listener.accept()?;
                if !peer.ip().is_loopback() {
                    continue;
                }
                if authenticated(&mut s, token) {
                    s.set_nodelay(true)?;
                    return Ok(s);
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::paths::tests::TempHome;

        #[test]
        fn wrong_or_missing_token_is_dropped() {
            let home = TempHome::new("tk");
            let endpoint = home.0.join("host.port");
            let l = bind(&endpoint).unwrap();
            let (port, token) = read_endpoint(&endpoint).unwrap();
            let accepted = std::thread::spawn(move || {
                let mut s = l.accept().unwrap();
                let mut line = String::new();
                io::BufRead::read_line(&mut io::BufReader::new(&mut s), &mut line).unwrap();
                line
            });
            // Чужой: неверный токен, потом HTTP-запрос — оба закрыты без ответа.
            let mut bad = connect_to(port, &"0".repeat(TOKEN_LEN)).unwrap();
            let _ = bad.write_all(b"x\n");
            let mut http = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
            let _ = http.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            let mut good = connect_to(port, &token).unwrap();
            good.write_all(b"hello\n").unwrap();
            assert_eq!(accepted.join().unwrap(), "hello\n");
        }

        #[test]
        fn tokens_differ() {
            assert_ne!(token(), token());
            assert_eq!(token().len(), TOKEN_LEN);
        }
    }
}
