//! Кадры обоих каналов моста.
//!
//! Firefox (native messaging): длина u32 в порядке байтов платформы, затем
//! JSON в UTF-8. Сокет и MCP: одна JSON-строка на сообщение. Размеры
//! ограничены: вход из любого канала считается недоверенным.

use std::io::{self, BufRead, Read, Write};

use leash_core::json::{Value, parse_json};

/// Предел сообщения от Firefox: снимок страницы с запасом.
pub const MAX_FROM_FIREFOX: usize = 8 << 20;
/// Предел Firefox для сообщений от приложения.
pub const MAX_TO_FIREFOX: usize = 1 << 20;
/// Предел строки сокета и MCP.
pub const MAX_LINE: usize = 8 << 20;

fn invalid(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.to_owned())
}

/// Кадр от Firefox. `None` — Firefox закрыл канал между кадрами.
pub fn read_native(r: &mut impl Read) -> io::Result<Option<Value>> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match r.read(&mut len[got..])? {
            0 if got == 0 => return Ok(None),
            0 => return Err(invalid("обрыв заголовка кадра")),
            n => got += n,
        }
    }
    let len = u32::from_ne_bytes(len) as usize;
    if len > MAX_FROM_FIREFOX {
        return Err(invalid("кадр больше предела"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    let text = std::str::from_utf8(&body).map_err(|_| invalid("кадр не UTF-8"))?;
    parse_json(text)
        .map(Some)
        .ok_or_else(|| invalid("кадр не JSON"))
}

/// Кадр в Firefox.
pub fn write_native(w: &mut impl Write, v: &Value) -> io::Result<()> {
    let json = v.to_json();
    if json.len() > MAX_TO_FIREFOX {
        return Err(invalid("кадр больше предела Firefox"));
    }
    // Длина меньше 1 МиБ, в u32 помещается.
    w.write_all(&(json.len() as u32).to_ne_bytes())?;
    w.write_all(json.as_bytes())?;
    w.flush()
}

/// Строка до `\n` не длиннее `MAX_LINE`. `None` — конец потока.
pub fn read_line(r: &mut impl BufRead) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    let n = r
        .by_ref()
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    } else if buf.len() > MAX_LINE {
        return Err(invalid("строка больше предела"));
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| invalid("строка не UTF-8"))
}

/// Сообщение одной строкой. `to_json` экранирует переводы строк внутри
/// строк, поэтому сообщение всегда занимает ровно одну строку.
pub fn write_line(w: &mut impl Write, v: &Value) -> io::Result<()> {
    let mut json = v.to_json();
    json.push('\n');
    w.write_all(json.as_bytes())?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn native_roundtrip() {
        let v = Value::obj(vec![("id", Value::Num(1.0)), ("t", Value::str("а\nб"))]);
        let mut buf = Vec::new();
        write_native(&mut buf, &v).unwrap();
        write_native(&mut buf, &Value::Null).unwrap();
        let mut r = Cursor::new(buf);
        assert_eq!(read_native(&mut r).unwrap(), Some(v));
        assert_eq!(read_native(&mut r).unwrap(), Some(Value::Null));
        assert_eq!(read_native(&mut r).unwrap(), None);
    }

    #[test]
    fn native_rejects_bad_frames() {
        let frame = |len: u32, body: &[u8]| {
            let mut b = len.to_ne_bytes().to_vec();
            b.extend_from_slice(body);
            Cursor::new(b)
        };
        assert!(read_native(&mut frame(MAX_FROM_FIREFOX as u32 + 1, b"")).is_err());
        assert!(read_native(&mut frame(5, b"{}")).is_err(), "обрыв тела");
        assert!(read_native(&mut frame(2, b"\xff\xfe")).is_err(), "не UTF-8");
        assert!(read_native(&mut frame(3, b"{a}")).is_err(), "не JSON");
        assert!(
            read_native(&mut Cursor::new(vec![1u8, 0])).is_err(),
            "обрыв длины"
        );
    }

    #[test]
    fn native_refuses_oversized_output() {
        let big = Value::str("x".repeat(MAX_TO_FIREFOX));
        assert!(write_native(&mut Vec::new(), &big).is_err());
    }

    #[test]
    fn lines() {
        let mut r = Cursor::new(b"{\"a\":1}\r\n\n{}".to_vec());
        assert_eq!(read_line(&mut r).unwrap().as_deref(), Some("{\"a\":1}"));
        assert_eq!(read_line(&mut r).unwrap().as_deref(), Some(""));
        assert_eq!(read_line(&mut r).unwrap().as_deref(), Some("{}"));
        assert_eq!(read_line(&mut r).unwrap(), None);

        let long = vec![b'x'; MAX_LINE + 10];
        assert!(read_line(&mut Cursor::new(long)).is_err());

        let mut out = Vec::new();
        write_line(&mut out, &Value::str("a\nb")).unwrap();
        assert_eq!(out, b"\"a\\nb\"\n");
    }
}
