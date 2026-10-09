//! Данные без кода: дерево JSON-значений.
//!
//! Всё, что приходит из JS (ответ API, результат content-скрипта), сначала
//! переводится сюда с бюджетом на глубину и размер, а разбирается уже нативно
//! и тестируется без браузера. Тела запросов к API собираются тоже здесь.

use js_sys::{Array, Object, Reflect};
use wasm_bindgen::JsValue;

/// Бюджет на одно преобразование из JS.
const MAX_DEPTH: usize = 12;
const MAX_NODES: usize = 50_000;
const MAX_STRING_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl Value {
    pub(crate) fn obj(fields: Vec<(&str, Value)>) -> Self {
        Self::Obj(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }

    pub(crate) fn str(s: impl Into<String>) -> Self {
        Self::Str(s.into())
    }

    pub(crate) fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub(crate) fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Num(n) => Some(*n),
            _ => None,
        }
    }

    /// Целое в диапазоне; дробные, NaN и бесконечности отклоняются.
    pub(crate) fn as_uint(&self, max: u64) -> Option<u64> {
        let n = self.as_f64()?;
        // Диапазон проверен до приведения, усечения нет.
        (n.fract() == 0.0 && n >= 0.0 && n <= max as f64).then_some(n as u64)
    }

    pub(crate) fn as_arr(&self) -> Option<&[Value]> {
        match self {
            Self::Arr(items) => Some(items),
            _ => None,
        }
    }

    /// Объект ровно с этими ключами, в любом порядке.
    pub(crate) fn has_exact_keys(&self, expected: &[&str]) -> bool {
        match self {
            Self::Obj(fields) => {
                fields.len() == expected.len()
                    && expected.iter().all(|e| fields.iter().any(|(k, _)| k == e))
            }
            _ => false,
        }
    }

    pub(crate) fn to_json(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out);
        out
    }

    fn write_json(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Self::Num(n) if !n.is_finite() => out.push_str("null"),
            Self::Num(n) if n.fract() == 0.0 && n.abs() < 9.0e15 => {
                // Целое в пределах точности f64: печатается без ".0".
                out.push_str(&format!("{}", *n as i64));
            }
            Self::Num(n) => out.push_str(&format!("{n}")),
            Self::Str(s) => write_json_str(s, out),
            Self::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_json(out);
                }
                out.push(']');
            }
            Self::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_json_str(k, out);
                    out.push(':');
                    v.write_json(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_json_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Управляющие символы и разделители строк JS — только escape-ом.
            c if (c as u32) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Budget {
    nodes: usize,
    string_bytes: usize,
}

/// Перевод из JS. `None`, если значение не данные (функция, символ, BigInt)
/// или превышен бюджет.
pub(crate) fn from_js(value: &JsValue) -> Option<Value> {
    let mut budget = Budget {
        nodes: 0,
        string_bytes: 0,
    };
    convert(value, 0, &mut budget)
}

fn convert(value: &JsValue, depth: usize, budget: &mut Budget) -> Option<Value> {
    budget.nodes += 1;
    if depth > MAX_DEPTH || budget.nodes > MAX_NODES {
        return None;
    }
    if value.is_null() || value.is_undefined() {
        return Some(Value::Null);
    }
    if let Some(b) = value.as_bool() {
        return Some(Value::Bool(b));
    }
    if let Some(n) = value.as_f64() {
        return Some(Value::Num(n));
    }
    if let Some(s) = value.as_string() {
        budget.string_bytes += s.len();
        return (budget.string_bytes <= MAX_STRING_BYTES).then_some(Value::Str(s));
    }
    if Array::is_array(value) {
        let arr = Array::from(value);
        let mut items = Vec::new();
        for item in arr.iter() {
            items.push(convert(&item, depth + 1, budget)?);
        }
        return Some(Value::Arr(items));
    }
    if value.is_object() && !value.is_function() {
        let obj = Object::from(value.clone());
        let mut fields = Vec::new();
        for key in Object::keys(&obj).iter() {
            let name = key.as_string()?;
            budget.string_bytes += name.len();
            let field = Reflect::get(value, &key).ok()?;
            fields.push((name, convert(&field, depth + 1, budget)?));
        }
        return Some(Value::Obj(fields));
    }
    None
}

/// Разбор JSON-текста (строгий RFC 8259) с тем же бюджетом, что у `from_js`.
/// Повторяющиеся ключи отклоняются: JS взял бы последний, `get` — первый,
/// и два разборщика увидели бы разные данные.
pub(crate) fn parse_json(text: &str) -> Option<Value> {
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
        budget: Budget {
            nodes: 0,
            string_bytes: 0,
        },
    };
    let v = p.value(0)?;
    p.ws();
    (p.i == p.s.len()).then_some(v)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    budget: Budget,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &[u8]) -> Option<()> {
        self.s
            .get(self.i..)?
            .starts_with(lit)
            .then(|| self.i += lit.len())
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        self.budget.nodes += 1;
        if depth > MAX_DEPTH || self.budget.nodes > MAX_NODES {
            return None;
        }
        self.ws();
        match self.peek()? {
            b'n' => self.eat(b"null").map(|()| Value::Null),
            b't' => self.eat(b"true").map(|()| Value::Bool(true)),
            b'f' => self.eat(b"false").map(|()| Value::Bool(false)),
            b'"' => self.string().map(Value::Str),
            b'[' => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Some(Value::Arr(items));
                }
                loop {
                    items.push(self.value(depth + 1)?);
                    self.ws();
                    match self.peek()? {
                        b',' => self.i += 1,
                        b']' => {
                            self.i += 1;
                            return Some(Value::Arr(items));
                        }
                        _ => return None,
                    }
                }
            }
            b'{' => {
                self.i += 1;
                let mut fields: Vec<(String, Value)> = Vec::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Some(Value::Obj(fields));
                }
                loop {
                    self.ws();
                    if self.peek()? != b'"' {
                        return None;
                    }
                    let key = self.string()?;
                    if fields.iter().any(|(k, _)| *k == key) {
                        return None;
                    }
                    self.ws();
                    self.eat(b":")?;
                    let v = self.value(depth + 1)?;
                    fields.push((key, v));
                    self.ws();
                    match self.peek()? {
                        b',' => self.i += 1,
                        b'}' => {
                            self.i += 1;
                            return Some(Value::Obj(fields));
                        }
                        _ => return None,
                    }
                }
            }
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Option<Value> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek()? {
            b'0' => self.i += 1,
            b'1'..=b'9' => {
                self.digits();
            }
            _ => return None,
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return None;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return None;
            }
        }
        // Срез — только ASCII по грамматике выше.
        let text = std::str::from_utf8(&self.s[start..self.i]).ok()?;
        text.parse::<f64>()
            .ok()
            .filter(|n| n.is_finite())
            .map(Value::Num)
    }

    fn hex4(&mut self) -> Option<u32> {
        let h = self.s.get(self.i..self.i + 4)?;
        let h = std::str::from_utf8(h).ok()?;
        if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        self.i += 4;
        u32::from_str_radix(h, 16).ok()
    }

    fn string(&mut self) -> Option<String> {
        self.i += 1; // открывающая кавычка
        let mut out = String::new();
        loop {
            let start = self.i;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.i += 1;
            }
            // Вход — &str, а границы среза стоят на ASCII-байтах.
            out.push_str(std::str::from_utf8(&self.s[start..self.i]).ok()?);
            match self.peek()? {
                b'"' => {
                    self.i += 1;
                    break;
                }
                b'\\' => {
                    self.i += 1;
                    let c = match self.peek()? {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            self.i += 1;
                            let hi = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&hi) {
                                self.eat(b"\\u")?;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return None;
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            // Одиночная суррогатная половина — не символ.
                            out.push(char::from_u32(code)?);
                            continue;
                        }
                        _ => return None,
                    };
                    self.i += 1;
                    out.push(c);
                }
                _ => return None, // управляющий символ без escape
            }
        }
        self.budget.string_bytes += out.len();
        (self.budget.string_bytes <= MAX_STRING_BYTES).then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_output() {
        let v = Value::obj(vec![
            ("a", Value::Num(1.0)),
            ("b", Value::Num(1.5)),
            ("c", Value::str("q\"\\\n\u{1}\u{2028}я")),
            (
                "d",
                Value::Arr(vec![Value::Null, Value::Bool(true), Value::Num(f64::NAN)]),
            ),
        ]);
        assert_eq!(
            v.to_json(),
            r#"{"a":1,"b":1.5,"c":"q\"\\\n\u0001\u2028я","d":[null,true,null]}"#
        );
    }

    #[test]
    fn accessors() {
        let v = Value::obj(vec![("n", Value::Num(3.0)), ("s", Value::str("x"))]);
        assert_eq!(v.get("n").and_then(|n| n.as_uint(10)), Some(3));
        assert_eq!(v.get("n").and_then(|n| n.as_uint(2)), None);
        assert_eq!(Value::Num(1.5).as_uint(10), None);
        assert_eq!(Value::Num(-1.0).as_uint(10), None);
        assert_eq!(Value::Num(f64::NAN).as_uint(10), None);
        assert!(v.has_exact_keys(&["s", "n"]));
        assert!(!v.has_exact_keys(&["s"]));
        assert!(!Value::Null.has_exact_keys(&[]));
    }

    // Hardened test coverage: value.rs JSON serialization
    #[test]
    fn all_control_chars_escaped() {
        // Test all control chars 0x00-0x1F
        for code in 0..32u8 {
            let c = code as char;
            let s = format!("a{}b", c);
            let v = Value::str(&s);
            let json = v.to_json();
            // Should contain escape sequence, not raw char
            if c == '\n' {
                assert!(json.contains("\\n"), "char {:02x}", code);
            } else if c == '\r' {
                assert!(json.contains("\\r"), "char {:02x}", code);
            } else if c == '\t' {
                assert!(json.contains("\\t"), "char {:02x}", code);
            } else if c == '"' {
                assert!(json.contains("\\\""), "char {:02x}", code);
            } else if c == '\\' {
                assert!(json.contains("\\\\"), "char {:02x}", code);
            } else {
                // Other controls should be \uXXXX
                assert!(json.contains("\\u"), "char {:02x}", code);
            }
        }
    }

    #[test]
    fn line_and_paragraph_separators_escaped() {
        // U+2028 (line separator) and U+2029 (paragraph separator)
        let v = Value::str("a\u{2028}b\u{2029}c");
        let json = v.to_json();
        assert!(json.contains("\\u2028"));
        assert!(json.contains("\\u2029"));
    }

    #[test]
    fn number_edge_cases() {
        // -0.0 should format as "0"
        let v = Value::Num(-0.0);
        assert_eq!(v.to_json(), "0");

        // Very large number that triggers scientific notation
        let v = Value::Num(1e21);
        let json = v.to_json();
        // Should contain 'e' in output (scientific notation)
        assert!(json.contains('e') || json.parse::<f64>().unwrap() == 1e21);

        // 9e15 boundary - this is within f64 integer precision
        let v = Value::Num(9e15);
        let json = v.to_json();
        // Round-trip test
        assert_eq!(json.parse::<f64>().unwrap(), 9e15);

        // 1.5e-7 - very small number
        let v = Value::Num(1.5e-7);
        let json = v.to_json();
        assert_eq!(json.parse::<f64>().unwrap(), 1.5e-7, "got: {json}");

        // i64 overflow representation: larger than i64::MAX
        let large = (i64::MAX as f64) * 2.0;
        let v = Value::Num(large);
        let json = v.to_json();
        // Should be valid JSON (not panic)
        assert!(!json.is_empty());
    }

    #[test]
    fn infinity_and_nan_become_null() {
        // NaN → null
        let v = Value::Num(f64::NAN);
        assert_eq!(v.to_json(), "null");

        // Infinity → null
        let v = Value::Num(f64::INFINITY);
        assert_eq!(v.to_json(), "null");

        // -Infinity → null
        let v = Value::Num(f64::NEG_INFINITY);
        assert_eq!(v.to_json(), "null");
    }

    #[test]
    fn integer_formatting_precision() {
        // Within i64 range and representable: no .0
        let v = Value::Num(42.0);
        assert_eq!(v.to_json(), "42");

        // Fractional part is zero but number has it: should still be no .0
        let v = Value::Num(1_000_000.0);
        assert_eq!(v.to_json(), "1000000");

        // Exceeds i64::MAX: use f64 formatting with potential e notation
        let v = Value::Num((i64::MAX as f64) + 1.0);
        let json = v.to_json();
        assert_eq!(
            json.parse::<f64>().unwrap(),
            (i64::MAX as f64) + 1.0,
            "got: {json}"
        );
    }

    #[test]
    fn string_escaping_quotes_and_backslash() {
        // Quote escaping
        let v = Value::str("\"hello\"");
        assert_eq!(v.to_json(), r#""\"hello\"""#);

        // Backslash escaping
        let v = Value::str("a\\b");
        assert_eq!(v.to_json(), r#""a\\b""#);

        // Mixed
        let v = Value::str("say \"hi\\there\"");
        assert_eq!(v.to_json(), r#""say \"hi\\there\"""#);
    }

    #[test]
    fn key_escaping_in_objects() {
        let v = Value::obj(vec![
            ("a\"b", Value::Num(1.0)),
            ("c\\d", Value::Num(2.0)),
            ("e\nf", Value::Num(3.0)),
        ]);
        let json = v.to_json();
        // All keys should be properly escaped
        assert!(json.contains(r#"\"#)); // quote escape
        assert!(json.contains(r#"\\"#)); // backslash escape
        assert!(json.contains(r#"\n"#)); // newline escape
    }

    #[test]
    fn deep_nesting_output() {
        // Create deeply nested structure
        let mut v = Value::Null;
        for _ in 0..10 {
            v = Value::Arr(vec![v]);
        }
        let json = v.to_json();
        // Should not panic, should be valid
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
        let open_brackets = json.matches('[').count();
        let close_brackets = json.matches(']').count();
        assert_eq!(open_brackets, close_brackets);
    }

    #[test]
    fn as_uint_boundaries() {
        // Exact 0
        assert_eq!(Value::Num(0.0).as_uint(10), Some(0));

        // Exact max
        assert_eq!(Value::Num(10.0).as_uint(10), Some(10));

        // One below max
        assert_eq!(Value::Num(9.0).as_uint(10), Some(9));

        // One above max
        assert_eq!(Value::Num(11.0).as_uint(10), None);

        // Negative
        assert_eq!(Value::Num(-1.0).as_uint(100), None);

        // Fractional
        assert_eq!(Value::Num(1.5).as_uint(10), None);

        // NaN
        assert_eq!(Value::Num(f64::NAN).as_uint(10), None);

        // Infinity
        assert_eq!(Value::Num(f64::INFINITY).as_uint(10), None);

        // Very large max
        assert_eq!(Value::Num(1e15).as_uint(u64::MAX), Some(1e15 as u64));

        // Exceeds u64 max
        assert_eq!(Value::Num((u64::MAX as f64) * 2.0).as_uint(u64::MAX), None);
    }

    // Simple round-trip JSON validator for structural checks
    fn validate_json_structure(json: &str) -> bool {
        let mut depth = 0i32;
        let mut in_string = false;
        let mut escape_next = false;

        for c in json.chars() {
            if escape_next {
                escape_next = false;
                continue;
            }
            match c {
                '\\' if in_string => escape_next = true,
                '"' => in_string = !in_string,
                '{' | '[' if !in_string => depth += 1,
                '}' | ']' if !in_string => depth -= 1,
                _ => {}
            }
            if depth < 0 {
                return false;
            }
        }
        depth == 0 && !in_string && !escape_next
    }

    #[test]
    fn json_output_always_valid_structure() {
        let test_values = vec![
            Value::Null,
            Value::Bool(true),
            Value::Bool(false),
            Value::Num(0.0),
            Value::Num(-1.5),
            Value::Num(f64::NAN),
            Value::str(""),
            Value::str("hello"),
            Value::str("with\nnewline\tand\rcarriage"),
            Value::str("with\"quote"),
            Value::Arr(vec![]),
            Value::Arr(vec![Value::Num(1.0), Value::Num(2.0)]),
            Value::Arr(vec![Value::Arr(vec![Value::Null])]),
            Value::obj(vec![]),
            Value::obj(vec![("key", Value::str("value"))]),
            Value::obj(vec![("a", Value::Num(1.0)), ("b", Value::Arr(vec![]))]),
        ];

        for v in test_values {
            let json = v.to_json();
            assert!(
                validate_json_structure(&json),
                "invalid structure for {v:?}: {json}"
            );
        }
    }

    #[test]
    fn complex_nested_structure_with_all_types() {
        let v = Value::obj(vec![
            ("null_field", Value::Null),
            ("bool_true", Value::Bool(true)),
            ("bool_false", Value::Bool(false)),
            ("number", Value::Num(42.5)),
            ("string", Value::str("test\nwith\"escapes")),
            (
                "array",
                Value::Arr(vec![
                    Value::Num(1.0),
                    Value::str("nested"),
                    Value::Bool(false),
                ]),
            ),
            (
                "nested_obj",
                Value::obj(vec![
                    ("inner", Value::Num(99.0)),
                    ("inner_str", Value::str("deep")),
                ]),
            ),
        ]);

        let json = v.to_json();
        // Should be valid JSON
        assert!(validate_json_structure(&json));
        // Should contain all the types
        assert!(json.contains("null"));
        assert!(json.contains("true"));
        assert!(json.contains("false"));
        assert!(json.contains("42.5"));
        assert!(json.contains("test"));
        assert!(json.contains(r#"\n"#));
    }

    #[test]
    fn parse_json_accepts_valid() {
        let v = parse_json(r#" {"a":[1,-2.5e2,0,true,false,null],"b":"q\"\\\/\b\f\n\r\t\u0041\u044f\ud83d\ude00","c":{}} "#)
            .unwrap();
        assert_eq!(
            v,
            Value::obj(vec![
                (
                    "a",
                    Value::Arr(vec![
                        Value::Num(1.0),
                        Value::Num(-250.0),
                        Value::Num(0.0),
                        Value::Bool(true),
                        Value::Bool(false),
                        Value::Null,
                    ])
                ),
                ("b", Value::str("q\"\\/\u{8}\u{c}\n\r\tAя😀")),
                ("c", Value::Obj(vec![])),
            ])
        );
        assert_eq!(parse_json("[]"), Some(Value::Arr(vec![])));
        assert_eq!(parse_json("\"я\""), Some(Value::str("я")));
    }

    #[test]
    fn parse_json_roundtrip() {
        let v = Value::obj(vec![
            ("s", Value::str("\u{1}\u{2028}<>\"")),
            ("n", Value::Num(1.5)),
            ("a", Value::Arr(vec![Value::Null, Value::Obj(vec![])])),
        ]);
        assert_eq!(parse_json(&v.to_json()), Some(v));
    }

    #[test]
    fn parse_json_rejects_invalid() {
        for bad in [
            "",
            " ",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "{a:1}",
            "{'a':1}",
            "01",
            "1.",
            ".5",
            "+1",
            "1e",
            "-",
            "NaN",
            "Infinity",
            "1e999",
            "tru",
            "nul",
            "\"a",
            "\"\\x\"",
            "\"\\u12\"",
            "\"\\ud800\"",
            "\"\\udc00\"",
            "\"\\ud800\\u0041\"",
            "\"a\nb\"",
            "\"\t\"",
            "1 2",
            "{} x",
            "{\"a\":1,\"a\":2}",
            "[1 2]",
            "{\"a\" 1}",
        ] {
            assert_eq!(parse_json(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn parse_json_budget() {
        let deep = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
        assert_eq!(parse_json(&deep), None);
        let ok = "[".repeat(MAX_DEPTH) + &"]".repeat(MAX_DEPTH);
        assert!(parse_json(&ok).is_some());
        let many = format!("[{}0]", "0,".repeat(MAX_NODES));
        assert_eq!(parse_json(&many), None);
        let big = format!("[\"{0}\",\"{0}\"]", "x".repeat(MAX_STRING_BYTES / 2 + 1));
        assert_eq!(parse_json(&big), None);
    }
}
