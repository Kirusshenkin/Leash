//! Инструменты модели. Модель только предлагает вызов; здесь он разбирается
//! строго (точный набор полей, типы, диапазоны), а решение «можно ли»
//! принимает `guard`.

use crate::json::Value;

/// Предел номера элемента и вкладки.
const MAX_ID: u64 = 100_000;
/// Предел текста, который модель может ввести за один вызов.
pub const MAX_TYPE_CHARS: usize = 2_000;
const MAX_OPTION_CHARS: usize = 200;
const MAX_URL_CHARS: usize = 2_048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Up,
    Down,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolCall {
    ReadPage,
    Click {
        element: u32,
    },
    TypeText {
        element: u32,
        text: String,
        submit: bool,
    },
    SelectOption {
        element: u32,
        option: String,
    },
    Scroll {
        direction: Direction,
    },
    Navigate {
        url: String,
    },
    GoBack,
    ListTabs,
    SwitchTab {
        tab: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolError {
    UnknownTool,
    BadInput(&'static str),
}

impl ToolError {
    pub fn describe(self) -> String {
        match self {
            Self::UnknownTool => "Неизвестный инструмент.".into(),
            Self::BadInput(why) => format!("Неверные параметры: {why}."),
        }
    }
}

pub fn parse(name: &str, input: &Value) -> Result<ToolCall, ToolError> {
    let keys = |expected: &[&str]| {
        if input.has_exact_keys(expected) {
            Ok(())
        } else {
            Err(ToolError::BadInput("набор полей не совпадает со схемой"))
        }
    };
    let id = |key: &str| {
        input
            .get(key)
            .and_then(|v| v.as_uint(MAX_ID))
            .filter(|n| *n >= 1)
            // MAX_ID меньше u32::MAX.
            .map(|n| n as u32)
            .ok_or(ToolError::BadInput("номер должен быть целым от 1"))
    };
    let text = |key: &str, max: usize| {
        let s = input
            .get(key)
            .and_then(Value::as_str)
            .ok_or(ToolError::BadInput("ожидается строка"))?;
        if s.chars().count() > max {
            return Err(ToolError::BadInput("строка слишком длинная"));
        }
        // Разделители строк JS и управление направлением текста визуально
        // подменяют введённое на сайте; принимаются только перевод строки и табуляция.
        if s.chars().any(|c| {
            (c.is_control() && c != '\n' && c != '\t')
                || matches!(c, '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        }) {
            return Err(ToolError::BadInput("управляющие символы в строке"));
        }
        Ok(s.to_owned())
    };
    match name {
        "read_page" => keys(&[]).map(|()| ToolCall::ReadPage),
        "click" => {
            keys(&["element"])?;
            Ok(ToolCall::Click {
                element: id("element")?,
            })
        }
        "type_text" => {
            keys(&["element", "text", "submit"])?;
            let submit = input
                .get("submit")
                .and_then(Value::as_bool)
                .ok_or(ToolError::BadInput("submit должен быть true или false"))?;
            Ok(ToolCall::TypeText {
                element: id("element")?,
                text: text("text", MAX_TYPE_CHARS)?,
                submit,
            })
        }
        "select_option" => {
            keys(&["element", "option"])?;
            Ok(ToolCall::SelectOption {
                element: id("element")?,
                option: text("option", MAX_OPTION_CHARS)?,
            })
        }
        "scroll" => {
            keys(&["direction"])?;
            let direction = match input.get("direction").and_then(Value::as_str) {
                Some("up") => Direction::Up,
                Some("down") => Direction::Down,
                _ => return Err(ToolError::BadInput("direction: up или down")),
            };
            Ok(ToolCall::Scroll { direction })
        }
        "navigate" => {
            keys(&["url"])?;
            Ok(ToolCall::Navigate {
                url: text("url", MAX_URL_CHARS)?,
            })
        }
        "go_back" => keys(&[]).map(|()| ToolCall::GoBack),
        "list_tabs" => keys(&[]).map(|()| ToolCall::ListTabs),
        "switch_tab" => {
            keys(&["tab"])?;
            Ok(ToolCall::SwitchTab { tab: id("tab")? })
        }
        _ => Err(ToolError::UnknownTool),
    }
}

/// Короткое описание вызова для журнала в панели.
pub fn summary(call: &ToolCall) -> String {
    match call {
        ToolCall::ReadPage => "читаю страницу".into(),
        ToolCall::Click { element } => format!("нажать [{element}]"),
        ToolCall::TypeText {
            element, submit, ..
        } => {
            if *submit {
                format!("ввести текст в [{element}] и отправить")
            } else {
                format!("ввести текст в [{element}]")
            }
        }
        ToolCall::SelectOption { element, .. } => format!("выбрать вариант в [{element}]"),
        ToolCall::Scroll {
            direction: Direction::Up,
        } => "прокрутить вверх".into(),
        ToolCall::Scroll {
            direction: Direction::Down,
        } => "прокрутить вниз".into(),
        ToolCall::Navigate { .. } => "перейти по адресу".into(),
        ToolCall::GoBack => "назад".into(),
        ToolCall::ListTabs => "список вкладок".into(),
        ToolCall::SwitchTab { tab } => format!("перейти во вкладку {tab}"),
    }
}

fn schema(props: Vec<(&str, Value)>, required: &[&str]) -> Value {
    Value::obj(vec![
        ("type", Value::str("object")),
        ("properties", Value::obj(props)),
        (
            "required",
            Value::Arr(required.iter().map(|r| Value::str(*r)).collect()),
        ),
        ("additionalProperties", Value::Bool(false)),
    ])
}

fn prop(kind: &str, description: &str) -> Value {
    Value::obj(vec![
        ("type", Value::str(kind)),
        ("description", Value::str(description)),
    ])
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    Value::obj(vec![
        ("name", Value::str(name)),
        ("description", Value::str(description)),
        ("input_schema", input_schema),
    ])
}

/// Описание инструментов для API.
pub fn definitions() -> Value {
    let element = || prop("integer", "Номер элемента из последнего снимка read_page.");
    Value::Arr(vec![
        tool(
            "read_page",
            "Снимок текущей вкладки: адрес, заголовок, интерактивные элементы с номерами и видимый текст. \
Номера действуют до следующего снимка. Вызывай перед действиями и после каждого действия, \
которое меняет страницу.",
            schema(vec![], &[]),
        ),
        tool(
            "click",
            "Нажать на элемент. Отправка форм, покупки, удаление, публикация и похожие действия \
требуют подтверждения пользователя.",
            schema(vec![("element", element())], &["element"]),
        ),
        tool(
            "type_text",
            "Ввести текст в поле, заменив его содержимое. submit=true отправляет форму (нужно подтверждение).",
            schema(
                vec![
                    ("element", element()),
                    ("text", prop("string", "Текст, не длиннее 2000 символов.")),
                    ("submit", prop("boolean", "Отправить форму после ввода.")),
                ],
                &["element", "text", "submit"],
            ),
        ),
        tool(
            "select_option",
            "Выбрать вариант в выпадающем списке по его тексту.",
            schema(
                vec![
                    ("element", element()),
                    ("option", prop("string", "Текст варианта, как в снимке.")),
                ],
                &["element", "option"],
            ),
        ),
        tool(
            "scroll",
            "Прокрутить страницу на экран вверх или вниз.",
            schema(
                vec![(
                    "direction",
                    Value::obj(vec![
                        ("type", Value::str("string")),
                        (
                            "enum",
                            Value::Arr(vec![Value::str("up"), Value::str("down")]),
                        ),
                    ]),
                )],
                &["direction"],
            ),
        ),
        tool(
            "navigate",
            "Открыть https-адрес в текущей вкладке. Работает только для сайтов, разрешённых пользователем.",
            schema(
                vec![("url", prop("string", "Полный https-адрес."))],
                &["url"],
            ),
        ),
        tool(
            "go_back",
            "Вернуться на предыдущую страницу вкладки.",
            schema(vec![], &[]),
        ),
        tool(
            "list_tabs",
            "Список вкладок этого окна. Содержимое вкладок закрытых сайтов не показывается.",
            schema(vec![], &[]),
        ),
        tool(
            "switch_tab",
            "Сделать рабочей вкладку с номером из list_tabs. Только для разрешённых сайтов.",
            schema(
                vec![("tab", prop("integer", "Номер из последнего list_tabs."))],
                &["tab"],
            ),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(fields: Vec<(&str, Value)>) -> Value {
        Value::obj(fields)
    }

    #[test]
    fn valid_calls() {
        let n = |x: f64| Value::Num(x);
        let cases = [
            ("read_page", input(vec![]), ToolCall::ReadPage),
            (
                "click",
                input(vec![("element", n(3.0))]),
                ToolCall::Click { element: 3 },
            ),
            (
                "type_text",
                input(vec![
                    ("submit", Value::Bool(false)),
                    ("element", n(7.0)),
                    ("text", Value::str("привет\nмир")),
                ]),
                ToolCall::TypeText {
                    element: 7,
                    text: "привет\nмир".into(),
                    submit: false,
                },
            ),
            (
                "select_option",
                input(vec![("element", n(2.0)), ("option", Value::str("A"))]),
                ToolCall::SelectOption {
                    element: 2,
                    option: "A".into(),
                },
            ),
            (
                "scroll",
                input(vec![("direction", Value::str("down"))]),
                ToolCall::Scroll {
                    direction: Direction::Down,
                },
            ),
            (
                "navigate",
                input(vec![("url", Value::str("https://example.com/"))]),
                ToolCall::Navigate {
                    url: "https://example.com/".into(),
                },
            ),
            ("go_back", input(vec![]), ToolCall::GoBack),
            ("list_tabs", input(vec![]), ToolCall::ListTabs),
            (
                "switch_tab",
                input(vec![("tab", n(1.0))]),
                ToolCall::SwitchTab { tab: 1 },
            ),
        ];
        for (name, inp, expected) in cases {
            assert_eq!(parse(name, &inp), Ok(expected), "{name}");
        }
    }

    #[test]
    fn invalid_calls() {
        let n = |x: f64| Value::Num(x);
        let bad = [
            ("eval", input(vec![])),
            ("Click", input(vec![("element", n(1.0))])),
            ("read_page", input(vec![("x", n(1.0))])),
            ("read_page", Value::Null),
            ("click", input(vec![])),
            ("click", input(vec![("element", n(0.0))])),
            ("click", input(vec![("element", n(-1.0))])),
            ("click", input(vec![("element", n(1.5))])),
            ("click", input(vec![("element", n(1e12))])),
            ("click", input(vec![("element", Value::str("1"))])),
            (
                "click",
                input(vec![("element", n(1.0)), ("force", Value::Bool(true))]),
            ),
            (
                "type_text",
                input(vec![("element", n(1.0)), ("text", Value::str("x"))]),
            ),
            (
                "type_text",
                input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str("x")),
                    ("submit", Value::str("true")),
                ]),
            ),
            (
                "type_text",
                input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str("a\u{0}b")),
                    ("submit", Value::Bool(false)),
                ]),
            ),
            (
                "type_text",
                input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str("я".repeat(MAX_TYPE_CHARS + 1))),
                    ("submit", Value::Bool(false)),
                ]),
            ),
            ("scroll", input(vec![("direction", Value::str("left"))])),
            ("navigate", input(vec![("url", Value::Num(1.0))])),
            (
                "navigate",
                input(vec![("url", Value::str("x".repeat(MAX_URL_CHARS + 1)))]),
            ),
        ];
        for (name, inp) in bad {
            assert!(parse(name, &inp).is_err(), "{name} {inp:?}");
        }
        assert_eq!(parse("eval", &input(vec![])), Err(ToolError::UnknownTool));
    }

    #[test]
    fn every_defined_tool_parses_by_name() {
        let defs = definitions();
        let names: Vec<&str> = defs
            .as_arr()
            .unwrap()
            .iter()
            .map(|t| t.get("name").and_then(Value::as_str).unwrap())
            .collect();
        assert_eq!(names.len(), 9);
        for name in names {
            assert_ne!(
                parse(name, &Value::Obj(vec![])),
                Err(ToolError::UnknownTool),
                "{name}"
            );
        }
    }

    // Hardened test coverage: tools.rs strict parsing
    #[test]
    fn click_field_wrong_types() {
        // element as string instead of number
        assert!(parse("click", &input(vec![("element", Value::str("1"))])).is_err());

        // element as object
        assert!(parse("click", &input(vec![("element", Value::obj(vec![]))])).is_err());

        // element as boolean
        assert!(parse("click", &input(vec![("element", Value::Bool(true))])).is_err());

        // element as null
        assert!(parse("click", &input(vec![("element", Value::Null)])).is_err());
    }

    #[test]
    fn type_text_field_types() {
        let n = |x: f64| Value::Num(x);

        // text as number instead of string
        assert!(
            parse(
                "type_text",
                &input(vec![
                    ("element", n(1.0)),
                    ("text", n(42.0)),
                    ("submit", Value::Bool(false)),
                ])
            )
            .is_err()
        );

        // submit as string instead of bool
        assert!(
            parse(
                "type_text",
                &input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str("hi")),
                    ("submit", Value::str("true")),
                ])
            )
            .is_err()
        );

        // submit as number
        assert!(
            parse(
                "type_text",
                &input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str("hi")),
                    ("submit", n(1.0)),
                ])
            )
            .is_err()
        );
    }

    #[test]
    fn select_option_field_types() {
        let n = |x: f64| Value::Num(x);

        // option as number
        assert!(
            parse(
                "select_option",
                &input(vec![("element", n(1.0)), ("option", n(42.0)),])
            )
            .is_err()
        );

        // element as string
        assert!(
            parse(
                "select_option",
                &input(vec![
                    ("element", Value::str("1")),
                    ("option", Value::str("A")),
                ])
            )
            .is_err()
        );
    }

    #[test]
    fn navigate_field_types() {
        // url as number
        assert!(parse("navigate", &input(vec![("url", Value::Num(42.0)),])).is_err());

        // url as object
        assert!(parse("navigate", &input(vec![("url", Value::obj(vec![])),])).is_err());
    }

    #[test]
    fn switch_tab_field_types() {
        // tab as string
        assert!(parse("switch_tab", &input(vec![("tab", Value::str("1")),])).is_err());

        // tab as boolean
        assert!(parse("switch_tab", &input(vec![("tab", Value::Bool(true)),])).is_err());
    }

    #[test]
    fn missing_required_fields() {
        let n = |x: f64| Value::Num(x);

        // click without element
        assert!(parse("click", &input(vec![])).is_err());

        // type_text missing text
        assert!(
            parse(
                "type_text",
                &input(vec![("element", n(1.0)), ("submit", Value::Bool(false)),])
            )
            .is_err()
        );

        // type_text missing submit
        assert!(
            parse(
                "type_text",
                &input(vec![("element", n(1.0)), ("text", Value::str("hi")),])
            )
            .is_err()
        );

        // select_option missing option
        assert!(parse("select_option", &input(vec![("element", n(1.0)),])).is_err());

        // scroll missing direction
        assert!(parse("scroll", &input(vec![])).is_err());

        // navigate missing url
        assert!(parse("navigate", &input(vec![])).is_err());

        // switch_tab missing tab
        assert!(parse("switch_tab", &input(vec![])).is_err());
    }

    #[test]
    fn extra_fields_rejected() {
        let n = |x: f64| Value::Num(x);

        // click with extra field
        assert!(
            parse(
                "click",
                &input(vec![("element", n(1.0)), ("force", Value::Bool(true)),])
            )
            .is_err()
        );

        // read_page with extra field
        assert!(parse("read_page", &input(vec![("force", Value::Bool(true)),])).is_err());

        // go_back with extra field
        assert!(parse("go_back", &input(vec![("force", Value::Bool(true)),])).is_err());
    }

    #[test]
    fn id_boundary_values() {
        let n = |x: f64| Value::Num(x);

        // id = 0 is rejected
        assert!(parse("click", &input(vec![("element", n(0.0))])).is_err());

        // id = 1 is minimum valid
        assert_eq!(
            parse("click", &input(vec![("element", n(1.0))])),
            Ok(ToolCall::Click { element: 1 })
        );

        // id = MAX_ID is valid
        assert_eq!(
            parse("click", &input(vec![("element", n(MAX_ID as f64))])),
            Ok(ToolCall::Click {
                element: MAX_ID as u32
            })
        );

        // id = MAX_ID + 1 is rejected
        assert!(parse("click", &input(vec![("element", n((MAX_ID + 1) as f64))])).is_err());

        // id = -1 is rejected
        assert!(parse("click", &input(vec![("element", n(-1.0))])).is_err());

        // id as fractional is rejected
        assert!(parse("click", &input(vec![("element", n(1.5))])).is_err());

        // id as huge number is rejected
        assert!(parse("click", &input(vec![("element", n(1e20))])).is_err());
    }

    #[test]
    fn text_length_boundaries() {
        let n = |x: f64| Value::Num(x);

        // Empty text is valid
        assert_eq!(
            parse(
                "type_text",
                &input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str("")),
                    ("submit", Value::Bool(false)),
                ])
            ),
            Ok(ToolCall::TypeText {
                element: 1,
                text: String::new(),
                submit: false,
            })
        );

        // MAX_TYPE_CHARS exactly is valid
        let max_text = "я".repeat(MAX_TYPE_CHARS);
        assert!(
            parse(
                "type_text",
                &input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str(&max_text)),
                    ("submit", Value::Bool(false)),
                ])
            )
            .is_ok()
        );

        // MAX_TYPE_CHARS + 1 is rejected
        let too_long = "я".repeat(MAX_TYPE_CHARS + 1);
        assert!(
            parse(
                "type_text",
                &input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str(&too_long)),
                    ("submit", Value::Bool(false)),
                ])
            )
            .is_err()
        );
    }

    #[test]
    fn option_text_length_boundary() {
        let n = |x: f64| Value::Num(x);

        // Exactly MAX_OPTION_CHARS is valid
        let max_opt = "x".repeat(MAX_OPTION_CHARS);
        assert!(
            parse(
                "select_option",
                &input(vec![("element", n(1.0)), ("option", Value::str(&max_opt)),])
            )
            .is_ok()
        );

        // MAX_OPTION_CHARS + 1 is rejected
        let too_long = "x".repeat(MAX_OPTION_CHARS + 1);
        assert!(
            parse(
                "select_option",
                &input(vec![("element", n(1.0)), ("option", Value::str(&too_long)),])
            )
            .is_err()
        );
    }

    #[test]
    fn url_length_boundary() {
        // Exactly MAX_URL_CHARS is valid
        let max_url = format!("https://example.com/{}", "a".repeat(MAX_URL_CHARS - 20));
        assert!(parse("navigate", &input(vec![("url", Value::str(&max_url)),])).is_ok());

        // MAX_URL_CHARS + 1 is rejected
        let too_long = "x".repeat(MAX_URL_CHARS + 1);
        assert!(parse("navigate", &input(vec![("url", Value::str(&too_long)),])).is_err());
    }

    #[test]
    fn control_chars_rejected_in_text() {
        let n = |x: f64| Value::Num(x);

        // NUL character (U+0000) is rejected
        assert!(
            parse(
                "type_text",
                &input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str("a\u{0}b")),
                    ("submit", Value::Bool(false)),
                ])
            )
            .is_err()
        );

        // DEL character (U+007F) is rejected
        assert!(
            parse(
                "type_text",
                &input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str("a\u{7F}b")),
                    ("submit", Value::Bool(false)),
                ])
            )
            .is_err()
        );

        // U+0001 is rejected
        assert!(
            parse(
                "type_text",
                &input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str("a\u{1}b")),
                    ("submit", Value::Bool(false)),
                ])
            )
            .is_err()
        );

        // Carriage return (U+000D) is rejected
        assert!(
            parse(
                "type_text",
                &input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str("a\rb")),
                    ("submit", Value::Bool(false)),
                ])
            )
            .is_err()
        );

        // Line separator (U+2028) is rejected
        assert!(
            parse(
                "type_text",
                &input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str("a\u{2028}b")),
                    ("submit", Value::Bool(false)),
                ])
            )
            .is_err()
        );
    }

    #[test]
    fn allowed_whitespace_in_text() {
        let n = |x: f64| Value::Num(x);

        // Newline (U+000A) is allowed
        assert!(
            parse(
                "type_text",
                &input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str("a\nb")),
                    ("submit", Value::Bool(false)),
                ])
            )
            .is_ok()
        );

        // Tab (U+0009) is allowed
        assert!(
            parse(
                "type_text",
                &input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str("a\tb")),
                    ("submit", Value::Bool(false)),
                ])
            )
            .is_ok()
        );

        // Regular space is allowed
        assert!(
            parse(
                "type_text",
                &input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str("a b")),
                    ("submit", Value::Bool(false)),
                ])
            )
            .is_ok()
        );
    }

    #[test]
    fn emoji_and_combining_chars_in_text() {
        let n = |x: f64| Value::Num(x);

        // Emoji should be counted by chars, not bytes
        let emoji = "😀";
        assert!(
            parse(
                "type_text",
                &input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str(emoji)),
                    ("submit", Value::Bool(false)),
                ])
            )
            .is_ok()
        );

        // Combining diacritics are counted as chars
        let with_diacritic = "e\u{0301}"; // e with acute accent
        assert!(
            parse(
                "type_text",
                &input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str(with_diacritic)),
                    ("submit", Value::Bool(false)),
                ])
            )
            .is_ok()
        );
    }

    #[test]
    fn scroll_direction_validation() {
        // "up" is valid
        assert_eq!(
            parse("scroll", &input(vec![("direction", Value::str("up")),])),
            Ok(ToolCall::Scroll {
                direction: Direction::Up
            })
        );

        // "down" is valid
        assert_eq!(
            parse("scroll", &input(vec![("direction", Value::str("down")),])),
            Ok(ToolCall::Scroll {
                direction: Direction::Down
            })
        );

        // "left" is invalid
        assert!(parse("scroll", &input(vec![("direction", Value::str("left")),])).is_err());

        // "UP" (uppercase) is invalid
        assert!(parse("scroll", &input(vec![("direction", Value::str("UP")),])).is_err());

        // Direction as number is invalid
        assert!(parse("scroll", &input(vec![("direction", Value::Num(0.0)),])).is_err());
    }

    #[test]
    fn definitions_schema_sanity() {
        let defs = definitions();
        let tools = defs.as_arr().unwrap();

        // Should have 9 tools
        assert_eq!(tools.len(), 9);

        for tool in tools {
            // Every tool should be an object
            assert!(matches!(tool, Value::Obj(_)));

            // Every tool needs name, description, input_schema
            let name = tool.get("name").and_then(Value::as_str);
            let desc = tool.get("description").and_then(Value::as_str);
            let schema = tool.get("input_schema");

            assert!(name.is_some(), "tool missing name");
            assert!(desc.is_some(), "tool missing description");
            assert!(schema.is_some(), "tool missing input_schema");
            assert!(!name.unwrap().is_empty(), "tool has empty name");
            assert!(!desc.unwrap().is_empty(), "tool has empty description");

            // input_schema must be object with type, properties, required, additionalProperties
            let schema = schema.unwrap();
            assert_eq!(schema.get("type").and_then(Value::as_str), Some("object"));
            assert!(matches!(schema.get("properties"), Some(Value::Obj(_))));
            assert!(schema.get("required").and_then(Value::as_arr).is_some());
            assert_eq!(
                schema.get("additionalProperties").and_then(Value::as_bool),
                Some(false),
                "tool {}: additionalProperties must be false",
                name.unwrap()
            );

            // Verify required fields are subset of properties
            let Some(Value::Obj(props)) = schema.get("properties") else {
                panic!("properties не объект");
            };
            let required = schema.get("required").and_then(Value::as_arr).unwrap();
            let prop_names: Vec<&str> = props.iter().map(|(k, _)| k.as_str()).collect();

            for req in required {
                if let Some(req_name) = req.as_str() {
                    assert!(
                        prop_names.contains(&req_name),
                        "tool {}: required field {} not in properties",
                        name.unwrap(),
                        req_name
                    );
                }
            }
        }
    }

    #[test]
    fn tool_names_are_unique() {
        let defs = definitions();
        let tools = defs.as_arr().unwrap();
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str))
            .collect();

        assert_eq!(names.len(), tools.len(), "duplicate tool names");

        // Check for exact matches (case-sensitive)
        for (i, name1) in names.iter().enumerate() {
            for (j, name2) in names.iter().enumerate() {
                if i != j {
                    assert_ne!(name1, name2, "duplicate tool: {}", name1);
                }
            }
        }
    }

    #[test]
    fn minimal_valid_input_for_each_tool() {
        let n = |x: f64| Value::Num(x);

        // Minimal input that should parse for each tool
        let cases = [
            ("read_page", input(vec![])),
            ("click", input(vec![("element", n(1.0))])),
            (
                "type_text",
                input(vec![
                    ("element", n(1.0)),
                    ("text", Value::str("")),
                    ("submit", Value::Bool(false)),
                ]),
            ),
            (
                "select_option",
                input(vec![("element", n(1.0)), ("option", Value::str(""))]),
            ),
            ("scroll", input(vec![("direction", Value::str("up"))])),
            (
                "navigate",
                input(vec![("url", Value::str("https://example.com"))]),
            ),
            ("go_back", input(vec![])),
            ("list_tabs", input(vec![])),
            ("switch_tab", input(vec![("tab", n(1.0))])),
        ];

        for (name, inp) in cases {
            let result = parse(name, &inp);
            assert!(result.is_ok(), "{name}: {result:?}");
        }
    }
}
