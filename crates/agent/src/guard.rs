//! Решение по каждому вызову инструмента: выполнить, спросить пользователя
//! или отказать. Только детерминированные правила; мнение модели не
//! учитывается.
//!
//! Модель считается скомпрометированной, как только прочитала страницу.
//! Поэтому опасное определяется по фактам (тип поля, отправка формы, адрес
//! ссылки, откуда пришли данные), а не по тому, что модель о них пишет.
//! Сомнительное — подтверждение пользователем в панели, которую страница
//! подделать не может.

use crate::page::{Element, Snapshot};
use crate::policy::{Access, Origin};
use crate::tools::ToolCall;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    Allow,
    /// Причины, по которым нужно согласие пользователя.
    Confirm(Vec<String>),
    Block(String),
}

pub(crate) struct Ctx<'a> {
    pub access: &'a Access,
    /// Origin рабочей вкладки, если он разрешён.
    pub current: Option<&'a Origin>,
    pub snapshot: Option<&'a Snapshot>,
    /// Сайты, чьё содержимое попало в диалог.
    pub read: &'a [Origin],
    /// Тексты пользователя в этом диалоге: их ввод не считается утечкой.
    pub user_text: &'a str,
}

/// Слова в имени элемента, после которых нажатие может быть необратимым.
const DANGER_WORDS: &[&str] = &[
    "buy",
    "purchase",
    "pay",
    "checkout",
    "order",
    "delete",
    "remove",
    "erase",
    "destroy",
    "send",
    "post",
    "publish",
    "submit",
    "confirm",
    "transfer",
    "withdraw",
    "unsubscribe",
    "deactivate",
    "close account",
    "approve",
    "accept",
    "reply",
    "share",
    "upload",
    "save",
    "invite",
    "grant",
    "authorize",
    "install",
    "donate",
    "subscribe",
    "sign",
    "apply",
    "купить",
    "куплю",
    "оплат",
    "заказ",
    "удал",
    "стереть",
    "отправ",
    "опубликов",
    "публик",
    "подтверд",
    "перевес",
    "перевод",
    "вывес",
    "отпис",
    "подпис",
    "поделит",
    "загруз",
    "сохран",
    "принять",
    "соглас",
    "ответить",
    "пригласит",
    "разреш",
    "установ",
    "оформ",
    "пожертв",
    "подать",
];

/// Признаки поля пароля или платёжных данных.
const SECRET_AUTOCOMPLETE: &[&str] = &["password", "cc-", "one-time-code"];
const SECRET_WORDS: &[&str] = &[
    "password",
    "пароль",
    "cvv",
    "cvc",
    "card number",
    "номер карты",
    "iban",
    "кодовое слово",
    "секретн",
];

/// Самый короткий фрагмент текста пользователя, который можно вводить на
/// сайт без подтверждения при данных с других сайтов: короче — секрет можно
/// перенести по символу, каждый из которых встречается в задаче.
const MIN_USER_FRAGMENT: usize = 4;

/// Вводимый текст целиком взят из сообщений пользователя.
fn typed_by_user(user_text: &str, text: &str) -> bool {
    let text = text.trim();
    text.chars().count() >= MIN_USER_FRAGMENT && user_text.contains(text)
}

/// Слово целиком в имени элемента ищется по «скелету»: страница не должна
/// прятать «удалить» от проверки невидимым символом, диакритикой, буквой
/// другого алфавита того же вида или полноширинной формой.
fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    let h = skeleton(haystack);
    needles.iter().any(|n| h.contains(&skeleton(n)))
}

/// Нижний регистр без невидимых символов и комбинирующих знаков; похожие
/// буквы кириллицы и греческого сведены к латинским, пробелы — к одному.
fn skeleton(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut space = false;
    for c in s.chars().flat_map(char::to_lowercase) {
        let c = match c {
            '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{E0000}'..='\u{E0FFF}'
            | '\u{0300}'..='\u{036F}'
            | '\u{0483}'..='\u{0489}'
            | '\u{1AB0}'..='\u{1AFF}'
            | '\u{1DC0}'..='\u{1DFF}'
            | '\u{20D0}'..='\u{20FF}'
            | '\u{FE20}'..='\u{FE2F}' => continue,
            '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            'а' | 'α' => 'a',
            'в' | 'β' => 'b',
            'с' | 'ς' => 'c',
            'е' | 'ё' | 'є' | 'ε' => 'e',
            'һ' => 'h',
            'і' | 'ї' | 'ı' | 'ι' | 'ӏ' => 'i',
            'ј' => 'j',
            'к' | 'κ' => 'k',
            'м' => 'm',
            'н' | 'η' => 'n',
            'о' | 'ο' | '0' => 'o',
            'р' | 'ρ' => 'p',
            'ԛ' => 'q',
            'ѕ' => 's',
            'т' | 'τ' => 't',
            'у' | 'υ' | 'γ' => 'y',
            'х' | 'χ' => 'x',
            'ԝ' | 'ѡ' => 'w',
            'ь' => 'b',
            c if c.is_whitespace() => ' ',
            c => c,
        };
        if c == ' ' {
            if !space {
                out.push(' ');
            }
            space = true;
        } else {
            out.push(c);
            space = false;
        }
    }
    out
}

fn is_root(url: &str, origin: &Origin) -> bool {
    url.trim_end_matches('/')
        .eq_ignore_ascii_case(&origin.to_string())
}

/// Сайты, чьи данные могут уйти на `target`.
fn foreign(ctx: &Ctx<'_>, target: &Origin) -> Vec<String> {
    ctx.read
        .iter()
        .filter(|o| *o != target)
        .map(Origin::to_string)
        .collect()
}

/// Переход на адрес: сайт должен быть открыт, а данные с других сайтов
/// в адресе — только с согласия.
fn navigation(ctx: &Ctx<'_>, url: &str, what: &str) -> Verdict {
    let target = match ctx.access.check(url) {
        Ok(o) => o,
        Err(denied) => return Verdict::Block(format!("{what}: {}", denied.describe())),
    };
    let others = foreign(ctx, &target);
    if others.is_empty() || is_root(url, &target) {
        Verdict::Allow
    } else {
        Verdict::Confirm(vec![format!(
            "{what} на {target}: в адресе могут оказаться данные с {}",
            others.join(", ")
        )])
    }
}

fn element<'a>(ctx: &'a Ctx<'_>, id: u32) -> Result<(&'a Element, &'a Origin), Verdict> {
    let current = ctx
        .current
        .ok_or_else(|| Verdict::Block("рабочая вкладка не на разрешённом сайте".into()))?;
    let snapshot = ctx
        .snapshot
        .ok_or_else(|| Verdict::Block("сначала вызови read_page".into()))?;
    let el = snapshot
        .element(id)
        .ok_or_else(|| Verdict::Block(format!("элемента [{id}] нет в последнем снимке")))?;
    if el.disabled {
        return Err(Verdict::Block(format!("элемент [{id}] недоступен")));
    }
    Ok((el, current))
}

/// Проверка отправки формы: адрес формы должен быть открыт.
fn form_submission(ctx: &Ctx<'_>, el: &Element, reasons: &mut Vec<String>) -> Option<Verdict> {
    match ctx.access.check(&el.form_action) {
        Ok(target) => {
            reasons.push(format!("отправка формы на {target}"));
            None
        }
        Err(denied) => Some(Verdict::Block(format!(
            "форма отправляется на закрытый адрес: {}",
            denied.describe()
        ))),
    }
}

fn finish(reasons: Vec<String>) -> Verdict {
    if reasons.is_empty() {
        Verdict::Allow
    } else {
        Verdict::Confirm(reasons)
    }
}

pub(crate) fn decide(call: &ToolCall, ctx: &Ctx<'_>) -> Verdict {
    match call {
        ToolCall::ReadPage | ToolCall::Scroll { .. } => match ctx.current {
            Some(_) => Verdict::Allow,
            None => Verdict::Block("рабочая вкладка не на разрешённом сайте".into()),
        },
        // Вкладки проверяет background: список показывает только открытые
        // сайты, переключение — только на них.
        ToolCall::GoBack | ToolCall::ListTabs | ToolCall::SwitchTab { .. } => Verdict::Allow,
        ToolCall::Navigate { url } => navigation(ctx, url, "переход"),
        ToolCall::Click { element: id } => {
            let (el, _) = match element(ctx, *id) {
                Ok(found) => found,
                Err(v) => return v,
            };
            let mut reasons = Vec::new();
            if !el.href.is_empty() {
                match navigation(ctx, &el.href, "ссылка") {
                    Verdict::Allow => {}
                    Verdict::Confirm(r) => reasons.extend(r),
                    block => return block,
                }
            }
            if el.submits
                && let Some(block) = form_submission(ctx, el, &mut reasons)
            {
                return block;
            }
            if contains_any(&el.name, DANGER_WORDS) {
                reasons.push(format!(
                    "кнопка «{}» похожа на необратимое действие",
                    crate::page::clean_line(&el.name)
                ));
            }
            finish(reasons)
        }
        ToolCall::TypeText {
            element: id,
            text,
            submit,
        } => {
            let (el, current) = match element(ctx, *id) {
                Ok(found) => found,
                Err(v) => return v,
            };
            if !el.editable {
                return Verdict::Block(format!("в элемент [{id}] нельзя вводить текст"));
            }
            if el.kind == "file" {
                return Verdict::Block("работа с файлами запрещена".into());
            }
            let mut reasons = Vec::new();
            if el.kind == "password"
                || contains_any(&el.autocomplete, SECRET_AUTOCOMPLETE)
                || contains_any(&el.name, SECRET_WORDS)
            {
                reasons.push("ввод в поле пароля или платёжных данных".into());
            }
            let others = foreign(ctx, current);
            if !others.is_empty() && !text.trim().is_empty() && !typed_by_user(ctx.user_text, text)
            {
                reasons.push(format!(
                    "ввод на {current} текста, который мог прийти с {}",
                    others.join(", ")
                ));
            }
            if *submit {
                if !el.form {
                    return Verdict::Block("поле не в форме, отправлять нечего".into());
                }
                if let Some(block) = form_submission(ctx, el, &mut reasons) {
                    return block;
                }
            }
            finish(reasons)
        }
        ToolCall::SelectOption {
            element: id,
            option,
        } => {
            let (el, _) = match element(ctx, *id) {
                Ok(found) => found,
                Err(v) => return v,
            };
            if el.tag != "select" {
                return Verdict::Block(format!("элемент [{id}] не выпадающий список"));
            }
            if !el.options.iter().any(|o| o == option) {
                return Verdict::Block("такого варианта нет в снимке".into());
            }
            Verdict::Allow
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::tests::element as el;
    use crate::policy::{Policy, parse_url};

    fn access() -> Access {
        let p = Policy::parse("https://shop.example\nhttps://notes.example", "").unwrap();
        Access::new(
            p,
            &[
                "https://shop.example/*".to_owned(),
                "https://notes.example/*".to_owned(),
            ],
        )
    }

    fn snapshot(elements: Vec<Element>) -> Snapshot {
        Snapshot {
            origin: "https://shop.example".into(),
            url: "https://shop.example/".into(),
            title: String::new(),
            version: 1,
            elements,
            text: String::new(),
            frames: 0,
            truncated: false,
        }
    }

    struct World {
        access: Access,
        current: Origin,
        snapshot: Snapshot,
        read: Vec<Origin>,
        user: String,
    }

    impl World {
        fn new(elements: Vec<Element>) -> Self {
            let current = parse_url("https://shop.example").unwrap();
            Self {
                access: access(),
                read: vec![current.clone()],
                current,
                snapshot: snapshot(elements),
                user: "найди книгу Rust".into(),
            }
        }

        fn also_read(mut self, url: &str) -> Self {
            self.read.push(parse_url(url).unwrap());
            self
        }

        fn decide(&self, call: ToolCall) -> Verdict {
            decide(
                &call,
                &Ctx {
                    access: &self.access,
                    current: Some(&self.current),
                    snapshot: Some(&self.snapshot),
                    read: &self.read,
                    user_text: &self.user,
                },
            )
        }
    }

    fn textbox(id: u32, name: &str) -> Element {
        let mut e = el(id, "textbox", name);
        e.tag = "input".into();
        e.kind = "text".into();
        e.editable = true;
        e
    }

    fn link(id: u32, href: &str) -> Element {
        let mut e = el(id, "link", "ссылка");
        e.tag = "a".into();
        e.href = href.into();
        e
    }

    fn is_confirm(v: &Verdict) -> bool {
        matches!(v, Verdict::Confirm(_))
    }

    fn is_block(v: &Verdict) -> bool {
        matches!(v, Verdict::Block(_))
    }

    #[test]
    fn plain_actions_are_allowed() {
        let w = World::new(vec![
            el(1, "button", "Следующая страница"),
            textbox(2, "Поиск"),
            link(3, "https://shop.example/books"),
        ]);
        assert_eq!(w.decide(ToolCall::ReadPage), Verdict::Allow);
        assert_eq!(w.decide(ToolCall::Click { element: 1 }), Verdict::Allow);
        assert_eq!(w.decide(ToolCall::Click { element: 3 }), Verdict::Allow);
        assert_eq!(
            w.decide(ToolCall::TypeText {
                element: 2,
                text: "книга".into(),
                submit: false
            }),
            Verdict::Allow
        );
    }

    #[test]
    fn invented_or_stale_elements_are_blocked() {
        let w = World::new(vec![el(1, "button", "OK")]);
        assert!(is_block(&w.decide(ToolCall::Click { element: 9 })));
        let mut disabled = el(1, "button", "OK");
        disabled.disabled = true;
        let w = World::new(vec![disabled]);
        assert!(is_block(&w.decide(ToolCall::Click { element: 1 })));
        // Без снимка — никаких действий.
        let w = World::new(vec![]);
        let v = decide(
            &ToolCall::Click { element: 1 },
            &Ctx {
                access: &w.access,
                current: Some(&w.current),
                snapshot: None,
                read: &w.read,
                user_text: "",
            },
        );
        assert!(is_block(&v));
        // Вкладка ушла на закрытый сайт.
        let v = decide(
            &ToolCall::ReadPage,
            &Ctx {
                access: &w.access,
                current: None,
                snapshot: None,
                read: &w.read,
                user_text: "",
            },
        );
        assert!(is_block(&v));
    }

    #[test]
    fn dangerous_buttons_need_confirmation() {
        for name in [
            "Купить сейчас",
            "Delete account",
            "Оформить заказ",
            "SEND",
            "Удалить",
        ] {
            let w = World::new(vec![el(1, "button", name)]);
            assert!(
                is_confirm(&w.decide(ToolCall::Click { element: 1 })),
                "{name}"
            );
        }
    }

    #[test]
    fn form_submission() {
        let mut submit = el(1, "button", "Далее");
        submit.form = true;
        submit.submits = true;
        submit.form_action = "https://shop.example/cart".into();
        let w = World::new(vec![submit.clone()]);
        assert!(is_confirm(&w.decide(ToolCall::Click { element: 1 })));

        // Форма на чужой сайт — отказ без вопросов.
        submit.form_action = "https://evil.example/collect".into();
        let w = World::new(vec![submit.clone()]);
        assert!(is_block(&w.decide(ToolCall::Click { element: 1 })));
        submit.form_action = "javascript:steal()".into();
        let w = World::new(vec![submit]);
        assert!(is_block(&w.decide(ToolCall::Click { element: 1 })));

        let mut field = textbox(2, "Поиск");
        field.form = true;
        field.form_action = "https://shop.example/search".into();
        let w = World::new(vec![field]);
        assert!(is_confirm(&w.decide(ToolCall::TypeText {
            element: 2,
            text: "книга".into(),
            submit: true
        })));
        let w = World::new(vec![textbox(2, "Поиск")]);
        assert!(is_block(&w.decide(ToolCall::TypeText {
            element: 2,
            text: "x".into(),
            submit: true
        })));
    }

    #[test]
    fn secrets_and_files() {
        let mut pass = textbox(1, "Вход");
        pass.kind = "password".into();
        let mut card = textbox(2, "Card");
        card.autocomplete = "cc-number".into();
        let w = World::new(vec![
            pass,
            card,
            textbox(3, "Ваш пароль"),
            textbox(6, "Ваш па\u{200B}роль"),
            textbox(7, "Pasѕword"),
        ]);
        for id in [1, 2, 3, 6, 7] {
            assert!(
                is_confirm(&w.decide(ToolCall::TypeText {
                    element: id,
                    text: "x".into(),
                    submit: false
                })),
                "{id}"
            );
        }
        let mut file = textbox(4, "Файл");
        file.kind = "file".into();
        let w = World::new(vec![file, el(5, "button", "Не поле")]);
        for id in [4, 5] {
            assert!(is_block(&w.decide(ToolCall::TypeText {
                element: id,
                text: "x".into(),
                submit: false
            })));
        }
    }

    #[test]
    fn cross_site_data_flow_needs_confirmation() {
        // Прочитали заметки, вводим текст в магазин.
        let w = World::new(vec![textbox(1, "Комментарий")]).also_read("https://notes.example");
        let v = w.decide(ToolCall::TypeText {
            element: 1,
            text: "секрет из заметок".into(),
            submit: false,
        });
        assert!(is_confirm(&v), "{v:?}");
        // Текст самого пользователя утечкой не считается.
        let v = w.decide(ToolCall::TypeText {
            element: 1,
            text: "книгу Rust".into(),
            submit: false,
        });
        assert_eq!(v, Verdict::Allow);
        // Но не по символу: каждая буква есть в задаче, а вместе это секрет.
        for chunk in ["к", "ни", "Rus", " R "] {
            let v = w.decide(ToolCall::TypeText {
                element: 1,
                text: chunk.into(),
                submit: false,
            });
            assert!(is_confirm(&v), "{chunk:?} {v:?}");
        }
    }

    #[test]
    fn navigation_rules() {
        let w = World::new(vec![
            link(1, "https://evil.example/?q=1"),
            link(2, "javascript:alert(1)"),
            link(3, "https://notes.example/page?data=x"),
        ]);
        assert!(is_block(&w.decide(ToolCall::Navigate {
            url: "https://evil.example/".into()
        })));
        assert!(is_block(&w.decide(ToolCall::Navigate {
            url: "http://shop.example/".into()
        })));
        assert!(is_block(&w.decide(ToolCall::Navigate {
            url: "https://paypal.com/".into()
        })));
        assert!(is_block(&w.decide(ToolCall::Click { element: 1 })));
        assert!(is_block(&w.decide(ToolCall::Click { element: 2 })));
        // Данные магазина в адресе заметок — только с согласия.
        assert!(is_confirm(&w.decide(ToolCall::Click { element: 3 })));
        assert!(is_confirm(&w.decide(ToolCall::Navigate {
            url: "https://notes.example/new?text=секрет".into()
        })));
        // Корень разрешённого сайта данных не несёт.
        assert_eq!(
            w.decide(ToolCall::Navigate {
                url: "https://notes.example/".into()
            }),
            Verdict::Allow
        );
        // В пределах одного сайта переходы свободны.
        assert_eq!(
            w.decide(ToolCall::Navigate {
                url: "https://shop.example/search?q=rust".into()
            }),
            Verdict::Allow
        );
    }

    #[test]
    fn select_only_known_options() {
        let mut s = el(1, "combobox", "Страна");
        s.tag = "select".into();
        s.options = vec!["Россия".into(), "Сербия".into()];
        let w = World::new(vec![s, el(2, "button", "x")]);
        assert_eq!(
            w.decide(ToolCall::SelectOption {
                element: 1,
                option: "Сербия".into()
            }),
            Verdict::Allow
        );
        assert!(is_block(&w.decide(ToolCall::SelectOption {
            element: 1,
            option: "Нарния".into()
        })));
        assert!(is_block(&w.decide(ToolCall::SelectOption {
            element: 2,
            option: "x".into()
        })));
    }

    #[test]
    fn danger_words_require_confirmation() {
        // Опасные слова в кнопках требуют подтверждения независимо от регистра.
        for name in [
            "Delete account",
            "Send now",
            "Buy this",
            "Publish post",
            "Confirm payment",
            "DELETE",
            "ОПЛАТ",
            // Маскировка: невидимые символы, буквы другого алфавита,
            // диакритика, полноширинные формы, неразрывный пробел.
            "Уда\u{200C}лить",
            "Удал\u{00AD}ить",
            "Уда\u{2060}лить",
            "УдаліТЬ",
            "Удaлить",
            "Уда\u{0301}лить",
            "Dеlеtе",
            "ｄｅｌｅｔｅ",
            "de\u{FEFF}lete",
            "Оплатить",
            "Pаy",
            "close\u{00A0}account",
        ] {
            let w = World::new(vec![el(1, "button", name)]);
            assert!(
                is_confirm(&w.decide(ToolCall::Click { element: 1 })),
                "{name}"
            );
        }
    }

    #[test]
    fn form_submission_to_allowed_site() {
        let mut form = el(1, "button", "Send");
        form.form = true;
        form.submits = true;
        form.form_action = "https://shop.example/checkout".into();
        let w = World::new(vec![form]);
        assert!(is_confirm(&w.decide(ToolCall::Click { element: 1 })));
    }

    #[test]
    fn form_submission_to_blocked_site() {
        let mut form = el(1, "button", "Send");
        form.form = true;
        form.submits = true;
        form.form_action = "javascript:void(0)".into();
        let w = World::new(vec![form]);
        assert!(is_block(&w.decide(ToolCall::Click { element: 1 })));
    }

    #[test]
    fn cross_site_typing_requires_confirmation() {
        let w = World::new(vec![textbox(1, "Input")]).also_read("https://notes.example");

        // Текст, который не в user_text, требует подтверждения.
        let v = w.decide(ToolCall::TypeText {
            element: 1,
            text: "секрет из заметок".into(),
            submit: false,
        });
        assert!(is_confirm(&v));
    }

    #[test]
    fn password_fields_require_confirmation() {
        let mut pass = textbox(1, "");
        pass.kind = "password".into();
        let w = World::new(vec![pass]);
        let v = w.decide(ToolCall::TypeText {
            element: 1,
            text: "x".into(),
            submit: false,
        });
        assert!(is_confirm(&v));
    }

    #[test]
    fn builtin_denied_links_are_blocked() {
        let w = World::new(vec![
            link(1, "https://www.paypal.com/pay"),
            link(2, "https://mail.google.com/"),
        ]);
        assert!(is_block(&w.decide(ToolCall::Click { element: 1 })));
        assert!(is_block(&w.decide(ToolCall::Click { element: 2 })));
    }
}
