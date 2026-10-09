//! Цикл агента: запрос к модели → решение политики → (подтверждение) →
//! действие → результат модели. Один цикл на задачу пользователя.
//!
//! Перед каждым действием доступ к сайту проверяется заново: по текущему
//! адресу вкладки, текущим спискам и текущим разрешениям Firefox. Content-скрипт
//! ещё раз сверяет origin документа непосредственно перед действием.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use js_sys::futures::JsFuture;
use js_sys::{Function, Object, Promise};
use wasm_bindgen::prelude::*;
use web_sys::AbortController;

use crate::api::{self, ApiError, Content, Role, Stop, Turn, Usage};
use crate::background::{self, Cause};
use crate::ext;
use crate::guard::{self, Verdict};
use crate::page::{self, ActOutcome, Snapshot};
use crate::policy::{self, Access, Origin, Policy};
use crate::protocol::Event;
use crate::settings::{self, ApiKey};
use crate::stream::Stream;
use crate::tools::{self, Direction, ToolCall};
use crate::value::{self, Value};

/// Предельное время одного запроса к API, даже если поток идёт.
const REQUEST_TIMEOUT_MS: i32 = 600_000;
/// Сколько поток ответа может молчать (между порциями байтов).
const IDLE_TIMEOUT_MS: i32 = 60_000;
/// Как часто панель получает черновик ответа.
const PARTIAL_INTERVAL_MS: f64 = 250.0;
/// Сколько запросов к модели допускает одна задача.
const MAX_STEPS: usize = 30;
/// Сколько раз подряд модель может повторить один и тот же вызов.
const MAX_REPEATS: usize = 3;
/// Сколько ждать ответа пользователя на запрос подтверждения.
const CONFIRM_TIMEOUT_MS: i32 = 300_000;
/// Ожидание загрузки вкладки после перехода.
const LOAD_WAIT_MS: i32 = 10_000;
const LOAD_POLL_MS: i32 = 250;

/// Общее с background: чем задачу можно остановить снаружи.
#[derive(Clone)]
pub(crate) struct Shared {
    /// Номер задачи: результат старой задачи не применяется к новой.
    pub request: u64,
    pub controller: AbortController,
    pub cause: Rc<Cell<Cause>>,
    /// Ожидающий ответа запрос подтверждения: номер и `resolve` промиса.
    pub confirm: Rc<RefCell<Option<(u64, Function)>>>,
}

impl Shared {
    pub(crate) fn new() -> Option<Self> {
        Some(Self {
            request: background::next_id(),
            controller: AbortController::new().ok()?,
            cause: Rc::new(Cell::new(Cause::None)),
            confirm: Rc::new(RefCell::new(None)),
        })
    }

    /// Остановить: прервать запрос и ответить «нет» на ожидающий вопрос.
    pub(crate) fn halt(&self, cause: Cause) {
        if self.cause.get() == Cause::None {
            self.cause.set(cause);
        }
        self.controller.abort();
        self.answer(None, false);
    }

    /// Ответ на подтверждение. `id = None` — любой ожидающий.
    pub(crate) fn answer(&self, id: Option<u64>, allow: bool) {
        let pending = self
            .confirm
            .borrow_mut()
            .take_if(|(p, _)| id.is_none_or(|i| i == *p));
        if let Some((_, resolve)) = pending {
            let _ = resolve.call1(&JsValue::NULL, &JsValue::from_bool(allow));
        }
    }

    fn stopped(&self) -> bool {
        self.cause.get() != Cause::None
    }
}

enum Failure {
    Storage,
    NoKey,
    BadKey,
    Api(ApiError),
    TooLong,
}

impl Failure {
    fn describe(&self) -> String {
        match self {
            Self::Storage => "Не удалось прочитать настройки.".into(),
            Self::NoKey => {
                "Ключ API не задан. Откройте настройки (после перезапуска Firefox ключ вводится заново).".into()
            }
            Self::BadKey => "Сохранённый ключ API некорректен. Задайте его заново.".into(),
            Self::Api(e) => e.describe(),
            Self::TooLong => "Диалог слишком длинный. Нажмите «Новый чат».".into(),
        }
    }
}

struct Config {
    key: ApiKey,
    model: &'static str,
    max_tokens: u32,
}

async fn load_config() -> Result<Config, Failure> {
    let get = ext::storage_session_get(&ext::strings(&[settings::KEY_API_KEY]))
        .map_err(|_| Failure::Storage)?;
    let session = JsFuture::from(get).await.map_err(|_| Failure::Storage)?;
    let key = ext::get(&session, settings::KEY_API_KEY)
        .and_then(|v| v.as_string())
        .ok_or(Failure::NoKey)?;
    let key = ApiKey::parse(&key).map_err(|_| Failure::BadKey)?;
    let local = JsFuture::from(ext::storage_local_get(&ext::strings(&[
        settings::KEY_MODEL,
        settings::KEY_MAX_TOKENS,
    ])))
    .await
    .map_err(|_| Failure::Storage)?;
    let model = settings::model_from_storage(
        ext::get(&local, settings::KEY_MODEL)
            .and_then(|v| v.as_string())
            .as_deref(),
    );
    let max_tokens = settings::max_tokens_from_storage(
        ext::get(&local, settings::KEY_MAX_TOKENS).and_then(|v| v.as_f64()),
    );
    Ok(Config {
        key,
        model,
        max_tokens,
    })
}

/// Текущий доступ: списки из хранилища и разрешения Firefox. Любая ошибка
/// чтения закрывает всё.
async fn load_access() -> Access {
    let lists = JsFuture::from(ext::storage_local_get(&ext::strings(&[
        settings::KEY_ALLOW_ORIGINS,
        settings::KEY_DENY_HOSTS,
    ])))
    .await
    .ok();
    let Some(lists) = lists else {
        return Access::default();
    };
    let text = |k| ext::get(&lists, k).and_then(|v| v.as_string());
    let policy = Policy::from_storage(
        text(settings::KEY_ALLOW_ORIGINS).as_deref(),
        text(settings::KEY_DENY_HOSTS).as_deref(),
    );
    let granted = match ext::permissions_get_all() {
        Ok(p) => JsFuture::from(p).await.ok(),
        Err(_) => None,
    };
    let origins: Vec<String> = granted
        .and_then(|g| ext::get(&g, "origins"))
        .map(|o| {
            js_sys::Array::from(&o)
                .iter()
                .filter_map(|v| v.as_string())
                .collect()
        })
        .unwrap_or_default();
    Access::new(policy, &origins)
}

/// Случайный разделитель для данных страниц: 128 бит в hex.
fn nonce() -> Option<String> {
    let mut bytes = [0u8; 16];
    web_sys::window()?
        .crypto()
        .ok()?
        .get_random_values_with_u8_array(&mut bytes)
        .ok()?;
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn sleep(ms: i32) -> JsFuture {
    let promise = Promise::new(&mut |resolve, _| {
        if let Some(w) = web_sys::window() {
            let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
        }
    });
    JsFuture::from(promise)
}

async fn call(promise: Result<Promise, JsValue>) -> Option<JsValue> {
    JsFuture::from(promise.ok()?).await.ok()
}

fn tab_id(tab: &JsValue) -> Option<f64> {
    ext::get(tab, "id")
        .and_then(|v| v.as_f64())
        .filter(|n| n.fract() == 0.0 && *n >= 0.0)
}

/// Активная вкладка окна панели.
async fn active_tab(window: u64) -> Option<f64> {
    let query = Object::new();
    ext::set(&query, "active", &JsValue::TRUE);
    // Номер окна от панели проверен как целое в пределах 2^52.
    ext::set(&query, "windowId", &JsValue::from_f64(window as f64));
    let tabs = call(ext::tabs_query(&query)).await?;
    tab_id(&js_sys::Array::from(&tabs).get(0))
}

/// Адрес вкладки. Без host-разрешения Firefox его не отдаёт.
async fn tab_url(tab: f64) -> Option<String> {
    let info = call(ext::tabs_get(tab)).await?;
    ext::get(&info, "url").and_then(|v| v.as_string())
}

async fn wait_loaded(tab: f64) {
    let mut waited = 0;
    while waited < LOAD_WAIT_MS {
        let _ = sleep(LOAD_POLL_MS).await;
        waited += LOAD_POLL_MS;
        let status = call(ext::tabs_get(tab))
            .await
            .and_then(|t| ext::get(&t, "status"))
            .and_then(|s| s.as_string());
        if status.as_deref() != Some("loading") {
            return;
        }
    }
}

/// Операция content-скрипта; результат переводится в `Value` с бюджетом.
async fn in_tab(tab: f64, op: &Value) -> Option<Value> {
    let js = js_sys::JSON::parse(&op.to_json()).ok()?;
    let result = call(ext::leash_in_tab(tab, &js)).await?;
    value::from_js(&result)
}

/// Состояние одной задачи.
struct Task {
    id: u64,
    window: u64,
    tab: Option<f64>,
    snapshot: Option<Snapshot>,
    /// Сайты, чьи данные попали в диалог.
    read: Vec<Origin>,
    /// Вкладки из последнего list_tabs.
    tabs: Vec<f64>,
    user_text: String,
    recent: Vec<ToolCall>,
    shared: Shared,
}

struct Done {
    text: String,
    is_error: bool,
    origin: api::Origin,
}

fn ours(text: impl Into<String>) -> Done {
    Done {
        text: text.into(),
        is_error: false,
        origin: api::Origin::Ours,
    }
}

fn refused(text: impl Into<String>) -> Done {
    Done {
        text: text.into(),
        is_error: true,
        origin: api::Origin::Ours,
    }
}

impl Task {
    fn post(&self, event: &Event) {
        background::post(self.id, event);
    }

    fn note_read(&mut self, origin: &Origin) {
        if !self.read.contains(origin) {
            self.read.push(origin.clone());
        }
    }

    async fn current(&self, access: &Access) -> Option<Origin> {
        let url = tab_url(self.tab?).await?;
        access.check(&url).ok()
    }

    /// Вопрос пользователю. Нет ответа за 5 минут, «Стоп» или закрытая
    /// панель — это «нет».
    async fn ask(&self, text: String) -> bool {
        let id = background::next_id();
        let confirm = Rc::clone(&self.shared.confirm);
        let promise = Promise::new(&mut |resolve, _| {
            if let Some(w) = web_sys::window() {
                let _ = w.set_timeout_with_callback_and_timeout_and_arguments_1(
                    &resolve,
                    CONFIRM_TIMEOUT_MS,
                    &JsValue::FALSE,
                );
            }
            *confirm.borrow_mut() = Some((id, resolve));
        });
        self.post(&Event::Confirm { id, text });
        let answer = JsFuture::from(promise).await.ok().and_then(|v| v.as_bool());
        self.shared.confirm.borrow_mut().take_if(|(p, _)| *p == id);
        answer == Some(true) && !self.shared.stopped()
    }

    fn describe(&self, call: &ToolCall, current: Option<&Origin>) -> String {
        let site = current.map_or_else(|| "?".to_owned(), Origin::to_string);
        let el = |id: &u32| {
            self.snapshot
                .as_ref()
                .and_then(|s| s.element(*id))
                .map_or_else(
                    || format!("[{id}]"),
                    |e| format!("[{id}] {} «{}»", e.role, page::clean_line(&e.name)),
                )
        };
        match call {
            ToolCall::Click { element } => format!("нажать {} на {site}", el(element)),
            ToolCall::TypeText {
                element,
                text,
                submit,
            } => format!(
                "ввести в {} на {site}{}:\n«{}»",
                el(element),
                if *submit {
                    " и отправить форму"
                } else {
                    ""
                },
                page::clean_line(text)
            ),
            ToolCall::Navigate { url } => format!("открыть {}", page::clean_line(url)),
            other => tools::summary(other),
        }
    }

    async fn execute(&mut self, name: &str, input: &Value) -> Done {
        let call = match tools::parse(name, input) {
            Ok(c) => c,
            Err(e) => return refused(e.describe()),
        };
        self.recent.push(call.clone());
        let repeats = self.recent.iter().rev().take_while(|c| **c == call).count();
        if repeats > MAX_REPEATS {
            self.shared.halt(Cause::Looping);
            return refused("Одно и то же действие повторяется; задача остановлена.");
        }
        self.post(&Event::Step(tools::summary(&call)));

        let access = load_access().await;
        let current = self.current(&access).await;
        let verdict = guard::decide(
            &call,
            &guard::Ctx {
                access: &access,
                current: current.as_ref(),
                snapshot: self.snapshot.as_ref(),
                read: &self.read,
                user_text: &self.user_text,
            },
        );
        match verdict {
            Verdict::Allow => {}
            Verdict::Block(why) => {
                self.post(&Event::Step(format!("отказ политики: {why}")));
                return refused(format!("Политика отказала: {why}"));
            }
            Verdict::Confirm(reasons) => {
                let mut text = format!(
                    "Разрешить действие?\n{}",
                    self.describe(&call, current.as_ref())
                );
                for r in &reasons {
                    text.push_str(&format!("\n• {r}"));
                }
                if !self.ask(text).await {
                    self.post(&Event::Step("действие отклонено".into()));
                    return refused(
                        "Пользователь не разрешил это действие. Не пытайся сделать то же другим способом; \
спроси пользователя, как продолжить.",
                    );
                }
            }
        }
        if self.shared.stopped() {
            return refused("Остановлено пользователем.");
        }
        self.perform(&call, &access).await
    }

    async fn perform(&mut self, call: &ToolCall, access: &Access) -> Done {
        let Some(tab) = self.tab else {
            return refused("Нет рабочей вкладки.");
        };
        // Повторная проверка непосредственно перед действием: вкладка могла
        // уйти на другой сайт, пока ждали подтверждения.
        let current = self.current(access).await;
        match call {
            ToolCall::ReadPage => {
                let Some(origin) = current else {
                    return refused("Сайт рабочей вкладки закрыт политикой.");
                };
                let raw = in_tab(tab, &Value::obj(vec![("op", Value::str("snapshot"))])).await;
                let snapshot = match raw.as_ref().map(page::parse_snapshot) {
                    Some(Ok(s)) => s,
                    _ => return refused("Не удалось прочитать страницу."),
                };
                // Снимок обязан быть с того же сайта, что проверен.
                let same = policy::parse_url(&snapshot.origin).is_ok_and(|o| o == origin)
                    && access.check(&snapshot.url).is_ok_and(|o| o == origin);
                if !same {
                    self.snapshot = None;
                    return refused("Пока читали, вкладка ушла на другой сайт.");
                }
                self.note_read(&origin);
                let text = page::render(&snapshot);
                self.snapshot = Some(snapshot);
                Done {
                    text,
                    is_error: false,
                    origin: api::Origin::Page,
                }
            }
            ToolCall::Click { element }
            | ToolCall::TypeText { element, .. }
            | ToolCall::SelectOption { element, .. } => {
                let (Some(origin), Some(snapshot)) = (current, self.snapshot.as_ref()) else {
                    return refused("Сначала вызови read_page на разрешённом сайте.");
                };
                let Some(el) = snapshot.element(*element) else {
                    return refused("Элемента нет в последнем снимке.");
                };
                let (action, text, submit) = match call {
                    ToolCall::TypeText { text, submit, .. } => ("type", text.as_str(), *submit),
                    ToolCall::SelectOption { option, .. } => ("select", option.as_str(), false),
                    _ => ("click", "", false),
                };
                let op = Value::obj(vec![
                    ("op", Value::str("act")),
                    ("origin", Value::str(origin.to_string())),
                    ("version", Value::Num(snapshot.version as f64)),
                    ("id", Value::Num(f64::from(*element))),
                    ("action", Value::str(action)),
                    ("text", Value::str(text)),
                    ("submit", Value::Bool(submit)),
                    // Всё, на чём основано решение политики: если страница
                    // подменила адрес ссылки или формы после снимка, действие
                    // не выполняется.
                    (
                        "expect",
                        Value::obj(vec![
                            ("tag", Value::str(&el.tag)),
                            ("role", Value::str(el.role)),
                            ("name", Value::str(&el.name)),
                            ("type", Value::str(&el.kind)),
                            ("href", Value::str(&el.href)),
                            ("form", Value::Bool(el.form)),
                            ("formAction", Value::str(&el.form_action)),
                            ("submits", Value::Bool(el.submits)),
                            ("autocomplete", Value::str(&el.autocomplete)),
                            ("editable", Value::Bool(el.editable)),
                        ]),
                    ),
                ]);
                let outcome = match in_tab(tab, &op).await {
                    Some(v) => page::parse_act(&v),
                    None => ActOutcome::Refused("страница не ответила"),
                };
                match outcome {
                    ActOutcome::Done => {
                        wait_loaded(tab).await;
                        ours(
                            "Готово. Страница могла измениться: перед следующим действием вызови read_page.",
                        )
                    }
                    ActOutcome::Refused(why) => refused(format!("Действие не выполнено: {why}.")),
                }
            }
            ToolCall::Scroll { direction } => {
                let Some(origin) = current else {
                    return refused("Сайт рабочей вкладки закрыт политикой.");
                };
                let op = Value::obj(vec![
                    ("op", Value::str("scroll")),
                    ("origin", Value::str(origin.to_string())),
                    (
                        "direction",
                        Value::str(match direction {
                            Direction::Up => "up",
                            Direction::Down => "down",
                        }),
                    ),
                ]);
                match in_tab(tab, &op).await.map(|v| page::parse_act(&v)) {
                    Some(ActOutcome::Done) => {
                        ours("Прокручено. Вызови read_page, чтобы увидеть страницу.")
                    }
                    Some(ActOutcome::Refused(why)) => refused(format!("Не прокручено: {why}.")),
                    None => refused("Страница не ответила."),
                }
            }
            ToolCall::Navigate { url } => {
                // guard уже проверил адрес; проверка ещё раз — на случай,
                // если списки изменились за время подтверждения.
                if access.check(url).is_err() {
                    return refused("Адрес закрыт политикой.");
                }
                let props = Object::new();
                ext::set(&props, "url", &JsValue::from_str(url));
                if call_tab(ext::tabs_update(tab, &props)).await {
                    self.snapshot = None;
                    wait_loaded(tab).await;
                    ours("Переход выполнен. Вызови read_page.")
                } else {
                    refused("Переход не удался.")
                }
            }
            ToolCall::GoBack => {
                if call_tab(ext::tabs_go_back(tab)).await {
                    self.snapshot = None;
                    wait_loaded(tab).await;
                    ours("Вернулись назад. Вызови read_page.")
                } else {
                    refused("Назад перейти нельзя.")
                }
            }
            ToolCall::ListTabs => self.list_tabs(access).await,
            ToolCall::SwitchTab { tab: n } => {
                let Some(&target) = self.tabs.get(*n as usize - 1) else {
                    return refused("Нет вкладки с таким номером; вызови list_tabs.");
                };
                let allowed = match tab_url(target).await {
                    Some(url) => access.check(&url).is_ok(),
                    None => false,
                };
                if !allowed {
                    return refused("Сайт этой вкладки закрыт политикой.");
                }
                let props = Object::new();
                ext::set(&props, "active", &JsValue::TRUE);
                if call_tab(ext::tabs_update(target, &props)).await {
                    self.tab = Some(target);
                    self.snapshot = None;
                    ours("Вкладка выбрана. Вызови read_page.")
                } else {
                    refused("Не удалось переключить вкладку.")
                }
            }
        }
    }

    async fn list_tabs(&mut self, access: &Access) -> Done {
        let query = Object::new();
        ext::set(&query, "windowId", &JsValue::from_f64(self.window as f64));
        let Some(tabs) = call(ext::tabs_query(&query)).await else {
            return refused("Не удалось получить список вкладок.");
        };
        self.tabs.clear();
        let mut lines = Vec::new();
        for (i, tab) in js_sys::Array::from(&tabs).iter().enumerate().take(100) {
            let Some(id) = tab_id(&tab) else { continue };
            self.tabs.push(id);
            let n = i + 1;
            let mark = if Some(id) == self.tab {
                " (рабочая)"
            } else {
                ""
            };
            let url = ext::get(&tab, "url").and_then(|v| v.as_string());
            match url.as_deref().map(|u| access.check(u)) {
                Some(Ok(origin)) => {
                    let title = ext::get(&tab, "title")
                        .and_then(|v| v.as_string())
                        .unwrap_or_default();
                    let title: String = title.chars().take(200).collect();
                    lines.push(format!(
                        "[{n}] {origin} «{}»{mark}",
                        page::clean_line(&title)
                    ));
                    self.note_read(&origin);
                }
                _ => lines.push(format!("[{n}] закрытый сайт{mark}")),
            }
        }
        Done {
            text: lines.join("\n"),
            is_error: false,
            origin: api::Origin::Untrusted,
        }
    }
}

async fn call_tab(promise: Result<Promise, JsValue>) -> bool {
    call(promise).await.is_some()
}

fn user_texts(history: &[Turn]) -> String {
    let mut out = String::new();
    for turn in history.iter().filter(|t| t.role == Role::User) {
        for c in &turn.content {
            if let Content::Text(t) = c {
                out.push_str(t);
                out.push('\n');
            }
        }
    }
    out
}

/// Добавить текст пользователя: в последнюю реплику, если она пользователя
/// (после прерванной задачи там результаты инструментов), иначе новой.
pub(crate) fn push_user_text(history: &mut Vec<Turn>, text: String) {
    match history.last_mut() {
        Some(turn) if turn.role == Role::User => turn.content.push(Content::Text(text)),
        _ => history.push(Turn {
            role: Role::User,
            content: vec![Content::Text(text)],
        }),
    }
}

/// Диалог в допустимом для API виде: на каждый вызов есть результат.
fn close_open_calls(history: &mut Vec<Turn>, why: &str) {
    let Some(last) = history.last() else { return };
    if last.role != Role::Assistant {
        return;
    }
    let results: Vec<Content> = last
        .content
        .iter()
        .filter_map(|c| match c {
            Content::ToolUse { id, .. } => Some(Content::ToolResult {
                id: id.clone(),
                text: why.to_owned(),
                is_error: true,
                origin: api::Origin::Ours,
            }),
            _ => None,
        })
        .collect();
    if !results.is_empty() {
        history.push(Turn {
            role: Role::User,
            content: results,
        });
    }
}

/// Запуск задачи. `history` уже содержит текст пользователя.
pub(crate) async fn run(id: u64, window: u64, mut history: Vec<Turn>, shared: Shared) {
    let start_len = history.len();
    let mut usage = Usage::default();
    let result = run_loop(id, window, &mut history, &shared, &mut usage).await;
    let cause = shared.cause.get();
    match (&result, cause) {
        (_, Cause::Stopped) => background::post(id, &Event::Notice("Остановлено.".into())),
        (_, Cause::TimedOut) => {
            background::post(id, &Event::Error("Превышено время ожидания ответа.".into()));
        }
        (_, Cause::Looping) => background::post(
            id,
            &Event::Error("Агент зациклился на одном действии и остановлен.".into()),
        ),
        (Err(f), Cause::None) => background::post(id, &Event::Error(f.describe())),
        (Ok(()), Cause::None) => {}
    }
    if usage.input + usage.output > 0 {
        background::post(
            id,
            &Event::Notice(format!(
                "Расход: вход {} токенов, выход {} токенов.",
                usage.input, usage.output
            )),
        );
    }
    // Если модель так и не ответила, сообщение пользователя убирается:
    // повтор начнётся с того же места.
    if history.len() == start_len
        && result.is_err()
        && let Some(turn) = history.last_mut()
        && turn.role == Role::User
    {
        turn.content.pop();
        if turn.content.is_empty() {
            history.pop();
        }
    }
    close_open_calls(&mut history, "Задача прервана.");
    background::finish_task(id, shared.request, history);
}

async fn run_loop(
    id: u64,
    window: u64,
    history: &mut Vec<Turn>,
    shared: &Shared,
    usage: &mut Usage,
) -> Result<(), Failure> {
    let cfg = load_config().await?;
    let mut task = Task {
        id,
        window,
        tab: active_tab(window).await,
        snapshot: None,
        read: Vec::new(),
        tabs: Vec::new(),
        user_text: user_texts(history),
        recent: Vec::new(),
        shared: shared.clone(),
    };
    for step in 0..MAX_STEPS {
        if shared.stopped() {
            return Ok(());
        }
        if !api::history_fits(history, 0, 2) {
            return Err(Failure::TooLong);
        }
        let nonce = nonce().ok_or(Failure::Api(ApiError::Internal))?;
        let reply = {
            let timer = Timeout::start(shared, REQUEST_TIMEOUT_MS)?;
            let mut idle = Timeout::start(shared, IDLE_TIMEOUT_MS)?;
            let mut shown = (0.0, String::new());
            let req = api::Request {
                key: &cfg.key,
                model: cfg.model,
                max_tokens: cfg.max_tokens,
                history,
                nonce: &nonce,
            };
            let mut progress = |s: &Stream| {
                idle.rearm();
                let now = js_sys::Date::now();
                if now - shown.0 >= PARTIAL_INTERVAL_MS {
                    let text = s.text();
                    if !text.trim().is_empty() && text != shown.1 {
                        task.post(&Event::Partial(text.clone()));
                        shown = (now, text);
                    }
                }
            };
            let reply = api::complete(&req, &shared.controller.signal(), &mut progress).await;
            drop(timer);
            drop(idle);
            reply
        };
        if shared.stopped() {
            return Ok(());
        }
        let reply = reply.map_err(Failure::Api)?;
        usage.input += reply.usage.input;
        usage.output += reply.usage.output;
        let text = reply.text();
        if !text.trim().is_empty() {
            task.post(&Event::Reply(text));
        }
        history.push(Turn {
            role: Role::Assistant,
            content: reply.content.clone(),
        });
        match reply.stop {
            Stop::EndTurn => return Ok(()),
            Stop::MaxTokens => {
                task.post(&Event::Notice("Ответ обрезан по лимиту длины.".into()));
                return Ok(());
            }
            Stop::ToolUse => {}
        }
        let mut results = Vec::new();
        for (i, (call_id, name, input)) in reply.calls().enumerate() {
            let done = if i >= api::MAX_CALLS_PER_REPLY {
                refused("Слишком много вызовов в одном ответе; этот не выполнен.")
            } else if shared.stopped() {
                refused("Остановлено пользователем.")
            } else {
                task.execute(name, input).await
            };
            results.push(Content::ToolResult {
                id: call_id.to_owned(),
                text: done.text,
                is_error: done.is_error,
                origin: done.origin,
            });
        }
        history.push(Turn {
            role: Role::User,
            content: results,
        });
        if step + 1 == MAX_STEPS {
            task.post(&Event::Notice(format!(
                "Достигнут предел в {MAX_STEPS} шагов. Напишите, продолжать ли."
            )));
        }
    }
    Ok(())
}

/// Таймер запроса: по истечении прерывает задачу. Снимается при drop.
struct Timeout {
    handle: i32,
    ms: i32,
    cb: Closure<dyn FnMut()>,
}

impl Timeout {
    fn start(shared: &Shared, ms: i32) -> Result<Self, Failure> {
        let s = shared.clone();
        let cb = Closure::<dyn FnMut()>::new(move || s.halt(Cause::TimedOut));
        // Без таймера запрос не отправляется: лимит времени обязателен.
        let handle = web_sys::window()
            .and_then(|w| {
                w.set_timeout_with_callback_and_timeout_and_arguments_0(
                    cb.as_ref().unchecked_ref(),
                    ms,
                )
                .ok()
            })
            .ok_or(Failure::Api(ApiError::Internal))?;
        Ok(Self { handle, ms, cb })
    }

    /// Начать отсчёт заново. Если новый таймер не встал, остаётся старый.
    fn rearm(&mut self) {
        let Some(w) = web_sys::window() else { return };
        if let Ok(handle) = w.set_timeout_with_callback_and_timeout_and_arguments_0(
            self.cb.as_ref().unchecked_ref(),
            self.ms,
        ) {
            w.clear_timeout_with_handle(self.handle);
            self.handle = handle;
        }
    }
}

impl Drop for Timeout {
    fn drop(&mut self) {
        if let Some(w) = web_sys::window() {
            w.clear_timeout_with_handle(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool_use(id: &str) -> Content {
        Content::ToolUse {
            id: id.into(),
            name: "click".into(),
            input: Value::Obj(vec![]),
        }
    }

    #[test]
    fn open_calls_are_closed() {
        let mut h = vec![
            Turn {
                role: Role::User,
                content: vec![Content::Text("x".into())],
            },
            Turn {
                role: Role::Assistant,
                content: vec![Content::Text("ok".into()), tool_use("a"), tool_use("b")],
            },
        ];
        close_open_calls(&mut h, "прервано");
        assert_eq!(h.len(), 3);
        let ids: Vec<&str> = h[2]
            .content
            .iter()
            .filter_map(|c| match c {
                Content::ToolResult { id, is_error, .. } if *is_error => Some(id.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(ids, vec!["a", "b"]);
        // Следующий текст пользователя дописывается в ту же реплику.
        push_user_text(&mut h, "дальше".into());
        assert_eq!(h.len(), 3);
        assert_eq!(h[2].content.last(), Some(&Content::Text("дальше".into())));
        // Без открытых вызовов ничего не добавляется.
        let mut plain = vec![Turn {
            role: Role::Assistant,
            content: vec![Content::Text("ответ".into())],
        }];
        close_open_calls(&mut plain, "x");
        assert_eq!(plain.len(), 1);
        push_user_text(&mut plain, "новый".into());
        assert_eq!(plain.len(), 2);
    }

    #[test]
    fn user_texts_skip_tool_results() {
        let h = vec![
            Turn {
                role: Role::User,
                content: vec![
                    Content::Text("купи книгу".into()),
                    Content::ToolResult {
                        id: "t".into(),
                        text: "данные сайта".into(),
                        is_error: false,
                        origin: api::Origin::Page,
                    },
                ],
            },
            Turn {
                role: Role::Assistant,
                content: vec![Content::Text("модель".into())],
            },
        ];
        assert_eq!(user_texts(&h), "купи книгу\n");
    }

    // push_user_text должен объединять текст в одну реплику, если последняя — user.
    #[test]
    fn push_user_text_merging() {
        // Пустая история: новая реплика.
        let mut h: Vec<Turn> = vec![];
        push_user_text(&mut h, "первый".into());
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].role, Role::User);
        assert_eq!(h[0].content, vec![Content::Text("первый".into())]);

        // Последняя — user: дописываем в ту же.
        push_user_text(&mut h, "второй".into());
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].content.len(), 2);
        assert_eq!(h[0].content[1], Content::Text("второй".into()));

        // Последняя — assistant: новая реплика.
        h.push(Turn {
            role: Role::Assistant,
            content: vec![Content::Text("ответ".into())],
        });
        push_user_text(&mut h, "третий".into());
        assert_eq!(h.len(), 3);
        assert_eq!(h[2].role, Role::User);
        assert_eq!(h[2].content[0], Content::Text("третий".into()));
    }

    // close_open_calls: каждый tool_use превращается в tool_result с ошибкой.
    #[test]
    fn close_open_calls_comprehensive() {
        // История заканчивается на assistant с множеством вызовов.
        let mut h = vec![
            Turn {
                role: Role::User,
                content: vec![Content::Text("задача".into())],
            },
            Turn {
                role: Role::Assistant,
                content: vec![
                    Content::Text("выполню".into()),
                    tool_use("call1"),
                    Content::Text("также".into()),
                    tool_use("call2"),
                    tool_use("call3"),
                ],
            },
        ];

        close_open_calls(&mut h, "прервано");

        // Должна добавиться user-реплика с результатами всех трёх вызовов.
        assert_eq!(h.len(), 3);
        assert_eq!(h[2].role, Role::User);
        assert_eq!(h[2].content.len(), 3);

        // Каждый результат — ошибка с текстом "прервано" и origin Ours.
        for content in &h[2].content {
            match content {
                Content::ToolResult {
                    id,
                    text,
                    is_error,
                    origin,
                } => {
                    assert_eq!(text, "прервано");
                    assert!(*is_error);
                    assert_eq!(*origin, api::Origin::Ours);
                    assert!(id == "call1" || id == "call2" || id == "call3");
                }
                _ => panic!("expected ToolResult, got {content:?}"),
            }
        }

        // Если последняя реплика не assistant, ничего не добавляется.
        let mut user_last = vec![Turn {
            role: Role::User,
            content: vec![Content::Text("x".into())],
        }];
        close_open_calls(&mut user_last, "error");
        assert_eq!(user_last.len(), 1);

        // Если assistant без tool_use, ничего не добавляется.
        let mut no_calls = vec![Turn {
            role: Role::Assistant,
            content: vec![Content::Text("готово".into())],
        }];
        close_open_calls(&mut no_calls, "error");
        assert_eq!(no_calls.len(), 1);
    }

    // Сценарий: перерванная задача → close_open_calls → push_user_text.
    #[test]
    fn interrupted_task_recovery() {
        // История с незавершёнными tool_use.
        let mut h = vec![
            Turn {
                role: Role::User,
                content: vec![Content::Text("купи".into())],
            },
            Turn {
                role: Role::Assistant,
                content: vec![tool_use("t1")],
            },
        ];

        // Прерывание: закрываем вызовы.
        close_open_calls(&mut h, "timeout");
        assert_eq!(h.len(), 3);

        // Следующий push добавляет текст В ТУ ЖЕ user-реплику.
        push_user_text(&mut h, "ещё попробуй".into());
        assert_eq!(h.len(), 3);
        assert_eq!(h[2].content.len(), 2);
        assert_eq!(h[2].content[1], Content::Text("ещё попробуй".into()));
    }

    // user_texts должен собирать ТОЛЬКО текст из user-реплик, пропуская tool_results.
    #[test]
    fn user_texts_comprehensive() {
        let h = vec![
            // Первая user-реплика с текстом и tool_result.
            Turn {
                role: Role::User,
                content: vec![
                    Content::Text("задача 1".into()),
                    Content::ToolResult {
                        id: "t1".into(),
                        text: "результат 1".into(),
                        is_error: false,
                        origin: api::Origin::Page,
                    },
                    Content::Text("продолжение".into()),
                ],
            },
            // Assistant реплика (пропускается).
            Turn {
                role: Role::Assistant,
                content: vec![Content::Text("ответ".into())],
            },
            // Вторая user-реплика.
            Turn {
                role: Role::User,
                content: vec![Content::Text("задача 2".into())],
            },
        ];

        let result = user_texts(&h);
        assert_eq!(result, "задача 1\nпродолжение\nзадача 2\n");
    }

    // Граница: пустая история, только assistant, только tool_results.
    #[test]
    fn user_texts_edge_cases() {
        // Пустая история.
        assert_eq!(user_texts(&[]), "");

        // Только assistant репликы.
        let only_assistant = vec![Turn {
            role: Role::Assistant,
            content: vec![Content::Text("только модель".into())],
        }];
        assert_eq!(user_texts(&only_assistant), "");

        // User реплика только с tool_results (без Text).
        let only_results = vec![Turn {
            role: Role::User,
            content: vec![Content::ToolResult {
                id: "t".into(),
                text: "данные".into(),
                is_error: false,
                origin: api::Origin::Page,
            }],
        }];
        assert_eq!(user_texts(&only_results), "");

        // Пустые Text блоки должны добавлять newline.
        let empty_text = vec![Turn {
            role: Role::User,
            content: vec![Content::Text("".into())],
        }];
        assert_eq!(user_texts(&empty_text), "\n");
    }
}
