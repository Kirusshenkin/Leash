//! Боковая панель: задачи агенту, журнал шагов, подтверждения, «Стоп»,
//! «Новый чат». Вывод только через textContent.

use std::cell::{Cell, RefCell};

use js_sys::futures::{JsFuture, spawn_local};
use js_sys::{Function, Object};
use wasm_bindgen::prelude::*;
use web_sys::{Element, HtmlElement, HtmlTextAreaElement, KeyboardEvent};

use crate::dom;
use crate::ext::{self, Port};
use crate::protocol::{self, Command, Event};

struct Ui {
    log: Element,
    input: HtmlTextAreaElement,
    send: HtmlElement,
    status: Element,
    confirm: Element,
    confirm_text: Element,
}

thread_local! {
    static UI: RefCell<Option<Ui>> = const { RefCell::new(None) };
    static PORT: RefCell<Option<Port>> = const { RefCell::new(None) };
    /// Номер текущего подключения: события старого порта игнорируются.
    static CONNECTION: Cell<u64> = const { Cell::new(0) };
    static READY: Cell<bool> = const { Cell::new(false) };
    static BUSY: Cell<bool> = const { Cell::new(false) };
    /// Отправить ввод, как только новое подключение станет готовым.
    static SEND_ON_READY: Cell<bool> = const { Cell::new(false) };
    /// Окно, в котором открыта панель: агент работает в его активной вкладке.
    static WINDOW: Cell<Option<u64>> = const { Cell::new(None) };
    /// Номер запроса подтверждения, который сейчас показан.
    static PENDING: Cell<Option<u64>> = const { Cell::new(None) };
}

/// Период ping, пока ждём ответа. Меньше idle-таймаута event page (~30 с).
const PING_INTERVAL_MS: i32 = 20_000;
/// Сколько сообщений хранит лог панели; старые удаляются.
const MAX_LOG_ENTRIES: u32 = 400;

#[wasm_bindgen]
pub fn start_sidebar() -> Result<(), JsValue> {
    let doc = dom::document()?;
    let ui = Ui {
        log: dom::by_id(&doc, "log")?,
        input: dom::by_id(&doc, "input")?,
        send: dom::by_id(&doc, "send")?,
        status: dom::by_id(&doc, "status")?,
        confirm: dom::by_id(&doc, "confirm")?,
        confirm_text: dom::by_id(&doc, "confirm-text")?,
    };
    let allow: HtmlElement = dom::by_id(&doc, "confirm-allow")?;
    let deny: HtmlElement = dom::by_id(&doc, "confirm-deny")?;
    dom::on(&allow, "click", |_| answer(true))?;
    dom::on(&deny, "click", |_| answer(false))?;
    let stop: HtmlElement = dom::by_id(&doc, "stop")?;
    let reset: HtmlElement = dom::by_id(&doc, "reset")?;
    let settings: HtmlElement = dom::by_id(&doc, "settings")?;

    dom::on(&ui.send, "click", |_| send_input())?;
    dom::on(&ui.input, "keydown", |e| {
        if let Some(k) = e.dyn_ref::<KeyboardEvent>()
            && k.key() == "Enter"
            && !k.shift_key()
            && !k.is_composing()
        {
            e.prevent_default();
            send_input();
        }
    })?;
    // «Стоп» не блокируется никогда.
    dom::on(&stop, "click", |_| post(&Command::Stop))?;
    dom::on(&reset, "click", |_| post(&Command::Reset))?;
    dom::on(&settings, "click", |_| {
        let _ = ext::runtime_open_options_page();
    })?;

    let ping = Closure::<dyn FnMut()>::new(|| {
        if READY.get() && BUSY.get() {
            post(&Command::Ping);
        }
    });
    web_sys::window()
        .ok_or_else(|| JsValue::from_str("нет window"))?
        .set_interval_with_callback_and_timeout_and_arguments_0(
            ping.as_ref().unchecked_ref(),
            PING_INTERVAL_MS,
        )?;
    // Таймер работает до закрытия панели.
    ping.forget();

    UI.set(Some(ui));
    spawn_local(find_window());
    connect();
    Ok(())
}

fn connect() {
    let conn = CONNECTION.with(|c| {
        c.set(c.get() + 1);
        c.get()
    });
    let info = Object::new();
    ext::set(&info, "name", &JsValue::from_str(protocol::PORT_NAME));
    let port = ext::runtime_connect(&info);

    let on_message: Function = Closure::<dyn FnMut(JsValue)>::new(move |msg: JsValue| {
        if CONNECTION.get() == conn {
            on_event(&msg);
        }
    })
    .into_js_value()
    .unchecked_into();
    let on_disconnect: Function = Closure::<dyn FnMut(JsValue)>::new(move |_: JsValue| {
        if CONNECTION.get() == conn {
            PORT.set(None);
            READY.set(false);
            BUSY.set(false);
            hide_confirm();
            show(
                "notice",
                "Связь с фоном потеряна, контекст диалога сброшен. Следующее сообщение начнёт новый чат.",
            );
            update_controls();
        }
    })
    .into_js_value()
    .unchecked_into();
    port.on_message().add_listener(&on_message);
    port.on_disconnect().add_listener(&on_disconnect);

    PORT.set(Some(port));
    READY.set(false);
    BUSY.set(false);
    update_controls();
}

fn post(cmd: &Command) {
    PORT.with_borrow(|p| {
        if let Some(port) = p {
            port.post(&protocol::command_to_js(cmd));
        }
    });
}

fn send_input() {
    if PORT.with_borrow(Option::is_none) {
        // Старый лог не соответствует новому (пустому) контексту фона.
        clear_log();
        show("notice", "Новый чат.");
        SEND_ON_READY.set(true);
        connect();
        return;
    }
    if !READY.get() || BUSY.get() {
        return;
    }
    let Some(text) = UI.with_borrow(|ui| ui.as_ref().map(|u| u.input.value())) else {
        return;
    };
    if text.trim().is_empty() {
        return;
    }
    if text.chars().count() > protocol::MAX_USER_TEXT_CHARS {
        show("error", "Сообщение слишком длинное.");
        return;
    }
    let Some(window) = WINDOW.get() else {
        show(
            "error",
            "Не удалось определить окно панели. Откройте панель заново.",
        );
        return;
    };
    show("user", text.trim());
    post(&Command::Chat { text, window });
    UI.with_borrow(|ui| {
        if let Some(u) = ui {
            u.input.set_value("");
        }
    });
    BUSY.set(true);
    update_controls();
}

fn on_event(msg: &JsValue) {
    let event = protocol::raw_from_js(msg).map(|raw| protocol::parse_event(&raw));
    match event {
        Some(Ok(Event::Ready)) => {
            READY.set(true);
            if SEND_ON_READY.replace(false) {
                update_controls();
                return send_input();
            }
        }
        Some(Ok(Event::Busy(busy))) => {
            BUSY.set(busy);
            if !busy {
                hide_confirm();
            }
        }
        Some(Ok(Event::Step(text))) => show("step", &format!("→ {text}")),
        Some(Ok(Event::Confirm { id, text })) => show_confirm(id, &text),
        Some(Ok(Event::Reply(text))) => show("assistant", &text),
        Some(Ok(Event::Error(text))) => show("error", &text),
        Some(Ok(Event::Notice(text))) => show("notice", &text),
        Some(Err(_)) | None => show("error", "Отклонено некорректное сообщение от фона."),
    }
    update_controls();
}

fn show(class: &str, text: &str) {
    UI.with_borrow(|ui| {
        if let Some(u) = ui {
            let text = protocol::display_text(text);
            let _ = dom::append_text(&u.log, &format!("msg {class}"), &text);
            while u.log.child_element_count() > MAX_LOG_ENTRIES {
                match u.log.first_element_child() {
                    Some(first) => first.remove(),
                    None => break,
                }
            }
            u.log.set_scroll_top(u.log.scroll_height());
        }
    });
}

fn clear_log() {
    UI.with_borrow(|ui| {
        if let Some(u) = ui {
            u.log.set_text_content(None);
        }
    });
}

fn update_controls() {
    let (ready, busy) = (READY.get(), BUSY.get());
    UI.with_borrow(|ui| {
        if let Some(u) = ui {
            u.input.set_disabled(!ready);
            dom::set_disabled(&u.send, !ready || busy);
            let status = match (ready, busy) {
                (false, _) => "Подключение…",
                (true, true) => "Агент работает… (Стоп или Alt+Shift+X — остановить)",
                (true, false) => "",
            };
            u.status.set_text_content(Some(status));
        }
    });
}

/// Номер окна панели. Без него задача не отправляется.
async fn find_window() {
    let Ok(promise) = ext::windows_get_current() else {
        return;
    };
    let id = JsFuture::from(promise)
        .await
        .ok()
        .and_then(|w| ext::get(&w, "id"))
        .and_then(|v| v.as_f64())
        .filter(|n| n.fract() == 0.0 && *n >= 0.0 && *n < 9.0e15);
    // Целое неотрицательное в пределах точности f64 проверено выше.
    WINDOW.set(id.map(|n| n as u64));
}

/// Запрос подтверждения. Текст строит background из проверенных фактов;
/// показывается только как текст.
fn show_confirm(id: u64, text: &str) {
    PENDING.set(Some(id));
    UI.with_borrow(|ui| {
        if let Some(u) = ui {
            u.confirm_text
                .set_text_content(Some(&protocol::display_text(text)));
            let _ = u.confirm.remove_attribute("hidden");
        }
    });
}

fn hide_confirm() {
    PENDING.set(None);
    UI.with_borrow(|ui| {
        if let Some(u) = ui {
            let _ = u.confirm.set_attribute("hidden", "");
            u.confirm_text.set_text_content(None);
        }
    });
}

fn answer(allow: bool) {
    let Some(id) = PENDING.get() else { return };
    hide_confirm();
    show(
        "step",
        if allow {
            "✓ разрешено"
        } else {
            "✗ отклонено"
        },
    );
    post(&Command::Confirm { id, allow });
}
