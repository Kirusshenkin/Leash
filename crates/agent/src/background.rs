//! Background: держит порт моста (native messaging), выполняет вызовы
//! Claude через `bridge`, принимает порты панели и окна подтверждения.
//!
//! Открытый native-порт не даёт Firefox выгрузить event page (Firefox 104+),
//! поэтому, пока мост подключён, состояние сеансов живёт в памяти.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use js_sys::Function;
use js_sys::futures::spawn_local;
use wasm_bindgen::prelude::*;

use crate::bridge;
use crate::confirm;
use crate::ext::{self, Port};
use crate::protocol::{self, Command, Event, Native};
use crate::value;

thread_local! {
    static NATIVE: RefCell<Option<Port>> = const { RefCell::new(None) };
    static SIDEBARS: RefCell<HashMap<u64, Port>> = RefCell::new(HashMap::new());
    static PAUSED: Cell<bool> = const { Cell::new(false) };
    /// Мост поздоровался: порт открыт и процесс моста работает.
    static GREETED: Cell<bool> = const { Cell::new(false) };
    /// Последнее состояние моста для новых панелей.
    static STATUS: RefCell<String> = RefCell::new("Мост не подключён.".into());
    static NEXT_ID: Cell<u64> = const { Cell::new(1) };
}

pub(crate) fn next_id() -> u64 {
    NEXT_ID.with(|n| {
        let id = n.get();
        n.set(id + 1);
        id
    })
}

/// Остановлен ли Leash пользователем.
pub(crate) fn paused() -> bool {
    PAUSED.get()
}

/// Событие во все открытые панели.
pub(crate) fn broadcast(event: &Event) {
    let msg = protocol::to_js(&protocol::event_value(event));
    SIDEBARS.with_borrow(|s| {
        for port in s.values() {
            port.post(&msg);
        }
    });
}

fn status_event() -> Event {
    Event::Status {
        connected: GREETED.get() && NATIVE.with_borrow(Option::is_some),
        paused: PAUSED.get(),
        text: STATUS.with_borrow(Clone::clone),
    }
}

fn set_status(text: &str) {
    STATUS.with_borrow_mut(|s| *s = text.to_owned());
    broadcast(&status_event());
}

/// Подключение к мосту; вызывается при загрузке background и по кнопке.
#[wasm_bindgen]
pub fn start_bridge() {
    if NATIVE.with_borrow(Option::is_some) {
        return;
    }
    let port = match ext::runtime_connect_native(leash_core::NATIVE_APP) {
        Ok(p) => p,
        Err(_) => return set_status("Не удалось запустить мост."),
    };
    let on_message: Function =
        Closure::<dyn FnMut(JsValue)>::new(move |msg: JsValue| on_native(&msg))
            .into_js_value()
            .unchecked_into();
    let on_disconnect: Function = Closure::<dyn FnMut(JsValue)>::new(move |p: JsValue| {
        NATIVE.with_borrow_mut(|n| *n = None);
        GREETED.set(false);
        // Причину Firefox кладёт в port.error: обычно мост не установлен.
        let detail = ext::get(&p, "error")
            .and_then(|e| ext::get(&e, "message"))
            .and_then(|m| m.as_string())
            .unwrap_or_default();
        set_status(&format!(
            "Мост не подключён{}. Установите его: leash-host install, затем перезапустите Firefox.",
            if detail.is_empty() {
                String::new()
            } else {
                format!(" ({})", protocol::display_text(&detail))
            }
        ));
    })
    .into_js_value()
    .unchecked_into();
    port.on_message().add_listener(&on_message);
    port.on_disconnect().add_listener(&on_disconnect);
    NATIVE.with_borrow_mut(|n| *n = Some(port));
    set_status("Подключаюсь к мосту…");
}

fn on_native(msg: &JsValue) {
    match value::from_js(msg).and_then(|v| protocol::parse_native(&v)) {
        Some(Native::Call {
            id,
            session,
            tool,
            input,
        }) => spawn_local(async move {
            let (text, is_error) = bridge::call_tool(session, &tool, &input).await;
            let reply = protocol::to_js(&protocol::native_reply(id, &text, is_error));
            NATIVE.with_borrow(|n| {
                if let Some(port) = n {
                    port.post(&reply);
                }
            });
        }),
        Some(Native::End { session }) => bridge::end_session(session),
        Some(Native::Hello { version }) => {
            GREETED.set(true);
            set_status(&format!(
                "Мост {version} подключён: Claude может работать на разрешённых сайтах."
            ))
        }
        // Мост — наш процесс; мусор от него игнорируется, а не исполняется.
        None => {}
    }
}

/// Вызывается JS-мостом на `runtime.onConnect`.
#[wasm_bindgen]
pub fn on_connect(port: Port) {
    let own_id = ext::runtime_id().unwrap_or_default();
    let sender = protocol::sender_from_js(&port.sender());
    let sidebar_url = ext::runtime_get_url("sidebar/sidebar.html");
    if protocol::is_sidebar_sender(&port.name(), &sender, &own_id, &sidebar_url) {
        return open_sidebar(port);
    }
    let confirm_url = ext::runtime_get_url("confirm/confirm.html");
    match protocol::confirm_sender(&port.name(), &sender, &own_id, &confirm_url) {
        Some(id) => confirm::on_connect(port, id),
        None => port.disconnect(),
    }
}

fn open_sidebar(port: Port) {
    let id = next_id();
    let on_message: Function =
        Closure::<dyn FnMut(JsValue)>::new(move |msg: JsValue| on_sidebar(id, &msg))
            .into_js_value()
            .unchecked_into();
    let on_disconnect: Function = Closure::<dyn FnMut(JsValue)>::new(move |_: JsValue| {
        SIDEBARS.with_borrow_mut(|s| s.remove(&id));
    })
    .into_js_value()
    .unchecked_into();
    port.on_message().add_listener(&on_message);
    port.on_disconnect().add_listener(&on_disconnect);
    port.post(&protocol::to_js(&protocol::event_value(&status_event())));
    SIDEBARS.with_borrow_mut(|s| s.insert(id, port));
    // Панель открыли — хороший момент попробовать подключиться снова.
    start_bridge();
}

fn on_sidebar(id: u64, msg: &JsValue) {
    match value::from_js(msg).and_then(|v| protocol::parse_command(&v)) {
        Some(Command::Stop) => stop(),
        Some(Command::Resume) => {
            PAUSED.set(false);
            broadcast(&Event::Notice(
                "Leash снова принимает команды Claude.".into(),
            ));
            broadcast(&status_event());
        }
        Some(Command::Connect) => start_bridge(),
        Some(Command::Reset) => {
            bridge::forget_all();
            broadcast(&Event::Notice(
                "Сеансы сброшены: прочитанные сайты и признаки инъекций забыты.".into(),
            ));
        }
        // Нарушение протокола своей же панелью: порт закрывается.
        None => {
            if let Some(port) = SIDEBARS.with_borrow_mut(|s| s.remove(&id)) {
                port.disconnect();
            }
        }
    }
}

fn stop() {
    PAUSED.set(true);
    confirm::deny_all();
    broadcast(&Event::Notice(
        "Остановлено. Claude получит отказ на каждый вызов, пока вы не нажмёте «Продолжить»."
            .into(),
    ));
    broadcast(&status_event());
}

/// Горячая клавиша аварийной остановки (manifest `commands`).
#[wasm_bindgen]
pub fn on_command(name: &str) {
    if name == "leash-stop" {
        stop();
    }
}
