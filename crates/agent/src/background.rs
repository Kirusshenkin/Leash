//! Background: принимает порт панели, ведёт диалог, запускает задачи агента.
//!
//! Закрытие панели (порта) прерывает задачу. Открытый порт сам по себе НЕ
//! держит event page живой: пока идёт задача, панель шлёт `ping`, и каждое
//! входящее сообщение сбрасывает idle-таймер Firefox.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use js_sys::Function;
use js_sys::futures::spawn_local;
use wasm_bindgen::prelude::*;

use crate::agent::{self, Shared};
use crate::api::{self, Turn};
use crate::ext::{self, Port};
use crate::protocol::{self, Command, Event, Rejected};
use crate::settings;

/// Почему задача остановлена извне цикла.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cause {
    None,
    Stopped,
    TimedOut,
    Looping,
}

struct Session {
    port: Port,
    history: Vec<Turn>,
    task: Option<Shared>,
}

impl Session {
    fn post(&self, event: &Event) {
        self.port.post(&protocol::event_to_js(event));
    }
}

thread_local! {
    static SESSIONS: RefCell<HashMap<u64, Session>> = RefCell::new(HashMap::new());
    static NEXT_ID: Cell<u64> = const { Cell::new(1) };
}

pub(crate) fn next_id() -> u64 {
    NEXT_ID.with(|n| {
        let id = n.get();
        n.set(id + 1);
        id
    })
}

/// Событие в панель сессии, если она ещё открыта.
pub(crate) fn post(id: u64, event: &Event) {
    with_session(id, |s| s.post(event));
}

/// Вызывается JS-мостом на `runtime.onConnect`.
#[wasm_bindgen]
pub fn on_connect(port: Port) {
    let own_id = ext::runtime_id().unwrap_or_default();
    let sidebar_url = ext::runtime_get_url("sidebar/sidebar.html");
    let sender = protocol::sender_from_js(&port.sender());
    if !protocol::is_sidebar_sender(&port.name(), &sender, &own_id, &sidebar_url) {
        port.disconnect();
        return;
    }
    forget_legacy_key();

    let id = next_id();
    // Слушатели отдаются во владение JS: освобождаются вместе с портом.
    let on_message: Function =
        Closure::<dyn FnMut(JsValue)>::new(move |msg: JsValue| handle_message(id, &msg))
            .into_js_value()
            .unchecked_into();
    let on_disconnect: Function =
        Closure::<dyn FnMut(JsValue)>::new(move |_: JsValue| close_session(id))
            .into_js_value()
            .unchecked_into();

    SESSIONS.with_borrow_mut(|s| {
        s.insert(
            id,
            Session {
                port: port.clone(),
                history: Vec::new(),
                task: None,
            },
        );
    });
    port.on_message().add_listener(&on_message);
    port.on_disconnect().add_listener(&on_disconnect);
    port.post(&protocol::event_to_js(&Event::Ready));
}

/// Горячая клавиша аварийной остановки (manifest `commands`).
#[wasm_bindgen]
pub fn on_command(name: &str) {
    if name != "leash-stop" {
        return;
    }
    SESSIONS.with_borrow(|s| {
        for session in s.values() {
            if let Some(task) = &session.task {
                task.halt(Cause::Stopped);
            }
        }
    });
}

/// Этап 1 хранил ключ в `storage.local`, доступной content-скриптам.
fn forget_legacy_key() {
    let _ = ext::storage_local_remove(&ext::strings(&[
        settings::KEY_API_KEY,
        settings::KEY_API_KEY_HINT,
    ]));
}

fn close_session(id: u64) {
    let session = SESSIONS.with_borrow_mut(|s| s.remove(&id));
    if let Some(task) = session.and_then(|s| s.task) {
        task.halt(Cause::Stopped);
    }
}

/// Нарушение протокола от собственной панели: это баг или компрометация,
/// поэтому сессия закрывается целиком.
fn drop_session(id: u64) {
    let session = SESSIONS.with_borrow_mut(|s| s.remove(&id));
    if let Some(session) = session {
        if let Some(task) = &session.task {
            task.halt(Cause::Stopped);
        }
        session.port.disconnect();
    }
}

fn handle_message(id: u64, msg: &JsValue) {
    let Some(raw) = protocol::raw_from_js(msg) else {
        return drop_session(id);
    };
    match protocol::parse_command(&raw) {
        Ok(Command::Chat { text, window }) => start_task(id, text, window),
        Ok(Command::Stop) => with_session(id, |s| {
            if let Some(task) = &s.task {
                task.halt(Cause::Stopped);
            }
        }),
        Ok(Command::Reset) => reset(id),
        Ok(Command::Confirm { id: confirm, allow }) => with_session(id, |s| {
            if let Some(task) = &s.task {
                task.answer(Some(confirm), allow);
            }
        }),
        // Само получение сообщения продлевает жизнь event page.
        Ok(Command::Ping) => {}
        Err(Rejected::EmptyText) => {}
        Err(Rejected::TextTooLong) => with_session(id, |s| {
            s.post(&Event::Error("Сообщение слишком длинное.".into()));
        }),
        Err(Rejected::UnknownType | Rejected::BadShape) => drop_session(id),
    }
}

fn with_session(id: u64, f: impl FnOnce(&mut Session)) {
    SESSIONS.with_borrow_mut(|s| {
        if let Some(session) = s.get_mut(&id) {
            f(session);
        }
    });
}

fn start_task(id: u64, text: String, window: u64) {
    let mut job = None;
    with_session(id, |s| {
        if s.task.is_some() {
            return s.post(&Event::Error("Дождитесь ответа или нажмите «Стоп».".into()));
        }
        if !api::history_fits(&s.history, text.chars().count(), 2) {
            return s.post(&Event::Error(
                "Диалог слишком длинный. Нажмите «Новый чат».".into(),
            ));
        }
        let Some(shared) = Shared::new() else {
            return s.post(&Event::Error(api::ApiError::Internal.describe()));
        };
        let mut history = std::mem::take(&mut s.history);
        agent::push_user_text(&mut history, text);
        s.task = Some(shared.clone());
        s.post(&Event::Busy(true));
        job = Some((history, shared));
    });
    if let Some((history, shared)) = job {
        spawn_local(agent::run(id, window, history, shared));
    }
}

/// Задача закончилась: диалог возвращается в сессию.
pub(crate) fn finish_task(id: u64, request: u64, history: Vec<Turn>) {
    with_session(id, |s| {
        // Если за время задачи нажали «Новый чат», старый диалог не нужен,
        // а слот задачи может принадлежать уже новой.
        if s.task.take_if(|t| t.request == request).is_some() {
            s.history = history;
            s.post(&Event::Busy(false));
        }
    });
}

fn reset(id: u64) {
    with_session(id, |s| {
        if let Some(task) = s.task.take() {
            task.halt(Cause::Stopped);
        }
        s.history.clear();
        s.post(&Event::Busy(false));
        s.post(&Event::Notice("Новый чат.".into()));
    });
}
