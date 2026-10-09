//! Боковая панель: состояние моста, журнал того, что делает Claude, и
//! кнопки «Стоп»/«Продолжить», «Подключить мост», «Сбросить сеансы».
//! Вывод только через textContent.

use std::cell::{Cell, RefCell};

use js_sys::{Function, Object};
use wasm_bindgen::prelude::*;
use web_sys::{Element, HtmlElement};

use crate::dom;
use crate::ext::{self, Port};
use crate::protocol::{self, Command, Event};
use crate::value;

struct Ui {
    log: Element,
    status: Element,
    stop: HtmlElement,
}

thread_local! {
    static UI: RefCell<Option<Ui>> = const { RefCell::new(None) };
    static PORT: RefCell<Option<Port>> = const { RefCell::new(None) };
    static PAUSED: Cell<bool> = const { Cell::new(false) };
}

/// Сколько записей хранит журнал; старые удаляются.
const MAX_LOG_ENTRIES: u32 = 400;

#[wasm_bindgen]
pub fn start_sidebar() -> Result<(), JsValue> {
    let doc = dom::document()?;
    let ui = Ui {
        log: dom::by_id(&doc, "log")?,
        status: dom::by_id(&doc, "status")?,
        stop: dom::by_id(&doc, "stop")?,
    };
    let connect: HtmlElement = dom::by_id(&doc, "connect")?;
    let reset: HtmlElement = dom::by_id(&doc, "reset")?;
    let settings: HtmlElement = dom::by_id(&doc, "settings")?;
    // «Стоп» не блокируется никогда.
    dom::on(&ui.stop, "click", |_| {
        post(if PAUSED.get() {
            Command::Resume
        } else {
            Command::Stop
        })
    })?;
    dom::on(&connect, "click", |_| {
        if PORT.with_borrow(Option::is_none) {
            connect_port();
        }
        post(Command::Connect);
    })?;
    dom::on(&reset, "click", |_| post(Command::Reset))?;
    dom::on(&settings, "click", |_| {
        let _ = ext::runtime_open_options_page();
    })?;
    UI.with_borrow_mut(|u| *u = Some(ui));
    connect_port();
    Ok(())
}

fn connect_port() {
    let info = Object::new();
    ext::set(&info, "name", &JsValue::from_str(protocol::SIDEBAR_PORT));
    let port = ext::runtime_connect(&info);
    let on_message: Function = Closure::<dyn FnMut(JsValue)>::new(|msg: JsValue| {
        match value::from_js(&msg).and_then(|v| protocol::parse_event(&v)) {
            Some(event) => show(event),
            None => show(Event::Error(
                "Отклонено некорректное сообщение от фона.".into(),
            )),
        }
    })
    .into_js_value()
    .unchecked_into();
    let on_disconnect: Function = Closure::<dyn FnMut(JsValue)>::new(|_: JsValue| {
        PORT.with_borrow_mut(|p| *p = None);
        set_status("Нет связи с фоном расширения. Нажмите «Подключить мост».");
    })
    .into_js_value()
    .unchecked_into();
    port.on_message().add_listener(&on_message);
    port.on_disconnect().add_listener(&on_disconnect);
    PORT.with_borrow_mut(|p| *p = Some(port));
}

fn post(cmd: Command) {
    let msg = protocol::to_js(&protocol::command_value(cmd));
    PORT.with_borrow(|p| {
        if let Some(port) = p {
            port.post(&msg);
        }
    });
}

fn show(event: Event) {
    match event {
        Event::Status {
            connected,
            paused,
            text,
        } => {
            PAUSED.set(paused);
            UI.with_borrow(|u| {
                if let Some(u) = u {
                    u.stop.set_text_content(Some(if paused {
                        "Продолжить"
                    } else {
                        "Стоп"
                    }));
                    u.status
                        .set_class_name(if connected { "status ok" } else { "status" });
                }
            });
            set_status(&text);
        }
        Event::Step(t) => append("step", &format!("→ {t}")),
        Event::Notice(t) => append("notice", &t),
        Event::Error(t) => append("error", &t),
    }
}

fn set_status(text: &str) {
    UI.with_borrow(|u| {
        if let Some(u) = u {
            u.status
                .set_text_content(Some(&protocol::display_text(text)));
        }
    });
}

fn append(class: &str, text: &str) {
    UI.with_borrow(|u| {
        let Some(u) = u else { return };
        let _ = dom::append_text(
            &u.log,
            &format!("msg {class}"),
            &protocol::display_text(text),
        );
        while u.log.child_element_count() > MAX_LOG_ENTRIES {
            if let Some(first) = u.log.first_element_child() {
                first.remove();
            }
        }
        u.log.set_scroll_top(u.log.scroll_height());
    });
}
