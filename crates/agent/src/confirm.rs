//! Подтверждение действия пользователем в отдельном окне Firefox.
//!
//! Окно — страница расширения: сайт не может ни показать его, ни нажать в
//! нём кнопку. Номер вопроса — в адресе окна; background сверяет его с
//! отправителем порта. Нет ответа за 5 минут, закрытое окно или «Стоп» —
//! это «нет».

use std::cell::RefCell;
use std::collections::HashMap;

use js_sys::futures::JsFuture;
use js_sys::{Function, Object, Promise};
use wasm_bindgen::prelude::*;
use web_sys::Element;

use crate::background;
use crate::dom;
use crate::ext::{self, Port};
use crate::protocol::{self, Event};
use crate::value;

const TIMEOUT_MS: i32 = 300_000;
/// Кнопки включаются не сразу: нажатие, начатое до появления окна, не
/// должно стать согласием.
const ARM_DELAY_MS: i32 = 800;

struct Pending {
    text: String,
    resolve: Function,
    window: Option<f64>,
    port: Option<Port>,
}

thread_local! {
    static PENDING: RefCell<HashMap<u64, Pending>> = RefCell::new(HashMap::new());
}

/// Вопрос пользователю; `true` — только явное «Разрешить».
pub(crate) async fn ask(text: String) -> bool {
    let id = background::next_id();
    let promise = Promise::new(&mut |resolve, _| {
        if let Some(w) = web_sys::window() {
            let _ = w.set_timeout_with_callback_and_timeout_and_arguments_1(
                &resolve,
                TIMEOUT_MS,
                &JsValue::FALSE,
            );
        }
        PENDING.with_borrow_mut(|p| {
            p.insert(
                id,
                Pending {
                    text: text.clone(),
                    resolve,
                    window: None,
                    port: None,
                },
            )
        });
    });
    let props = Object::new();
    let url = format!("{}#{id}", ext::runtime_get_url("confirm/confirm.html"));
    ext::set(&props, "url", &JsValue::from_str(&url));
    ext::set(&props, "type", &JsValue::from_str("popup"));
    ext::set(&props, "width", &JsValue::from_f64(480.0));
    ext::set(&props, "height", &JsValue::from_f64(400.0));
    let window = match ext::windows_create(&props) {
        Ok(p) => JsFuture::from(p).await.ok(),
        Err(_) => None,
    };
    match window
        .and_then(|w| ext::get(&w, "id"))
        .and_then(|v| v.as_f64())
    {
        Some(w) => PENDING.with_borrow_mut(|p| {
            if let Some(entry) = p.get_mut(&id) {
                entry.window = Some(w);
            }
        }),
        None => answer(id, false),
    }
    background::broadcast(&Event::Step("ждёт подтверждения в окне Leash".into()));
    let allow = JsFuture::from(promise).await.ok().and_then(|v| v.as_bool()) == Some(true);
    // По таймауту запись ещё на месте: окно закрывается здесь.
    finish(id);
    background::broadcast(&Event::Step(
        if allow {
            "разрешено"
        } else {
            "отклонено"
        }
        .into(),
    ));
    allow && !background::paused()
}

/// Ответ на вопрос `id`; повторный ответ ничего не меняет.
fn answer(id: u64, allow: bool) {
    let entry = PENDING.with_borrow_mut(|p| p.remove(&id));
    if let Some(e) = entry {
        let _ = e.resolve.call1(&JsValue::NULL, &JsValue::from_bool(allow));
        close(e);
    }
}

fn finish(id: u64) {
    if let Some(e) = PENDING.with_borrow_mut(|p| p.remove(&id)) {
        close(e);
    }
}

fn close(e: Pending) {
    if let Some(port) = e.port {
        port.disconnect();
    }
    if let Some(w) = e.window
        && let Ok(p) = ext::windows_remove(w)
    {
        // Окно уже могло быть закрыто пользователем: ошибку не ждём.
        let noop = Closure::<dyn FnMut(JsValue)>::new(|_| {});
        let _ = p.catch(&noop);
        noop.forget();
    }
}

/// «Стоп»: все открытые вопросы — «нет».
pub(crate) fn deny_all() {
    let ids: Vec<u64> = PENDING.with_borrow(|p| p.keys().copied().collect());
    for id in ids {
        answer(id, false);
    }
}

/// Порт окна подтверждения (отправитель уже проверен background).
pub(crate) fn on_connect(port: Port, id: u64) {
    let text = PENDING.with_borrow_mut(|p| match p.get_mut(&id) {
        Some(e) if e.port.is_none() => {
            e.port = Some(port.clone());
            Some(e.text.clone())
        }
        _ => None,
    });
    let Some(text) = text else {
        // Чужой или уже отвеченный вопрос.
        return port.disconnect();
    };
    let on_message: Function = Closure::<dyn FnMut(JsValue)>::new(move |msg: JsValue| {
        let allow = value::from_js(&msg).and_then(|v| protocol::parse_answer(&v));
        // Неверное сообщение от своего же окна — отказ.
        answer(id, allow == Some(true));
    })
    .into_js_value()
    .unchecked_into();
    let on_disconnect: Function =
        Closure::<dyn FnMut(JsValue)>::new(move |_: JsValue| answer(id, false))
            .into_js_value()
            .unchecked_into();
    port.on_message().add_listener(&on_message);
    port.on_disconnect().add_listener(&on_disconnect);
    port.post(&protocol::to_js(&protocol::show_value(&text)));
}

// --- Страница окна ---

#[wasm_bindgen]
pub fn start_confirm() -> Result<(), JsValue> {
    let doc = dom::document()?;
    let text: Element = dom::by_id(&doc, "text")?;
    let allow: Element = dom::by_id(&doc, "allow")?;
    let deny: Element = dom::by_id(&doc, "deny")?;
    dom::set_disabled(&allow, true);
    dom::set_disabled(&deny, true);

    let info = Object::new();
    ext::set(&info, "name", &JsValue::from_str(protocol::CONFIRM_PORT));
    let port = ext::runtime_connect(&info);

    let (t, a, d) = (text.clone(), allow.clone(), deny.clone());
    let on_message: Function = Closure::<dyn FnMut(JsValue)>::new(move |msg: JsValue| {
        let Some(q) = value::from_js(&msg).and_then(|v| protocol::parse_show(&v)) else {
            return;
        };
        t.set_text_content(Some(&protocol::display_text(&q)));
        let (a, d) = (a.clone(), d.clone());
        let arm: Function = Closure::once_into_js(move || {
            dom::set_disabled(&a, false);
            dom::set_disabled(&d, false);
        })
        .unchecked_into();
        if let Some(w) = web_sys::window() {
            let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(&arm, ARM_DELAY_MS);
        }
    })
    .into_js_value()
    .unchecked_into();
    let t = text.clone();
    let on_disconnect: Function = Closure::<dyn FnMut(JsValue)>::new(move |_: JsValue| {
        t.set_text_content(Some("Вопрос закрыт."));
        if let Some(w) = web_sys::window() {
            let _ = w.close();
        }
    })
    .into_js_value()
    .unchecked_into();
    port.on_message().add_listener(&on_message);
    port.on_disconnect().add_listener(&on_disconnect);

    for (button, choice) in [(allow.clone(), true), (deny.clone(), false)] {
        let (p, a, d) = (port.clone(), allow.clone(), deny.clone());
        dom::on(&button, "click", move |_| {
            dom::set_disabled(&a, true);
            dom::set_disabled(&d, true);
            p.post(&protocol::to_js(&protocol::answer_value(choice)));
        })?;
    }
    Ok(())
}
