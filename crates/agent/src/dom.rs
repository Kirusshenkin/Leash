//! Помощники для DOM. Текст выводится только через `textContent`;
//! HTML-строки в DOM не попадают нигде (проверяется scripts/check-static.sh).

use wasm_bindgen::prelude::*;
use web_sys::{Document, Element, EventTarget};

pub(crate) fn document() -> Result<Document, JsValue> {
    web_sys::window()
        .and_then(|w| w.document())
        .ok_or_else(|| JsValue::from_str("нет document"))
}

pub(crate) fn by_id<T: JsCast>(doc: &Document, id: &str) -> Result<T, JsValue> {
    doc.get_element_by_id(id)
        .ok_or_else(|| JsValue::from_str(&format!("нет элемента #{id}")))?
        .dyn_into::<T>()
        .map_err(|_| JsValue::from_str(&format!("#{id}: неожиданный тип элемента")))
}

/// Добавляет `<div class=…>` с текстом в конец `parent`.
pub(crate) fn append_text(parent: &Element, class: &str, text: &str) -> Result<(), JsValue> {
    let doc = document()?;
    let el = doc.create_element("div")?;
    el.set_class_name(class);
    el.set_text_content(Some(text));
    parent.append_child(&el)?;
    Ok(())
}

pub(crate) fn set_disabled(el: &Element, disabled: bool) {
    // set/removeAttribute("disabled") на своём элементе не бросает.
    let _ = if disabled {
        el.set_attribute("disabled", "")
    } else {
        el.remove_attribute("disabled")
    };
}

/// Обработчик на всё время жизни страницы.
pub(crate) fn on(
    target: &EventTarget,
    event: &str,
    handler: impl FnMut(web_sys::Event) + 'static,
) -> Result<(), JsValue> {
    let cb = Closure::<dyn FnMut(web_sys::Event)>::new(handler);
    target.add_event_listener_with_callback(event, cb.as_ref().unchecked_ref())?;
    // Страница расширения живёт, пока открыта; обработчик нужен до конца.
    cb.forget();
    Ok(())
}
