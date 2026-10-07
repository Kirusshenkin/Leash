//! Привязки к WebExtension API (`browser.*`), которых нет в web-sys.
//! Только то, что используется.

use js_sys::{Function, Object, Promise, Reflect};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["browser", "runtime"], js_name = getURL)]
    pub fn runtime_get_url(path: &str) -> String;

    #[wasm_bindgen(js_namespace = ["browser", "runtime"], js_name = connect)]
    pub fn runtime_connect(info: &Object) -> Port;

    #[wasm_bindgen(js_namespace = ["browser", "runtime"], js_name = openOptionsPage)]
    pub fn runtime_open_options_page() -> Promise;

    #[wasm_bindgen(js_namespace = ["browser", "storage", "local"], js_name = get)]
    pub fn storage_local_get(keys: &JsValue) -> Promise;

    #[wasm_bindgen(js_namespace = ["browser", "storage", "local"], js_name = set)]
    pub fn storage_local_set(items: &Object) -> Promise;

    #[wasm_bindgen(js_namespace = ["browser", "storage", "local"], js_name = remove)]
    pub fn storage_local_remove(keys: &JsValue) -> Promise;

    // storage.session по умолчанию недоступна content-скриптам: здесь ключ API.
    #[wasm_bindgen(catch, js_namespace = ["browser", "storage", "session"], js_name = get)]
    pub fn storage_session_get(keys: &JsValue) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_namespace = ["browser", "storage", "session"], js_name = set)]
    pub fn storage_session_set(items: &Object) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_namespace = ["browser", "storage", "session"], js_name = remove)]
    pub fn storage_session_remove(keys: &JsValue) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_namespace = ["browser", "tabs"], js_name = query)]
    pub fn tabs_query(info: &Object) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_namespace = ["browser", "tabs"], js_name = get)]
    pub fn tabs_get(tab: f64) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_namespace = ["browser", "tabs"], js_name = update)]
    pub fn tabs_update(tab: f64, props: &Object) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_namespace = ["browser", "tabs"], js_name = goBack)]
    pub fn tabs_go_back(tab: f64) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_namespace = ["browser", "windows"], js_name = getCurrent)]
    pub fn windows_get_current() -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_namespace = ["browser", "permissions"], js_name = getAll)]
    pub fn permissions_get_all() -> Result<Promise, JsValue>;

    /// Только синхронно из обработчика клика: иначе Firefox откажет.
    #[wasm_bindgen(catch, js_namespace = ["browser", "permissions"], js_name = request)]
    pub fn permissions_request(perms: &Object) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_namespace = ["browser", "permissions"], js_name = remove)]
    pub fn permissions_remove(perms: &Object) -> Result<Promise, JsValue>;

    /// Операция content-скрипта в главном фрейме вкладки
    /// (extension/background/background.js, docs/content-contract.md).
    #[wasm_bindgen(catch, js_name = leashInTab)]
    pub fn leash_in_tab(tab: f64, op: &JsValue) -> Result<Promise, JsValue>;

    /// `runtime.Port`.
    #[derive(Clone)]
    pub type Port;

    #[wasm_bindgen(method, getter)]
    pub fn name(this: &Port) -> String;

    #[wasm_bindgen(method, getter)]
    pub fn sender(this: &Port) -> JsValue;

    #[wasm_bindgen(method, catch, js_name = postMessage)]
    fn post_message_raw(this: &Port, msg: &JsValue) -> Result<(), JsValue>;

    #[wasm_bindgen(method)]
    pub fn disconnect(this: &Port);

    #[wasm_bindgen(method, getter, js_name = onMessage)]
    pub fn on_message(this: &Port) -> ExtEvent;

    #[wasm_bindgen(method, getter, js_name = onDisconnect)]
    pub fn on_disconnect(this: &Port) -> ExtEvent;

    /// `events.Event`.
    pub type ExtEvent;

    #[wasm_bindgen(method, js_name = addListener)]
    pub fn add_listener(this: &ExtEvent, cb: &Function);
}

impl Port {
    /// Отправка в порт. Ошибку (порт уже закрыт) сознательно игнорируем:
    /// получателя больше нет, сообщать некому.
    pub fn post(&self, msg: &JsValue) {
        let _ = self.post_message_raw(msg);
    }
}

/// `browser.runtime.id` нашего расширения.
pub fn runtime_id() -> Option<String> {
    let browser = get(&js_sys::global(), "browser")?;
    let runtime = get(&browser, "runtime")?;
    get(&runtime, "id")?.as_string()
}

/// Свойство объекта; `None`, если его нет или чтение бросило исключение.
pub fn get(obj: &JsValue, key: &str) -> Option<JsValue> {
    if !obj.is_object() {
        return None;
    }
    Reflect::get(obj, &JsValue::from_str(key))
        .ok()
        .filter(|v| !v.is_undefined() && !v.is_null())
}

/// Запись свойства в объект, который мы создали сами.
pub fn set(obj: &Object, key: &str, value: &JsValue) {
    // Reflect.set на обычном Object из Object::new() не бросает.
    let _ = Reflect::set(obj, &JsValue::from_str(key), value);
}

/// Массив строк для `keys`/`origins`.
pub fn strings<S: AsRef<str>>(items: &[S]) -> js_sys::Array {
    let arr = js_sys::Array::new();
    for s in items {
        arr.push(&JsValue::from_str(s.as_ref()));
    }
    arr
}

/// Объект `{ origins: [...] }` для permissions API.
pub fn origins(patterns: &[String]) -> Object {
    let obj = Object::new();
    set(&obj, "origins", &strings(patterns));
    obj
}
