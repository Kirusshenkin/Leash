//! Страница настроек. Ключ только записывается: страница его не читает,
//! а показывает подсказку из последних 4 символов.

use std::cell::RefCell;
use std::rc::Rc;

use js_sys::futures::{JsFuture, spawn_local};
use js_sys::{Object, Promise};
use wasm_bindgen::prelude::*;
use web_sys::{Element, HtmlElement, HtmlInputElement, HtmlSelectElement, HtmlTextAreaElement};

use crate::dom;
use crate::ext;
use crate::policy::{self, Access, Policy};
use crate::settings::{self, ApiKey, MaxTokensError};

/// Обязательное разрешение из манифеста; его не убираем.
const API_PATTERN: &str = "https://api.anthropic.com/*";

#[derive(Clone)]
struct Page {
    key: HtmlInputElement,
    key_status: Element,
    model: HtmlSelectElement,
    max_tokens: HtmlInputElement,
    allow: HtmlTextAreaElement,
    deny: HtmlTextAreaElement,
    probe: HtmlInputElement,
    probe_result: Element,
    /// Сохранённые списки и выданные разрешения; по ним проверяется адрес.
    saved: Rc<RefCell<Access>>,
    message: Element,
}

#[wasm_bindgen]
pub fn start_options() -> Result<(), JsValue> {
    let doc = dom::document()?;
    let page = Page {
        key: dom::by_id(&doc, "key")?,
        key_status: dom::by_id(&doc, "key-status")?,
        model: dom::by_id(&doc, "model")?,
        max_tokens: dom::by_id(&doc, "max-tokens")?,
        allow: dom::by_id(&doc, "allow")?,
        deny: dom::by_id(&doc, "deny")?,
        probe: dom::by_id(&doc, "probe")?,
        probe_result: dom::by_id(&doc, "probe-result")?,
        saved: Rc::new(RefCell::new(Access::default())),
        message: dom::by_id(&doc, "message")?,
    };
    let builtin: Element = dom::by_id(&doc, "builtin")?;
    for (domain, category) in policy::BUILTIN_DENY {
        let li = doc.create_element("li")?;
        li.set_text_content(Some(&format!("{domain} — {}", category.describe())));
        builtin.append_child(&li)?;
    }
    for m in settings::MODELS {
        let opt = doc.create_element("option")?;
        opt.set_attribute("value", m)?;
        opt.set_text_content(Some(m));
        page.model.append_child(&opt)?;
    }
    page.model.set_value(settings::MODELS[0]);
    page.max_tokens
        .set_value(&settings::MAX_TOKENS_DEFAULT.to_string());

    let save_key: HtmlElement = dom::by_id(&doc, "save-key")?;
    let clear_key: HtmlElement = dom::by_id(&doc, "clear-key")?;
    let save: HtmlElement = dom::by_id(&doc, "save")?;
    let save_sites: HtmlElement = dom::by_id(&doc, "save-sites")?;

    let p = page.clone();
    dom::on(&save_key, "click", move |_| {
        spawn_local(store_key(p.clone()))
    })?;
    let p = page.clone();
    dom::on(&clear_key, "click", move |_| {
        spawn_local(remove_key(p.clone()))
    })?;
    let p = page.clone();
    dom::on(&save, "click", move |_| {
        spawn_local(store_settings(p.clone()))
    })?;
    let p = page.clone();
    dom::on(&save_sites, "click", move |_| save_sites_clicked(&p))?;
    let p = page.clone();
    dom::on(&page.probe, "input", move |_| show_probe(&p))?;

    spawn_local(load(page));
    Ok(())
}

fn say(page: &Page, text: &str) {
    page.message.set_text_content(Some(text));
}

fn show_hint(page: &Page, hint: Option<&str>) {
    let text = match hint {
        Some(h) => format!("Ключ задан: …{h}"),
        None => "Ключ не задан.".to_owned(),
    };
    page.key_status.set_text_content(Some(&text));
}

async fn granted_origins() -> Vec<String> {
    let Ok(promise) = ext::permissions_get_all() else {
        return Vec::new();
    };
    JsFuture::from(promise)
        .await
        .ok()
        .and_then(|all| ext::get(&all, "origins"))
        .map(|o| {
            js_sys::Array::from(&o)
                .iter()
                .filter_map(|v| v.as_string())
                .collect()
        })
        .unwrap_or_default()
}

async fn load(page: Page) {
    // Этап 1 хранил ключ в storage.local, доступной content-скриптам.
    let legacy = ext::strings(&[settings::KEY_API_KEY, settings::KEY_API_KEY_HINT]);
    let _ = JsFuture::from(ext::storage_local_remove(&legacy)).await;

    // Сам ключ сюда не читается.
    let hint = match ext::storage_session_get(&ext::strings(&[settings::KEY_API_KEY_HINT])) {
        Ok(p) => JsFuture::from(p)
            .await
            .ok()
            .and_then(|s| ext::get(&s, settings::KEY_API_KEY_HINT))
            .and_then(|v| v.as_string()),
        Err(_) => None,
    };
    // Подсказку тоже проверяем: только 4 безопасных символа.
    let hint = hint.filter(|h| {
        h.len() == 4
            && h.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    show_hint(&page, hint.as_deref());

    let names = ext::strings(&[
        settings::KEY_MODEL,
        settings::KEY_MAX_TOKENS,
        settings::KEY_ALLOW_ORIGINS,
        settings::KEY_DENY_HOSTS,
    ]);
    let Ok(stored) = JsFuture::from(ext::storage_local_get(&names)).await else {
        return say(&page, "Не удалось прочитать настройки.");
    };
    let model = ext::get(&stored, settings::KEY_MODEL).and_then(|v| v.as_string());
    page.model
        .set_value(settings::model_from_storage(model.as_deref()));
    let max_tokens = ext::get(&stored, settings::KEY_MAX_TOKENS).and_then(|v| v.as_f64());
    page.max_tokens
        .set_value(&settings::max_tokens_from_storage(max_tokens).to_string());

    let text = |key| {
        ext::get(&stored, key)
            .and_then(|v| v.as_string())
            .unwrap_or_default()
    };
    let (allow, deny) = (
        text(settings::KEY_ALLOW_ORIGINS),
        text(settings::KEY_DENY_HOSTS),
    );
    page.allow.set_value(&allow);
    page.deny.set_value(&deny);
    // Неразборчивые списки не принимаются частично: проверка идёт по пустой
    // политике, то есть всё закрыто, пока списки не исправят и не сохранят.
    let policy = match Policy::parse(&allow, &deny) {
        Ok(p) => p,
        Err(e) => {
            say(
                &page,
                &format!(
                    "Сохранённые списки не разобраны, все сайты закрыты. {}",
                    e.describe()
                ),
            );
            Policy::default()
        }
    };
    *page.saved.borrow_mut() = Access::new(policy, &granted_origins().await);
}

/// `permissions.request` Firefox принимает только синхронно из обработчика
/// клика, поэтому разбор и запрос — здесь, а запись — уже асинхронно.
fn save_sites_clicked(page: &Page) {
    let parsed = match Policy::parse(&page.allow.value(), &page.deny.value()) {
        Ok(p) => p,
        Err(e) => return say(page, &e.describe()),
    };
    let wanted: Vec<String> = parsed
        .allowed()
        .iter()
        .map(policy::permission_pattern)
        .collect();
    let request = if wanted.is_empty() {
        None
    } else {
        ext::permissions_request(&ext::origins(&wanted)).ok()
    };
    spawn_local(store_sites(page.clone(), parsed, wanted, request));
}

async fn store_sites(page: Page, parsed: Policy, wanted: Vec<String>, request: Option<Promise>) {
    let granted = match request {
        Some(p) => JsFuture::from(p).await.ok().and_then(|v| v.as_bool()),
        None => Some(true),
    };
    let (allow, deny) = (parsed.allow_text(), parsed.deny_text());
    let items = Object::new();
    ext::set(
        &items,
        settings::KEY_ALLOW_ORIGINS,
        &JsValue::from_str(&allow),
    );
    ext::set(&items, settings::KEY_DENY_HOSTS, &JsValue::from_str(&deny));
    if JsFuture::from(ext::storage_local_set(&items))
        .await
        .is_err()
    {
        return say(&page, "Не удалось сохранить списки.");
    }
    page.allow.set_value(&allow);
    page.deny.set_value(&deny);

    // Разрешения на сайты, которых больше нет в списке, возвращаются браузеру.
    let extra: Vec<String> = granted_origins()
        .await
        .into_iter()
        .filter(|o| o != API_PATTERN && !wanted.contains(o))
        .collect();
    if !extra.is_empty()
        && let Ok(p) = ext::permissions_remove(&ext::origins(&extra))
    {
        let _ = JsFuture::from(p).await;
    }
    *page.saved.borrow_mut() = Access::new(parsed, &granted_origins().await);
    show_probe(&page);
    say(
        &page,
        if granted == Some(true) {
            "Списки сохранены."
        } else {
            "Списки сохранены, но Firefox не выдал доступ: эти сайты останутся закрыты."
        },
    );
}

fn show_probe(page: &Page) {
    let url = page.probe.value();
    let url = url.trim();
    let text = if url.is_empty() {
        String::new()
    } else {
        match page.saved.borrow().check(url) {
            Ok(origin) => format!("Разрешено: {origin}"),
            Err(denied) => denied.describe(),
        }
    };
    page.probe_result.set_text_content(Some(&text));
}

async fn store_key(page: Page) {
    let key = match ApiKey::parse(&page.key.value()) {
        Ok(k) => k,
        Err(e) => return say(&page, e.describe()),
    };
    let items = Object::new();
    ext::set(
        &items,
        settings::KEY_API_KEY,
        &JsValue::from_str(key.expose()),
    );
    ext::set(
        &items,
        settings::KEY_API_KEY_HINT,
        &JsValue::from_str(&key.hint()),
    );
    page.key.set_value("");
    let saved = match ext::storage_session_set(&items) {
        Ok(p) => JsFuture::from(p).await.is_ok(),
        Err(_) => false,
    };
    if saved {
        show_hint(&page, Some(&key.hint()));
        say(&page, "Ключ сохранён до закрытия Firefox.");
    } else {
        say(&page, "Не удалось сохранить ключ.");
    }
}

async fn remove_key(page: Page) {
    let names = ext::strings(&[settings::KEY_API_KEY, settings::KEY_API_KEY_HINT]);
    let removed = match ext::storage_session_remove(&names) {
        Ok(p) => JsFuture::from(p).await.is_ok(),
        Err(_) => false,
    };
    if removed {
        show_hint(&page, None);
        say(&page, "Ключ удалён.");
    } else {
        say(&page, "Не удалось удалить ключ.");
    }
}

async fn store_settings(page: Page) {
    let Some(model) = settings::parse_model(&page.model.value()) else {
        return say(&page, "Неизвестная модель.");
    };
    let max_tokens = match settings::parse_max_tokens(&page.max_tokens.value()) {
        Ok(n) => n,
        Err(MaxTokensError::NotANumber) => {
            return say(&page, "Лимит токенов должен быть целым числом.");
        }
        Err(MaxTokensError::OutOfRange) => {
            return say(
                &page,
                &format!(
                    "Лимит токенов: от {} до {}.",
                    settings::MAX_TOKENS_MIN,
                    settings::MAX_TOKENS_MAX
                ),
            );
        }
    };
    let items = Object::new();
    ext::set(&items, settings::KEY_MODEL, &JsValue::from_str(model));
    ext::set(&items, settings::KEY_MAX_TOKENS, &JsValue::from(max_tokens));
    match JsFuture::from(ext::storage_local_set(&items)).await {
        Ok(_) => say(&page, "Настройки сохранены."),
        Err(_) => say(&page, "Не удалось сохранить настройки."),
    }
}
