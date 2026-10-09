//! Страница настроек: списки разрешённых и запрещённых сайтов, проверка
//! адреса и подсказка, как подключить мост.

use std::cell::RefCell;
use std::rc::Rc;

use js_sys::futures::{JsFuture, spawn_local};
use js_sys::{Object, Promise};
use wasm_bindgen::prelude::*;
use web_sys::{Element, HtmlElement, HtmlInputElement, HtmlTextAreaElement};

use crate::dom;
use crate::ext;
use crate::policy::{self, Access, Policy};
use crate::settings;

#[derive(Clone)]
struct Page {
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
    let save_sites: HtmlElement = dom::by_id(&doc, "save-sites")?;
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
    let _ = JsFuture::from(ext::storage_local_remove(&ext::strings(
        settings::LEGACY_KEYS,
    )))
    .await;

    let names = ext::strings(&[settings::KEY_ALLOW_ORIGINS, settings::KEY_DENY_HOSTS]);
    let Ok(stored) = JsFuture::from(ext::storage_local_get(&names)).await else {
        return say(&page, "Не удалось прочитать настройки.");
    };
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
        .filter(|o| !wanted.contains(o))
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
