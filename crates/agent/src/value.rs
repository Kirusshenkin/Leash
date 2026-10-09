//! Перевод значений из JS в дерево `Value` с бюджетом на глубину и размер.
//! Само дерево, строгий разбор и печать JSON — в `leash_core::json`.

use js_sys::{Array, Object, Reflect};
use leash_core::json::{MAX_DEPTH, MAX_NODES, MAX_STRING_BYTES};
use wasm_bindgen::JsValue;

pub(crate) use leash_core::json::{Value, parse_json};

struct Budget {
    nodes: usize,
    string_bytes: usize,
}

/// Перевод из JS. `None`, если значение не данные (функция, символ, BigInt)
/// или превышен бюджет.
pub(crate) fn from_js(value: &JsValue) -> Option<Value> {
    let mut budget = Budget {
        nodes: 0,
        string_bytes: 0,
    };
    convert(value, 0, &mut budget)
}

fn convert(value: &JsValue, depth: usize, budget: &mut Budget) -> Option<Value> {
    budget.nodes += 1;
    if depth > MAX_DEPTH || budget.nodes > MAX_NODES {
        return None;
    }
    if value.is_null() || value.is_undefined() {
        return Some(Value::Null);
    }
    if let Some(b) = value.as_bool() {
        return Some(Value::Bool(b));
    }
    if let Some(n) = value.as_f64() {
        return Some(Value::Num(n));
    }
    if let Some(s) = value.as_string() {
        budget.string_bytes += s.len();
        return (budget.string_bytes <= MAX_STRING_BYTES).then_some(Value::Str(s));
    }
    if Array::is_array(value) {
        let arr = Array::from(value);
        let mut items = Vec::new();
        for item in arr.iter() {
            items.push(convert(&item, depth + 1, budget)?);
        }
        return Some(Value::Arr(items));
    }
    if value.is_object() && !value.is_function() {
        let obj = Object::from(value.clone());
        let mut fields = Vec::new();
        for key in Object::keys(&obj).iter() {
            let name = key.as_string()?;
            budget.string_bytes += name.len();
            let field = Reflect::get(value, &key).ok()?;
            fields.push((name, convert(&field, depth + 1, budget)?));
        }
        return Some(Value::Obj(fields));
    }
    None
}
