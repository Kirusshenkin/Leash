//! Leash: ядро расширения. Одна сборка WASM, три точки входа:
//! background (агент, политика, API), sidebar и options (интерфейс).
//!
//! Чистая логика (протокол, настройки, разбор ответа API) не зависит от
//! браузера и тестируется нативно через `cargo test`.

#![forbid(unsafe_code)]

mod agent;
mod api;
mod background;
mod dom;
mod ext;
mod guard;
mod options;
mod page;
mod policy;
mod probe;
mod protocol;
mod settings;
mod sidebar;
mod stream;
mod text;
mod tools;
mod value;

#[cfg(test)]
mod manifest_tests;
