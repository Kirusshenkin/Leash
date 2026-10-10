//! Leash: ядро расширения. Одна сборка WASM, четыре точки входа:
//! background (мост к Claude, политика, действия), sidebar (журнал и
//! «Стоп»), окно подтверждения и options.
//!
//! Чистая логика (протокол, политика, снимок, guard, проба) не зависит от
//! браузера и тестируется нативно через `cargo test`.

#![forbid(unsafe_code)]

mod background;
mod bridge;
mod confirm;
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
mod text;
mod value;

use leash_core::tools;

#[cfg(test)]
mod manifest_tests;
