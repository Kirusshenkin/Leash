//! Общее ядро Leash: JSON и инструменты. Без зависимостей и без `unsafe`,
//! собирается и в WASM расширения, и в нативный мост.

#![forbid(unsafe_code)]

pub mod json;
pub mod tools;

/// ID расширения: Firefox запускает мост только для него, мост сверяет его
/// при запуске.
pub const EXTENSION_ID: &str = "leash@kirusshenkin.github.io";

/// Имя native-приложения (`runtime.connectNative`) и файла его манифеста.
pub const NATIVE_APP: &str = "leash";
