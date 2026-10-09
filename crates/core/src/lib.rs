//! Общее ядро Leash: JSON и инструменты. Без зависимостей и без `unsafe`,
//! собирается и в WASM расширения, и в нативный мост.

#![forbid(unsafe_code)]

pub mod json;
pub mod tools;
