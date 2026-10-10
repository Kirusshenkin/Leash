//! leash-host — мост между Claude (MCP) и расширением Leash в Firefox.
//!
//! `leash-host install`   — зарегистрировать мост в Firefox;
//! `leash-host uninstall` — убрать регистрацию;
//! `leash-host mcp`       — MCP-сервер по stdio (его запускает Claude);
//! `leash-host <манифест> <ID расширения>` — так мост запускает Firefox.
//!
//! В stdout пишутся только сообщения протоколов; диагностика — в stderr
//! (Firefox показывает её в консоли браузера, Claude — в своих логах).
//!
//! На Windows используется unsafe FFI для работы с именованными каналами,
//! изолировано в модуле windows_ipc внутри native.rs.

mod client;
mod frame;
mod install;
mod mcp;
mod native;
mod paths;

use std::process::ExitCode;

const USAGE: &str = "leash-host install | uninstall | mcp | --version";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let home = match paths::home() {
        Ok(h) => h,
        Err(e) => return fail(&e.to_string()),
    };
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["install"] => install::install(&home),
        ["uninstall"] => install::uninstall(&home),
        ["mcp"] => paths::socket_path(&home).and_then(client::run),
        ["--version"] => {
            println!("leash-host {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        // Firefox: путь к манифесту и ID расширения, которому разрешён запуск.
        [_, ext] if ext == leash_core::EXTENSION_ID => native::run(&home),
        [_, _] => return fail("запуск разрешён только расширению Leash"),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&e.to_string()),
    }
}

fn fail(why: &str) -> ExitCode {
    eprintln!("leash-host: {why}");
    ExitCode::FAILURE
}
