//! Регистрация моста в Firefox (манифест native messaging) и подсказка,
//! как подключить его к Claude.
//!
//! macOS, Linux: Firefox ищет манифест в известном каталоге. Windows: путь к
//! манифесту лежит в реестре, `HKCU\Software\Mozilla\NativeMessagingHosts\leash`.

use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use leash_core::json::Value;

use crate::paths;

#[cfg(windows)]
const REG_KEY: &str = r"HKCU\Software\Mozilla\NativeMessagingHosts\leash";

/// Манифест: Firefox запустит `exe` только для нашего расширения.
pub fn manifest(exe: &Path) -> Value {
    Value::obj(vec![
        ("name", Value::str(leash_core::NATIVE_APP)),
        (
            "description",
            Value::str("Leash: мост между Claude и Firefox"),
        ),
        ("path", Value::str(exe.to_string_lossy())),
        ("type", Value::str("stdio")),
        (
            "allowed_extensions",
            Value::Arr(vec![Value::str(leash_core::EXTENSION_ID)]),
        ),
    ])
}

/// Путь к себе без префикса `\\?\`, который на Windows добавляет
/// `canonicalize`: Firefox и Claude ждут обычный путь.
fn own_path() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let plain = exe
        .to_string_lossy()
        .strip_prefix(r"\\?\")
        .map(PathBuf::from);
    Ok(plain.unwrap_or(exe))
}

pub fn install(home: &Path) -> io::Result<()> {
    let exe = own_path()?;
    let dir = paths::manifest_dir(home);
    fs::create_dir_all(&dir)?;
    let path = paths::manifest_path(home);
    fs::write(&path, manifest(&exe).to_json() + "\n")?;
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    #[cfg(windows)]
    reg(&[
        "add",
        REG_KEY,
        "/ve",
        "/t",
        "REG_SZ",
        "/d",
        &path.to_string_lossy(),
        "/f",
    ])?;
    println!("Мост зарегистрирован в Firefox: {}", path.display());
    println!("Перезапустите Firefox, чтобы расширение Leash подключилось к мосту.");
    println!();
    println!("Claude Code:");
    println!(
        "  claude mcp add --scope user leash -- {} mcp",
        exe.display()
    );
    println!("Claude Desktop (claude_desktop_config.json, раздел mcpServers):");
    println!(
        "  \"leash\": {{ \"command\": {}, \"args\": [\"mcp\"] }}",
        Value::str(exe.to_string_lossy()).to_json()
    );
    Ok(())
}

pub fn uninstall(home: &Path) -> io::Result<()> {
    // Ключа может не быть: тогда reg.exe вернёт ошибку, это не страшно.
    #[cfg(windows)]
    let _ = reg(&["delete", REG_KEY, "/f"]);
    let path = paths::manifest_path(home);
    match fs::remove_file(&path) {
        Ok(()) => println!("Удалено: {}", path.display()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => println!("Мост не был зарегистрирован."),
        Err(e) => return Err(e),
    }
    Ok(())
}

/// Системный reg.exe по полному пути: не тот, что первым найдётся в PATH.
#[cfg(windows)]
fn reg(args: &[&str]) -> io::Result<()> {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or_else(|| io::Error::other("SystemRoot не задан"))?;
    let out = std::process::Command::new(root.join(r"System32\reg.exe"))
        .args(args)
        .output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "reg.exe {}: {}",
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_names_only_our_extension() {
        let m = manifest(Path::new("/opt/leash/leash-host"));
        assert_eq!(
            m.to_json(),
            r#"{"name":"leash","description":"Leash: мост между Claude и Firefox","path":"/opt/leash/leash-host","type":"stdio","allowed_extensions":["leash@kirusshenkin.github.io"]}"#
        );
    }
}
