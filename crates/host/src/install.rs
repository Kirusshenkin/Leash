//! Регистрация моста в Firefox (манифест native messaging) и подсказка,
//! как подключить его к Claude.

use std::fs;
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use leash_core::json::Value;

use crate::paths;

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

pub fn install(home: &Path) -> io::Result<()> {
    let exe = std::env::current_exe()?.canonicalize()?;

    #[cfg(unix)]
    {
        let dir = paths::manifest_dir(home);
        fs::create_dir_all(&dir)?;
        let path = paths::manifest_path(home);
        fs::write(&path, manifest(&exe).to_json() + "\n")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        println!("Мост зарегистрирован в Firefox: {}", path.display());
    }

    #[cfg(windows)]
    {
        let dir = paths::manifest_dir(home);
        fs::create_dir_all(&dir)?;
        let path = paths::manifest_path(home);
        fs::write(&path, manifest(&exe).to_json() + "\n")?;
        // На Windows дополнительно регистрируем в реестре
        register_in_registry(&exe)?;
        println!("Мост зарегистрирован в Firefox и системе Windows");
        println!("  Манифест: {}", path.display());
    }

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
    let path = paths::manifest_path(home);
    match fs::remove_file(&path) {
        Ok(()) => println!("Удалено: {}", path.display()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => println!("Мост не был зарегистрирован."),
        Err(e) => return Err(e),
    }

    #[cfg(windows)]
    {
        // Удаляем из реестра
        let _ = unregister_from_registry();
    }

    Ok(())
}

#[cfg(windows)]
fn register_in_registry(_exe: &Path) -> io::Result<()> {
    // Firefox ищет манифест native messaging в реестре:
    // HKCU\Software\Mozilla\NativeMessagingHosts\leash
    // Значение REG_SZ "Default" должно быть путём к манифесту.
    // Используем reg.exe, так как FFI для реестра требует много боilerplate.
    use std::process::Command;

    let home = std::env::var_os("USERPROFILE")
        .ok_or_else(|| io::Error::other("USERPROFILE не задан"))?;
    let home_path = Path::new(&home);
    let manifest = paths::manifest_path(home_path);

    // Проверяем что манифест существует
    if !manifest.exists() {
        return Err(io::Error::other(
            "Манифест не найден. Сначала запустите: leash-host install"
        ));
    }

    let manifest_str = manifest.to_string_lossy().to_string();
    let key = "HKEY_CURRENT_USER\\Software\\Mozilla\\NativeMessagingHosts\\leash";

    // Используем reg.exe (встроена в Windows)
    let output = Command::new("reg")
        .args(&["add", key, "/ve", "/d", &manifest_str, "/f"])
        .output()
        .map_err(|e| io::Error::other(format!("Не удалось запустить reg.exe: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("Ошибка реестра: {}", stderr);
        return Err(io::Error::other("Не удалось зарегистрировать в реестре"));
    }

    Ok(())
}

#[cfg(windows)]
fn unregister_from_registry() -> io::Result<()> {
    // Удаляем ключ реестра HKCU\Software\Mozilla\NativeMessagingHosts\leash
    use std::process::Command;

    let key = "HKEY_CURRENT_USER\\Software\\Mozilla\\NativeMessagingHosts\\leash";

    let output = Command::new("reg")
        .args(&["delete", key, "/f"])
        .output()
        .map_err(|e| io::Error::other(format!("Не удалось запустить reg.exe: {}", e)))?;

    if !output.status.success() {
        // Ошибка нормальна, если ключа не было
        return Ok(());
    }

    Ok(())
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
