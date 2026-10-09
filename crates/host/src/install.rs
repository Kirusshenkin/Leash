//! Регистрация моста в Firefox (манифест native messaging) и подсказка,
//! как подключить его к Claude.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

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
    let dir = paths::manifest_dir(home);
    fs::create_dir_all(&dir)?;
    let path = paths::manifest_path(home);
    fs::write(&path, manifest(&exe).to_json() + "\n")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
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
    let path = paths::manifest_path(home);
    match fs::remove_file(&path) {
        Ok(()) => println!("Удалено: {}", path.display()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => println!("Мост не был зарегистрирован."),
        Err(e) => return Err(e),
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
