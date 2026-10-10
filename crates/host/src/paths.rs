//! Где лежат сокет/канал моста и манифест native messaging.
//!
//! Unix (macOS, Linux): сокет в `~/.leash/host.sock` с правами 0700.
//! Каталог проверяется при каждом запуске: чужой владелец, лишние права
//! или симлинк — отказ.
//!
//! Windows: именованный канал `\\.\pipe\Leash-<UID>`, безопасность
//! настраивается через дескриптор при создании.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub fn home() -> io::Result<PathBuf> {
    #[cfg(unix)]
    {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|h| h.is_absolute())
            .ok_or_else(|| io::Error::other("HOME не задан или не абсолютный"))?;
        Ok(home)
    }
    #[cfg(windows)]
    {
        let home = std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .filter(|h| h.is_absolute())
            .ok_or_else(|| io::Error::other("USERPROFILE не задан или не абсолютный"))?;
        Ok(home)
    }
}

pub fn state_dir(home: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        home.join(".leash")
    }
    #[cfg(windows)]
    {
        home.join("AppData/Local/Leash")
    }
}

pub fn socket_path(home: &Path) -> io::Result<PathBuf> {
    #[cfg(unix)]
    {
        /// Предел пути unix-сокета (`sun_path`) на macOS; на Linux он больше.
        const MAX_SOCKET_PATH: usize = 103;
        let path = state_dir(home).join("host.sock");
        if path.as_os_str().len() > MAX_SOCKET_PATH {
            return Err(io::Error::other(format!(
                "путь сокета длиннее {MAX_SOCKET_PATH} байт: {}",
                path.display()
            )));
        }
        Ok(path)
    }
    #[cfg(windows)]
    {
        // На Windows вычисляемый путь не используется (используется имя канала).
        // Возвращаем пустой путь как плейсхолдер.
        Ok(PathBuf::new())
    }
}

/// Каталог манифестов native messaging Firefox для этого пользователя.
pub fn manifest_dir(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Mozilla/NativeMessagingHosts")
    } else if cfg!(target_os = "windows") {
        home.join("AppData/Roaming/Mozilla/NativeMessagingHosts")
    } else {
        home.join(".mozilla/native-messaging-hosts")
    }
}

pub fn manifest_path(home: &Path) -> PathBuf {
    manifest_dir(home).join(format!("{}.json", leash_core::NATIVE_APP))
}

#[cfg(unix)]
/// Создаёт каталог 0700 и проверяет, что он наш и закрыт для других.
pub fn ensure_private_dir(dir: &Path, home: &Path) -> io::Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let meta = fs::symlink_metadata(dir)?;
    let owner = fs::metadata(home)?.uid();
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(io::Error::other(format!(
            "{} не каталог или симлинк",
            dir.display()
        )));
    }
    if meta.uid() != owner {
        return Err(io::Error::other(format!(
            "{}: владелец не тот, что у домашнего каталога",
            dir.display()
        )));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(io::Error::other(format!(
            "{}: доступен другим пользователям (нужно 0700)",
            dir.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
/// На Windows проверяет существование и создание каталога.
pub fn ensure_private_dir(dir: &Path, _home: &Path) -> io::Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(io::Error::other(format!(
            "{} не каталог или симлинк",
            dir.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Временный домашний каталог теста; удаляется при выходе из области.
    pub struct TempHome(pub PathBuf);

    impl TempHome {
        pub fn new(tag: &str) -> Self {
            let n = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or_default();
            // Короткий путь: у сокета предел длины.
            let dir = PathBuf::from(format!("/tmp/lh-{tag}-{}-{n}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn private_dir_is_created_closed() {
        let home = TempHome::new("pd");
        let dir = state_dir(&home.0);
        ensure_private_dir(&dir, &home.0).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        // Повторный вызов на готовом каталоге проходит.
        ensure_private_dir(&dir, &home.0).unwrap();
    }

    #[test]
    fn open_or_linked_dir_is_refused() {
        let home = TempHome::new("od");
        let dir = state_dir(&home.0);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ensure_private_dir(&dir, &home.0).is_err());

        let real = home.0.join("real");
        fs::create_dir_all(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let link = home.0.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(ensure_private_dir(&link, &home.0).is_err());
    }

    #[test]
    fn layout() {
        let home = Path::new("/home/u");
        assert_eq!(
            socket_path(home).unwrap(),
            PathBuf::from("/home/u/.leash/host.sock")
        );
        assert!(manifest_path(home).ends_with("leash.json"));
        let long = PathBuf::from(format!("/{}", "x".repeat(120)));
        assert!(socket_path(&long).is_err());
    }
}
