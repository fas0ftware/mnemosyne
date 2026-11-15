//! Desktop integration: `sphinx app` opens the vault in its own window, and
//! `sphinx install-app` puts Sphinx in the application menu (Linux), so it starts
//! with a click and no terminal.
//!
//! The window is a Chromium-based browser in app mode (Brave, Chromium, Chrome,
//! Edge) with a **separate profile** for Sphinx: extensions and history of your
//! everyday browser profile never see the vault page.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

type AppResult<T> = Result<T, String>;

use crate::app::ICON_SVG;

const BROWSERS: &[&str] = &[
    "brave",
    "brave-browser",
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "microsoft-edge",
];

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

fn home() -> AppResult<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("HOME").ok_or("HOME is not set")?,
    ))
}

/// Profile folder for the Sphinx window. Snap browsers may only write inside
/// their own ~/snap/<name>/ area, so they get a folder there.
fn profile_dir(browser: &Path) -> AppResult<PathBuf> {
    let home = home()?;
    let resolved = fs::canonicalize(browser).unwrap_or_else(|_| browser.to_path_buf());
    let is_snap = browser.starts_with("/snap/") || resolved.starts_with("/snap/");
    let dir = if is_snap {
        let name = browser
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("browser");
        home.join("snap")
            .join(name)
            .join("common")
            .join("mnemosyne-app-profile")
    } else {
        home.join(".local/share/mnemosyne/app-profile")
    };
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    Ok(dir)
}

/// The command line that opens `url` as an app window (pure, for tests).
pub fn app_window_args(url: &str, profile: &Path) -> Vec<String> {
    vec![
        format!("--app={url}"),
        format!("--user-data-dir={}", profile.display()),
        "--class=Mnemosyne".into(),
        "--window-size=1360,900".into(),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        "--disable-extensions".into(),
    ]
}

pub fn open_app_window(url: &str) -> AppResult<()> {
    let chosen = std::env::var_os("MNEMOSYNE_BROWSER")
        .map(PathBuf::from)
        .or_else(|| BROWSERS.iter().find_map(|name| find_in_path(name)));
    if let Some(browser) = chosen {
        let profile = profile_dir(&browser)?;
        Command::new(&browser)
            .args(app_window_args(url, &profile))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("could not start {}: {error}", browser.display()))?;
        return Ok(());
    }
    // No Chromium-based browser: a normal browser tab still works.
    Command::new("xdg-open")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "no browser found (set MNEMOSYNE_BROWSER to one)".to_string())?;
    Ok(())
}

/// The .desktop launcher text (pure, for tests).
pub fn desktop_entry(exe: &Path) -> String {
    let exe = exe.display().to_string().replace('"', "\\\"");
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=Mnemosyne\n\
         GenericName=Backups\n\
         Comment=Browse, compare and verify your encrypted backups\n\
         Exec=\"{exe}\" app\n\
         Icon=mnemosyne\n\
         Terminal=false\n\
         Categories=Utility;Archiving;\n\
         Keywords=backup;restore;yedek;\n\
         StartupWMClass=Mnemosyne\n"
    )
}

pub fn install_app() -> AppResult<()> {
    let home = home()?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let icon_dir = home.join(".local/share/icons/hicolor/scalable/apps");
    let apps_dir = home.join(".local/share/applications");
    fs::create_dir_all(&icon_dir).map_err(|e| e.to_string())?;
    fs::create_dir_all(&apps_dir).map_err(|e| e.to_string())?;
    fs::write(icon_dir.join("mnemosyne.svg"), ICON_SVG).map_err(|e| e.to_string())?;
    let launcher = apps_dir.join("mnemosyne.desktop");
    fs::write(&launcher, desktop_entry(&exe)).map_err(|e| e.to_string())?;
    let _ = Command::new("update-desktop-database")
        .arg(&apps_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    eprintln!(
        "Mnemosyne is now in your application menu ({}). It runs {} app.",
        launcher.display(),
        exe.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_window_uses_its_own_profile_and_no_extensions() {
        let args = app_window_args("http://127.0.0.1:1/#t=abc", Path::new("/p"));
        assert_eq!(args[0], "--app=http://127.0.0.1:1/#t=abc");
        assert!(args.contains(&"--user-data-dir=/p".to_string()));
        assert!(args.contains(&"--disable-extensions".to_string()));
    }

    #[test]
    fn desktop_entry_starts_the_app_without_a_terminal() {
        let entry = desktop_entry(Path::new("/home/u/.local/bin/mnemosyne"));
        assert!(entry.contains("Exec=\"/home/u/.local/bin/mnemosyne\" app\n"));
        assert!(entry.contains("Terminal=false\n"));
        assert!(entry.starts_with("[Desktop Entry]\n"));
    }
}
