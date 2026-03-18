use std::path::PathBuf;
use std::process::Command;

use clap::Args;
use secrecy::ExposeSecret;
use zeroize::Zeroize;

use revvault_core::Config;
use revvault_core::PassageStore;

use crate::tui_editor;

#[derive(Args)]
pub struct EditArgs {
    /// Secret path to edit
    pub path: String,
}

/// Minimal struct carrying only what `secure_tmp` needs, so we do not have to
/// clone the full `Config` (which is consumed by `PassageStore::open`).
struct TmpConfig {
    tmpdir: Option<PathBuf>,
}

pub fn run(args: EditArgs) -> anyhow::Result<()> {
    let config = Config::resolve()?;

    // Extract fields we need before config is consumed by PassageStore::open.
    let editor_field = config.editor.clone();
    let tmp_config = TmpConfig {
        tmpdir: config.tmpdir.clone(),
    };

    let store = PassageStore::open(config)?;
    let secret = store.get(&args.path)?;
    let current = secret.expose_secret().to_string();

    // Determine which editor to use.
    let editor_cmd = editor_field
        .or_else(|| std::env::var("EDITOR").ok())
        .unwrap_or_else(|| "builtin".into());

    if editor_cmd == "builtin" {
        // Built-in TUI editor — no temp file needed.
        match tui_editor::edit(&args.path, &current)? {
            None => {
                eprintln!("No changes made.");
            }
            Some(new_content) => {
                let trimmed = new_content.trim().to_string();
                if trimmed == current.trim() {
                    eprintln!("No changes made.");
                } else {
                    store.upsert(&args.path, trimmed.as_bytes())?;
                    eprintln!("Updated: {}", args.path);
                }
            }
        }
        return Ok(());
    }

    // External editor path: write decrypted content to a secure temp file.
    let (tmp_path, tmp_fd) = secure_tmp(&tmp_config, &current)?;

    let parts: Vec<&str> = editor_cmd.split_whitespace().collect();
    let (bin, extra_args) = parts
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("EDITOR is empty"))?;

    let bin_path = which::which(bin)
        .map(|p| p.into_os_string())
        .unwrap_or_else(|_| std::ffi::OsString::from(*bin));

    let status = Command::new(&bin_path)
        .args(extra_args)
        .arg(&tmp_path)
        .status()?;

    if !status.success() {
        cleanup_tmp(tmp_fd, &tmp_path);
        anyhow::bail!("editor exited with non-zero status");
    }

    // Read back and re-encrypt
    let new_value = std::fs::read_to_string(&tmp_path)?;
    let trimmed = new_value.trim().to_string();

    // Zero out the temp file contents on disk before removal
    cleanup_tmp(tmp_fd, &tmp_path);

    // Zero out the in-memory copy of the original plaintext
    let mut plain = current.clone();
    plain.zeroize();

    if trimmed == current.trim() {
        eprintln!("No changes made.");
        return Ok(());
    }

    store.upsert(&args.path, trimmed.as_bytes())?;
    eprintln!("Updated: {}", args.path);

    Ok(())
}

/// Returns `(path_for_editor, optional_memfd_owner)`.
///
/// Priority:
///   1. Linux: `memfd_create` — anonymous in-memory file at `/proc/self/fd/<n>`
///   2. Linux/WSL2: `/dev/shm` if it is a tmpfs mount
///   3. macOS: `NamedTempFile` with `F_NOCACHE`
///   4. `config.tmpdir` / `TMPDIR` / OS default tempdir
#[allow(unused_variables)]
fn secure_tmp(
    config: &TmpConfig,
    content: &str,
) -> anyhow::Result<(PathBuf, Option<memfd::Memfd>)> {
    // --- Strategy 1: /dev/shm tmpfs (Linux / WSL2) ---
    // Preferred over memfd because GUI editors (Zed, VS Code) use atomic
    // temp-rename saves that require a real filesystem path.
    #[cfg(target_os = "linux")]
    {
        use nix::sys::statfs::statfs;
        // TMPFS_MAGIC = 0x01021994
        const TMPFS_MAGIC: i64 = 0x0102_1994_u32 as i64;
        if let Ok(st) = statfs("/dev/shm") {
            if st.filesystem_type().0 == TMPFS_MAGIC {
                let shm_tmp = tempfile::NamedTempFile::new_in("/dev/shm")?;
                std::fs::write(shm_tmp.path(), content)?;
                let path = shm_tmp.path().to_path_buf();
                // Forget the handle — cleanup_tmp will overwrite + unlink
                std::mem::forget(shm_tmp);
                return Ok((path, None));
            }
        }
    }

    // --- Strategy 2: memfd_create (Linux, terminal editors only) ---
    // Only works with editors that do direct write() without temp-rename.
    // Kept as fallback when /dev/shm is unavailable.
    #[cfg(target_os = "linux")]
    {
        use std::io::Write as _;
        use memfd::MemfdOptions;
        match MemfdOptions::default()
            .allow_sealing(false)
            .close_on_exec(false)
            .create("revvault-edit")
        {
            Ok(mfd) => {
                let mut f = mfd.as_file();
                f.write_all(content.as_bytes())?;
                let fd_num = {
                    use std::os::unix::io::AsRawFd;
                    mfd.as_raw_fd()
                };
                let proc_path = PathBuf::from(format!("/proc/{}/fd/{fd_num}", std::process::id()));
                return Ok((proc_path, Some(mfd)));
            }
            Err(_) => {}
        }
    }

    // --- Strategy 3: macOS — disable OS caching ---
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        let tmp = tempfile::NamedTempFile::new_in(std::env::temp_dir())?;
        // Disable OS-level read/write caching for this fd
        unsafe {
            libc::fcntl(tmp.as_file().as_raw_fd(), libc::F_NOCACHE, 1i32);
        }
        std::fs::write(tmp.path(), content)?;
        let path = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        return Ok((path, None));
    }

    // --- Strategy 4: config.tmpdir / TMPDIR / OS default ---
    #[allow(unreachable_code)]
    {
        let base_dir = config
            .tmpdir
            .clone()
            .or_else(|| std::env::var("TMPDIR").ok().map(PathBuf::from))
            .unwrap_or_else(std::env::temp_dir);
        let tmp = tempfile::NamedTempFile::new_in(&base_dir)?;
        std::fs::write(tmp.path(), content)?;
        let path = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        Ok((path, None))
    }
}

/// Overwrite the temp file with zeros then remove it.
///
/// For a `memfd`, the kernel reclaims the memory when the last fd is closed
/// (i.e., when `mfd` is dropped here).
fn cleanup_tmp(mfd: Option<memfd::Memfd>, path: &std::path::Path) {
    if mfd.is_none() && path.exists() {
        if let Ok(meta) = std::fs::metadata(path) {
            let zeros = vec![0u8; meta.len() as usize];
            let _ = std::fs::write(path, &zeros);
        }
        let _ = std::fs::remove_file(path);
    }
    drop(mfd);
}
