// Download and cache the LOLDrivers JSON corpus (CLI-only).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

const CORPUS_URL: &str = "https://www.loldrivers.io/api/drivers.json";
const CACHE_FILENAME: &str = "loldrivers.json";
const APP_DIR: &str = "sigkill";
const MAX_CORPUS_BYTES: u64 = 50 * 1024 * 1024;
const HTTP_TIMEOUT_SECS: u32 = 60;
const USER_AGENT: &str = concat!("sigkill/", env!("CARGO_PKG_VERSION"));

#[derive(Debug)]
pub enum FetchError {
    NoCacheDir,
    CurlMissing,
    CurlFailed { code: Option<i32>, stderr: String },
    Io(std::io::Error),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCacheDir => write!(f, "could not determine OS cache directory"),
            Self::CurlMissing => write!(
                f,
                "`curl` not found on PATH; install curl or pass --loldrivers <path>"
            ),
            Self::CurlFailed { code, stderr } => match code {
                Some(c) => write!(f, "curl exited with code {c}: {}", stderr.trim()),
                None => write!(f, "curl did not finish: {}", stderr.trim()),
            },
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for FetchError {}

impl From<std::io::Error> for FetchError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Debug)]
pub struct FetchOutcome {
    pub path: PathBuf,
    pub bytes: u64,
}

pub fn cache_path() -> Result<PathBuf, FetchError> {
    let base = dirs::cache_dir().ok_or(FetchError::NoCacheDir)?;
    let dir = base.join(APP_DIR);
    fs::create_dir_all(&dir)?;
    Ok(dir.join(CACHE_FILENAME))
}

pub fn cached_path() -> Option<PathBuf> {
    let p = cache_path().ok()?;
    p.is_file().then_some(p)
}

pub fn cache_age() -> Option<Duration> {
    let p = cached_path()?;
    let mtime = fs::metadata(&p).and_then(|m| m.modified()).ok()?;
    SystemTime::now().duration_since(mtime).ok()
}

pub fn fetch_to_cache() -> Result<FetchOutcome, FetchError> {
    let dest = cache_path()?;
    let tmp = dest.with_extension("json.tmp");

    let output = Command::new("curl")
        .arg("-fsSL")
        .arg("--user-agent")
        .arg(USER_AGENT)
        .arg("--max-time")
        .arg(HTTP_TIMEOUT_SECS.to_string())
        .arg("--max-filesize")
        .arg(MAX_CORPUS_BYTES.to_string())
        .arg("--output")
        .arg(&tmp)
        .arg(CORPUS_URL)
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FetchError::CurlMissing
            } else {
                FetchError::Io(e)
            }
        })?;

    if !output.status.success() {
        let _ = fs::remove_file(&tmp);
        return Err(FetchError::CurlFailed {
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    let bytes = fs::metadata(&tmp)?.len();
    replace_cache_file(&tmp, &dest)?;

    Ok(FetchOutcome { path: dest, bytes })
}

#[cfg(unix)]
fn replace_cache_file(tmp: &Path, dest: &Path) -> Result<(), FetchError> {
    fs::rename(tmp, dest)?;
    Ok(())
}

#[cfg(not(unix))]
fn replace_cache_file(tmp: &Path, dest: &Path) -> Result<(), FetchError> {
    if dest.exists() {
        fs::remove_file(dest)?;
    }
    fs::rename(tmp, dest)?;
    Ok(())
}

pub fn human_age(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}
