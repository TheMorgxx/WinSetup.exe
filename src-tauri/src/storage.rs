use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
pub fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
pub fn file_hash(p: &Path) -> Result<String> {
    use std::io::Read;
    let mut f = fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0; 1024 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
pub fn atomic(p: &Path, b: &[u8], backup: bool) -> Result<()> {
    crate::model::no_links(p)?;
    let parent = p.parent().ok_or_else(|| anyhow::anyhow!("Нет каталога"))?;
    fs::create_dir_all(parent)?;
    let mut t = tempfile::NamedTempFile::new_in(parent)?;
    t.write_all(b)?;
    t.as_file().sync_all()?;
    if backup && p.exists() {
        let old = fs::read(p)?;
        atomic(&p.with_extension("toml.bak"), &old, false)?;
    }
    let tmp = t.into_temp_path();
    use std::os::windows::ffi::OsStrExt;
    let w = |v: &Path| {
        v.as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>()
    };
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(a: *const u16, b: *const u16, flags: u32) -> i32;
    }
    let a = w(&tmp);
    let dest = w(p);
    ensure!(
        unsafe { MoveFileExW(a.as_ptr(), dest.as_ptr(), 1 | 8) } != 0,
        "Атомарная запись: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
pub fn root() -> Result<PathBuf> {
    Ok(std::env::current_exe()?.parent().unwrap().to_path_buf())
}
pub fn load(root: &Path) -> Result<crate::model::Config> {
    crate::model::parse(&fs::read_to_string(root.join("winsetup.toml"))?)
}
pub fn redact(s: &str) -> String {
    let mut t = s.to_string();
    for pattern in [
        r"(?i)(authorization\s*[:=]\s*|bearer\s+)[^\s]+",
        r"(?i)(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+",
        r"(?:ghp_|github_pat_|sk-proj-)[A-Za-z0-9_-]+",
        r"https://[^/\s]+@",
        r"https://[^\s?]+\?[^\s]+",
    ] {
        if let Ok(re) = regex::Regex::new(pattern) {
            t = re.replace_all(&t, "[СКРЫТО]").to_string();
        }
    }
    t
}