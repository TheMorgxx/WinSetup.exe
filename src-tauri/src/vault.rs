use crate::{
    model::{no_links, resolve, Config},
    storage::file_hash,
};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use anyhow::{ensure, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
const MAGIC: &[u8; 8] = b"WSVAULT1";
const CHUNK: usize = 1024 * 1024;
#[derive(Serialize, Deserialize)]
struct Entry {
    root: String,
    relative: String,
    size: u64,
    sha256: String,
}
#[derive(Serialize, Deserialize)]
struct Archive {
    version: u32,
    roots: Vec<(String, bool)>,
    files: Vec<Entry>,
}
struct Crypt {
    cipher: Aes256Gcm,
    header: Vec<u8>,
    prefix: [u8; 8],
    counter: u32,
}
impl Crypt {
    fn new(password: &str, salt: &[u8], prefix: [u8; 8], header: Vec<u8>) -> Result<Self> {
        ensure!(
            password.chars().count() >= 8,
            "Пароль должен содержать не менее 8 символов"
        );
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(65536, 3, 1, Some(32)).map_err(|e| anyhow::anyhow!(e.to_string()))?,
        )
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        Ok(Self {
            cipher: Aes256Gcm::new_from_slice(&*key).unwrap(),
            header,
            prefix,
            counter: 0,
        })
    }
    fn codec(&mut self, b: &[u8], encrypt: bool) -> Result<Vec<u8>> {
        ensure!(self.counter < u32::MAX, "Архив слишком велик");
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.prefix);
        n[8..].copy_from_slice(&self.counter.to_be_bytes());
        let mut aad = self.header.clone();
        aad.extend(self.counter.to_be_bytes());
        self.counter += 1;
        let p = Payload { msg: b, aad: &aad };
        if encrypt {
            self.cipher.encrypt(Nonce::from_slice(&n), p)
        } else {
            self.cipher.decrypt(Nonce::from_slice(&n), p)
        }
        .map_err(|_| anyhow::anyhow!("Неверный пароль или повреждённый архив"))
    }
    fn write(&mut self, w: &mut impl Write, b: &[u8]) -> Result<()> {
        let encrypted = self.codec(b, true)?;
        w.write_all(&(encrypted.len() as u32).to_le_bytes())?;
        w.write_all(&encrypted)?;
        Ok(())
    }
    fn read(&mut self, r: &mut impl Read) -> Result<Vec<u8>> {
        let mut len = [0; 4];
        r.read_exact(&mut len).context("Архив обрезан")?;
        let len = u32::from_le_bytes(len) as usize;
        ensure!((16..=CHUNK + 16).contains(&len), "Повреждён размер блока");
        let mut b = vec![0; len];
        r.read_exact(&mut b)?;
        self.codec(&b, false)
    }
}
fn exclude(p: &Path) -> bool {
    p.components().any(|c| {
        let n = c.as_os_str().to_string_lossy().to_lowercase();
        [
            "cache2",
            "startupcache",
            "shader-cache",
            "parent.lock",
            "lock",
            ".parentlock",
        ]
        .contains(&n.as_str())
    })
}
fn roots(c: &Config) -> Result<Vec<(String, PathBuf)>> {
    let mut out = vec![];
    if c.backup.firefox {
        out.push((
            "firefox".into(),
            PathBuf::from(std::env::var("APPDATA")?).join("Mozilla/Firefox"),
        ));
    }
    for s in &c.backup.sources {
        out.push((s.key.clone(), resolve(&s.path, c)?));
    }
    ensure!(!out.is_empty(), "Не выбраны источники бэкапа");
    for (_, p) in &out {
        no_links(p)?;
    }
    for (i, (_, a)) in out.iter().enumerate() {
        let a = a.to_string_lossy().replace('/', "\\").to_lowercase();
        for (_, b) in out.iter().skip(i + 1) {
            let b = b.to_string_lossy().replace('/', "\\").to_lowercase();
            ensure!(
                a != b
                    && !a.starts_with(&(b.clone() + "\\"))
                    && !b.starts_with(&(a.clone() + "\\")),
                "Источники бэкапа пересекаются"
            );
        }
    }
    Ok(out)
}
fn relative(s: &str) -> Result<PathBuf> {
    let p = PathBuf::from(s);
    ensure!(
        !p.is_absolute()
            && !s.contains(['\\', ':', '\0'])
            && !s
                .split('/')
                .any(|v| v == ".." || v == "." || v.is_empty() || v.ends_with(['.', ' '])),
        "Небезопасный путь в архиве"
    );
    for v in s.split('/') {
        let n = v.split('.').next().unwrap_or("").to_uppercase();
        ensure!(
            ![
                "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
                "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
                "LPT9"
            ]
            .contains(&n.as_str()),
            "Зарезервированное имя в архиве"
        );
    }
    Ok(p)
}
fn decrypt_to(input: &Path, password: &str) -> Result<(tempfile::TempDir, Archive)> {
    let mut f = fs::File::open(input)?;
    let mut header = vec![0; 36];
    f.read_exact(&mut header)?;
    ensure!(
        &header[..8] == MAGIC && u32::from_le_bytes(header[8..12].try_into()?) == 1,
        "Неизвестный формат vault"
    );
    let mut cipher = Crypt::new(
        password,
        &header[12..28],
        header[28..36].try_into()?,
        header.clone(),
    )?;
    ensure!(
        cipher.read(&mut f)? == b"WinSetup password check v1",
        "Неверный пароль/заголовок"
    );
    let m = cipher.read(&mut f)?;
    let archive: Archive = serde_json::from_slice(&m)?;
    ensure!(
        archive.version == 1 && archive.files.len() <= 100000,
        "Неподдерживаемый архив"
    );
    let mut unique = std::collections::HashSet::new();
    for (root, _) in &archive.roots {
        ensure!(
            crate::model::key(root) && unique.insert(root.clone()),
            "Повторный root"
        );
    }
    let mut names = std::collections::HashSet::new();
    for e in &archive.files {
        ensure!(unique.contains(&e.root), "Неизвестный root");
        relative(&e.relative)?;
        ensure!(
            names.insert(format!("{}/{}", e.root, e.relative).to_lowercase()),
            "Повторный путь"
        );
    }
    let temp = tempfile::tempdir()?;
    for (r, _) in &archive.roots {
        fs::create_dir(temp.path().join(r))?;
    }
    for e in &archive.files {
        let path = temp.path().join(&e.root).join(relative(&e.relative)?);
        fs::create_dir_all(path.parent().unwrap())?;
        let mut out = fs::File::create(&path)?;
        let mut left = e.size;
        while left > 0 {
            let b = cipher.read(&mut f)?;
            ensure!(
                !b.is_empty() && b.len() as u64 <= left,
                "Неверный размер файла"
            );
            out.write_all(&b)?;
            left -= b.len() as u64;
        }
        out.sync_all()?;
        ensure!(
            file_hash(&path)? == e.sha256,
            "Контрольная сумма не совпала: {}",
            e.relative
        );
    }
    ensure!(
        cipher.read(&mut f)? == b"WinSetup authenticated end v1",
        "Нет завершающего блока"
    );
    let mut end = [0];
    ensure!(f.read(&mut end)? == 0, "Лишние данные после архива");
    Ok((temp, archive))
}
pub fn create(c: &Config, dest: &Path, password: &str) -> Result<String> {
    no_links(dest)?;
    ensure!(!dest.exists(), "Файл уже существует; выберите новое имя");
    if c.backup.firefox {
        ensure!(
            !crate::system::firefox_running()?,
            "Закройте Firefox перед созданием бэкапа"
        );
    }
    let roots = roots(c)?;
    let mut archive = Archive {
        version: 1,
        roots: vec![],
        files: vec![],
    };
    let mut originals = vec![];
    for (id, p) in &roots {
        ensure!(p.exists(), "Источник отсутствует: {}", p.display());
        ensure!(
            !dest.starts_with(p),
            "Нельзя создавать архив внутри источника"
        );
        let dir = p.is_dir();
        archive.roots.push((id.clone(), dir));
        if dir {
            for entry in walkdir::WalkDir::new(p).follow_links(false) {
                let e = entry?;
                no_links(e.path())?;
                if !e.file_type().is_file() {
                    continue;
                }
                let rel = e.path().strip_prefix(p)?;
                if id == "firefox" && exclude(rel) {
                    continue;
                }
                let s = rel.to_string_lossy().replace('\\', "/");
                relative(&s)?;
                archive.files.push(Entry {
                    root: id.clone(),
                    relative: s,
                    size: e.metadata()?.len(),
                    sha256: file_hash(e.path())?,
                });
                originals.push(e.path().to_path_buf());
            }
        } else {
            archive.files.push(Entry {
                root: id.clone(),
                relative: "file".into(),
                size: fs::metadata(p)?.len(),
                sha256: file_hash(p)?,
            });
            originals.push(p.clone());
        }
    }
    let manifest = serde_json::to_vec(&archive)?;
    ensure!(manifest.len() <= CHUNK, "Слишком большой список файлов");
    let mut salt = [0; 16];
    let mut prefix = [0; 8];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut prefix);
    let mut h = MAGIC.to_vec();
    h.extend(1u32.to_le_bytes());
    h.extend(salt);
    h.extend(prefix);
    let mut crypt = Crypt::new(password, &salt, prefix, h.clone())?;
    let parent = dest.parent().context("Нет папки назначения")?;
    ensure!(parent.is_dir(), "Папка назначения не существует");
    let mut encrypted = tempfile::NamedTempFile::new_in(parent)?;
    encrypted.write_all(&h)?;
    crypt.write(&mut encrypted, b"WinSetup password check v1")?;
    crypt.write(&mut encrypted, &manifest)?;
    let mut buffer = Zeroizing::new(vec![0; CHUNK]);
    for p in &originals {
        let mut f = fs::File::open(p)?;
        loop {
            let n = f.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            crypt.write(&mut encrypted, &buffer[..n])?;
        }
    }
    crypt.write(&mut encrypted, b"WinSetup authenticated end v1")?;
    encrypted.as_file().sync_all()?;
    let (verification, decoded) = decrypt_to(encrypted.path(), password)?;
    ensure!(decoded.files.len() == originals.len(), "Ошибка верификации");
    for (e, source) in decoded.files.iter().zip(&originals) {
        ensure!(
            file_hash(source)? == file_hash(&verification.path().join(&e.root).join(&e.relative))?,
            "Источник изменился во время бэкапа: {}",
            source.display()
        );
    }
    verification.close()?;
    encrypted.persist_noclobber(dest).map_err(|e| e.error)?;
    Ok(format!(
        "Готово: {} файлов; шифрование и обратная проверка SHA-256 завершены",
        originals.len()
    ))
}
pub fn restore(c: &Config, input: &Path, password: &str) -> Result<String> {
    if c.backup.firefox {
        ensure!(
            !crate::system::firefox_running()?,
            "Закройте Firefox перед восстановлением"
        );
    }
    let (temp, a) = decrypt_to(input, password)?;
    let destinations = roots(c)?;
    for (id, dir) in &a.roots {
        let dest = &destinations
            .iter()
            .find(|(k, _)| k == id)
            .context("В конфиге нет соответствующего источника/назначения")?
            .1;
        no_links(dest)?;
        ensure!(
            dest.parent().is_some(),
            "Нельзя восстанавливать корень диска"
        );
        if !*dir {
            ensure!(
                a.files.iter().filter(|x| &x.root == id).count() == 1,
                "Повреждён файловый источник"
            );
        }
    }
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S-%f").to_string();
    let mut committed: Vec<(PathBuf, Option<PathBuf>)> = vec![];
    let result = (|| -> Result<()> {
        for (id, dir) in &a.roots {
            let dest = &destinations.iter().find(|(k, _)| k == id).unwrap().1;
            fs::create_dir_all(dest.parent().unwrap())?;
            let stage = tempfile::tempdir_in(dest.parent().unwrap())?;
            let payload = stage.path().join("payload");
            let source = temp.path().join(id);
            if *dir {
                copy_tree(&source, &payload)?;
            } else {
                fs::copy(source.join("file"), &payload)?;
            }
            let backup = if dest.exists() {
                let b = PathBuf::from(format!("{}.bak-{}", dest.display(), stamp));
                ensure!(!b.exists(), "Путь .bak уже существует");
                fs::rename(dest, &b)?;
                Some(b)
            } else {
                None
            };
            if let Err(e) = fs::rename(&payload, dest) {
                if let Some(b) = &backup {
                    let _ = fs::rename(b, dest);
                }
                return Err(e.into());
            }
            committed.push((dest.clone(), backup));
        }
        Ok(())
    })();
    if let Err(e) = result {
        for (dest, bak) in committed.iter().rev() {
            if dest.is_dir() {
                let _ = fs::remove_dir_all(dest);
            } else {
                let _ = fs::remove_file(dest);
            }
            if let Some(b) = bak {
                let _ = fs::rename(b, dest);
            }
        }
        return Err(e);
    }
    temp.close()?;
    Ok(format!(
        "Восстановлено {} источников; предыдущие данные сохранены в .bak-{}",
        a.roots.len(),
        stamp
    ))
}
fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for item in walkdir::WalkDir::new(src).min_depth(1) {
        let item = item?;
        let p = dst.join(item.path().strip_prefix(src)?);
        if item.file_type().is_dir() {
            fs::create_dir_all(p)?;
        } else {
            fs::copy(item.path(), p)?;
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encryption_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("data.bin"), vec![42u8; CHUNK * 2 + 17]).unwrap();
        let mut c = crate::model::defaults();
        c.backup.firefox = false;
        c.backup.sources = vec![crate::model::BackupSource {
            key: "test".into(),
            path: source.display().to_string(),
        }];
        let target = dir.path().join("test.wsvault");
        create(&c, &target, "test-password").unwrap();
        let (decoded, _) = decrypt_to(&target, "test-password").unwrap();
        assert_eq!(
            file_hash(&source.join("data.bin")).unwrap(),
            file_hash(&decoded.path().join("test/data.bin")).unwrap()
        );
        assert!(decrypt_to(&target, "wrong-password").is_err());
        let mut b = fs::read(&target).unwrap();
        let n = b.len();
        b[n - 1] ^= 1;
        fs::write(&target, b).unwrap();
        assert!(decrypt_to(&target, "test-password").is_err());
    }
}
