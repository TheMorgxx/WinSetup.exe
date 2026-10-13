use crate::{
    model::{self, no_links, resolve, Config},
    storage, system,
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
const AWAITING: &str = "awaiting_confirm";
const AWAITING_DETAIL: &str = "Ожидает подтверждения продолжить без точки восстановления";
const NO_POINT_DETAIL: &str =
    "Точка восстановления не создана; продолжено без неё по подтверждению пользователя";
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value")]
pub enum Action {
    Check,
    RestorePoint,
    Folder(String),
    Program(String),
    Tweak(String, String),
    Remove(String),
    Startup(String),
    Repository(String),
    Restore,
    Final,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: usize,
    pub name: String,
    pub risk: String,
    pub reversible: String,
    pub status: String,
    pub detail: String,
    pub action: Action,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Plan {
    pub profile: String,
    pub fingerprint: String,
    pub tasks: Vec<Task>,
    pub warnings: Vec<String>,
    pub readiness: Value,
    pub displays: Vec<system::Display>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Run {
    pub id: String,
    pub plan: Plan,
    pub active: bool,
    pub paused: bool,
    pub tasks: Vec<Task>,
    pub log: Vec<String>,
    pub technical: Vec<String>,
    pub finished: bool,
}
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Rollback {
    pub registry: Vec<system::RegUndo>,
    pub displays: Vec<system::Display>,
    pub rolled_back: bool,
}
pub struct Engine {
    pub root: PathBuf,
    pub current: Mutex<Option<Run>>,
    pub busy: AtomicBool,
    pub pause: AtomicBool,
    pub cancel: AtomicBool,
}
impl Engine {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            current: Mutex::new(None),
            busy: AtomicBool::new(false),
            pause: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
        }
    }
    pub fn state(&self) -> Option<Run> {
        self.current.lock().unwrap().clone()
    }
    fn save(&self) -> Result<()> {
        if let Some(r) = self.state() {
            storage::atomic(
                &self.root.join("runs").join(format!("{}.json", r.id)),
                &serde_json::to_vec_pretty(&r)?,
                false,
            )?;
        }
        Ok(())
    }
    fn note(&self, s: &str, technical: bool) {
        if let Some(r) = self.current.lock().unwrap().as_mut() {
            let line = format!(
                "{} {}",
                chrono::Local::now().format("%H:%M:%S"),
                storage::redact(s)
            );
            if technical {
                r.technical.push(line)
            } else {
                r.log.push(line)
            };
        }
        let _ = self.save();
    }
}
pub fn fingerprint(c: &Config) -> String {
    let mut c = c.clone();
    c.application.mode = "choose".into();
    c.application.theme = "dark".into();
    c.application.selected_profile = String::new();
    storage::hash(&serde_json::to_vec(&c).unwrap())
}
pub fn plan(c: &Config, name: &str, network: bool) -> Result<Plan> {
    model::validate(c)?;
    let p = c
        .profiles
        .iter()
        .find(|p| p.name == name)
        .context("Профиль не найден")?;
    let readiness = system::inventory()?;
    let mut warnings = vec![];
    if readiness["admin"] != true {
        warnings.push("Нет прав администратора: реальное выполнение заблокировано".into());
    }
    if c.application.data_drive.is_empty() {
        warnings.push("Диск данных не выбран: выберите его перед запуском".into());
    }
    if readiness["winget"] != true && !p.programs.is_empty() {
        warnings.push("winget отсутствует: программы будут отмечены для ручной установки".into());
    }
    if network && !system::internet() {
        warnings.push("Интернет недоступен: установки и клонирование могут не пройти".into());
    }
    if readiness["windows"]
        .as_str()
        .map(|s| !s.contains("10"))
        .unwrap_or(true)
    {
        warnings.push("Не Windows 10: твики будут пропущены".into());
    }
    let mut tasks = vec![];
    let mut push = |name: String, risk: &str, rev: &str, action: Action| {
        tasks.push(Task {
            id: tasks.len(),
            name,
            risk: risk.into(),
            reversible: rev.into(),
            status: "pending".into(),
            detail: String::new(),
            action,
        });
    };
    push(
        "Проверка системы".into(),
        "Безопасно",
        "Только чтение",
        Action::Check,
    );
    push(
        "Точка восстановления Windows".into(),
        "Безопасно",
        "Создание контрольной точки",
        Action::RestorePoint,
    );
    for id in &p.paths {
        let x = c.paths.iter().find(|x| &x.key == id).unwrap();
        push(
            format!("Создать папку {}", x.path),
            "Безопасно",
            "Существующие данные не меняются",
            Action::Folder(id.clone()),
        );
    }
    let mut programs = c
        .programs
        .iter()
        .filter(|x| p.programs.contains(&x.key))
        .collect::<Vec<_>>();
    programs.sort_by_key(|x| x.order);
    if let Some(index) = programs.iter().position(|x| x.key == "vencord") {
        let v = programs.remove(index);
        let pos = programs
            .iter()
            .position(|x| x.key == "discord")
            .map(|i| i + 1)
            .unwrap_or(programs.len());
        programs.insert(pos, v);
    }
    for x in programs {
        push(
            format!(
                "Установить {} [{}]{}",
                x.name,
                x.id,
                if x.location.is_empty() {
                    String::new()
                } else {
                    format!(" → {}", x.location)
                }
            ),
            "Осторожно",
            "Откат установки автоматически не выполняется",
            Action::Program(x.key.clone()),
        );
    }
    for (k, state) in &p.windows_tweaks {
        if state != "keep" {
            if k == "max_refresh" && state == "disabled" {
                warnings.push(
                    "Для частоты disabled трактуется как keep: безопасная частота не угадывается"
                        .into(),
                );
                continue;
            }
            push(
                format!(
                    "{}: {}",
                    c.windows_tweaks
                        .iter()
                        .find(|t| &t.key == k)
                        .map(|t| t.name.clone())
                        .unwrap_or(k.clone()),
                    if state == "enabled" {
                        "включить"
                    } else {
                        "выключить"
                    }
                ),
                "Осторожно",
                "Есть снимок отката",
                Action::Tweak(k.clone(), state.clone()),
            );
        }
    }
    for a in &p.appx_removal {
        let found = readiness["apps"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|x| x["Name"] == *a);
        if let Some(app) = found {
            if app["IsFramework"] == true
                || app["NonRemovable"] == true
                || app["SignatureKind"] == 4
            {
                warnings.push(format!("{} защищён и пропущен", a));
                continue;
            }
            push(
                format!("Удалить {} у текущего пользователя", a),
                "Высокий риск",
                "Частично обратимо: ручная переустановка из Store",
                Action::Remove(a.clone()),
            );
        }
    }
    for id in &p.autostart {
        push(
            format!(
                "Отключить автозапуск {}",
                c.autostart.iter().find(|a| &a.key == id).unwrap().name
            ),
            "Осторожно",
            "Есть снимок StartupApproved",
            Action::Startup(id.clone()),
        );
    }
    for id in &p.repositories {
        let r = c.repositories.iter().find(|r| &r.key == id).unwrap();
        push(
            format!("Клонировать {} → {}", r.url, r.target),
            "Безопасно",
            "Существующая папка пропускается",
            Action::Repository(id.clone()),
        );
    }
    if p.restore_backup {
        push(
            "Восстановить Data Vault".into(),
            "Осторожно",
            "Существующие источники переименуются в .bak-дата",
            Action::Restore,
        );
    }
    push(
        "Финальная проверка и напоминание о драйвере".into(),
        "Безопасно",
        "Только чтение",
        Action::Final,
    );
    Ok(Plan {
        profile: p.name.clone(),
        fingerprint: fingerprint(c),
        tasks,
        warnings,
        readiness,
        displays: system::displays(),
    })
}
fn rb_save(root: &Path, id: &str, rb: &Rollback) -> Result<()> {
    storage::atomic(
        &root.join("runs").join(format!("{}.rollback.json", id)),
        &serde_json::to_vec_pretty(rb)?,
        false,
    )
}
fn record(rb: &mut Rollback, root: &Path, id: &str, h: &str, p: &str, n: &str) -> Result<()> {
    if !rb
        .registry
        .iter()
        .any(|r| r.hive == h && r.path == p && r.name == n)
    {
        rb.registry.push(system::snapshot(h, p, n)?);
        rb_save(root, id, rb)?;
    }
    Ok(())
}
/// Временный сбой: повтор имеет смысл (сеть, занятый файл, код выхода установщика).
/// Всё остальное (неверный пароль vault, ошибки валидации, отсутствующий пакет,
/// несовпадение SHA-256, защита от ссылок и т.п.) считается неисправимым.
#[derive(Debug)]
struct Transient(String);
impl std::fmt::Display for Transient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Transient {}
fn transient(msg: String) -> anyhow::Error {
    anyhow::Error::new(Transient(msg))
}
fn is_transient(err: &anyhow::Error) -> bool {
    use std::io::ErrorKind::*;
    err.chain().any(|cause| {
        if cause.downcast_ref::<Transient>().is_some() {
            return true;
        }
        if let Some(r) = cause.downcast_ref::<reqwest::Error>() {
            return match r.status() {
                Some(s) => s.is_server_error() || s.as_u16() == 408 || s.as_u16() == 429,
                None => r.is_timeout() || r.is_connect() || r.is_request() || r.is_body(),
            };
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            // 32 — файл занят другим процессом, 33 — часть файла заблокирована,
            // 1224 — файл открыт как отображаемая секция
            return matches!(io.raw_os_error(), Some(32 | 33 | 1224))
                || matches!(
                    io.kind(),
                    TimedOut
                        | Interrupted
                        | WouldBlock
                        | ConnectionReset
                        | ConnectionAborted
                        | ConnectionRefused
                );
        }
        false
    })
}
fn network_failure(output: &str) -> bool {
    let o = output.to_ascii_lowercase();
    [
        "could not resolve host",
        "failed to connect",
        "could not connect",
        "timed out",
        "connection reset",
        "rpc failed",
        "early eof",
        "unexpected disconnect",
        "remote end hung up",
    ]
    .iter()
    .any(|m| o.contains(m))
}
fn clone_repo(url: &str, path: &Path, branch: &str) -> Result<String> {
    model::https(url)?;
    no_links(path)?;
    if path.exists() {
        return Ok("Пропущено: папка уже существует, не изменялась".into());
    }
    fs::create_dir_all(path.parent().context("Нет родительской папки")?)?;
    let temp = tempfile::tempdir_in(path.parent().unwrap())?;
    let dst = temp.path().join("repo");
    let mut args = vec!["-c".into(), "core.hooksPath=NUL".into(), "clone".into()];
    if !branch.is_empty() {
        args.extend(["--branch".into(), branch.into()]);
    }
    args.extend(["--".into(), url.into(), dst.display().to_string()]);
    let (ok, out) = system::command(&system::tool("git"), &args)?;
    if !(ok && dst.join(".git").exists()) {
        let msg = format!(
            "Клонирование/авторизация не удались; проверьте Git Credential Manager. {}",
            out
        );
        return Err(if network_failure(&out) {
            transient(msg)
        } else {
            anyhow::anyhow!(msg)
        });
    }
    ensure!(
        !path.exists(),
        "Папка назначения появилась во время клонирования"
    );
    fs::rename(dst, path)?;
    Ok(out)
}
fn install(c: &Config, p: &model::Program, force: bool) -> Result<String> {
    if p.source == "git" {
        return clone_repo(&p.url, &resolve(&p.location, c)?, "");
    }
    if !force && system::installed(p)? {
        return Ok("Пропущено: программа найдена; установка пропущена".into());
    }
    if p.key == "vencord" {
        let discord = c
            .programs
            .iter()
            .find(|x| x.key == "discord")
            .context("Нет Discord в конфиге")?;
        ensure!(system::installed(discord)?, "Сначала установите Discord");
    }
    let (ok, out) = if p.source == "direct" {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("verified.msi");
        let mut response = reqwest::blocking::Client::builder()
            .https_only(true)
            .timeout(std::time::Duration::from_secs(1800))
            .build()?
            .get(&p.url)
            .send()?
            .error_for_status()?;
        let mut file = fs::File::create(&path)?;
        response.copy_to(&mut file)?;
        file.sync_all()?;
        ensure!(
            storage::file_hash(&path)?.eq_ignore_ascii_case(&p.sha256),
            "SHA-256 не совпадает, запуск запрещён"
        );
        system::command(
            "msiexec.exe",
            &vec![
                "/i".into(),
                path.display().to_string(),
                "/qn".into(),
                "/norestart".into(),
            ],
        )?
    } else {
        let mut args = vec![
            "install".into(),
            "--id".into(),
            p.id.clone(),
            "--exact".into(),
            "--source".into(),
            p.source.clone(),
            "--silent".into(),
            "--accept-package-agreements".into(),
            "--accept-source-agreements".into(),
            "--disable-interactivity".into(),
        ];
        if force {
            args.push("--force".into())
        }
        if !p.version.is_empty() {
            args.extend(["--version".into(), p.version.clone()]);
        }
        if !p.location.is_empty() {
            let path = resolve(&p.location, c)?;
            no_links(&path)?;
            args.extend(["--location".into(), path.display().to_string()]);
        }
        system::command("winget.exe", &args)?
    };
    if !system::installed(p)? {
        let msg = format!(
            "Поставить вручную: {}. Код успеха={}; постпроверка не нашла программу. {}",
            p.url, ok, out
        );
        // Ненулевой код выхода установщика — временный сбой; при успешном коде
        // повтор ничего не изменит.
        return Err(if ok {
            anyhow::anyhow!(msg)
        } else {
            transient(msg)
        });
    }
    Ok(out)
}
fn execute(
    e: &Engine,
    c: &Config,
    t: &Task,
    rb: &mut Rollback,
    password: &str,
    force_vencord: bool,
    started: chrono::DateTime<chrono::Local>,
) -> Result<String> {
    let run = e.state().unwrap();
    match &t.action {
        Action::Check => {
            let inv = system::inventory()?;
            ensure!(inv["admin"] == true, "Нужны права администратора");
            if run.tasks.iter().any(|t| {
                matches!(t.action, Action::Folder(_) | Action::Repository(_))
                    || matches!(t.action, Action::Program(_))
            }) {
                ensure!(!c.application.data_drive.is_empty(), "Выберите диск данных");
                let drive = inv["disks"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|d| d["DeviceID"] == c.application.data_drive)
                    .context("Диск данных отсутствует")?;
                ensure!(
                    drive["FreeSpace"].as_u64().unwrap_or(0)
                        >= c.execution.minimum_free_gib * 1024 * 1024 * 1024,
                    "Недостаточно свободного места"
                );
            }
            Ok("Проверка системы пройдена".into())
        }
        Action::RestorePoint => system::restore_point(started),
        Action::Folder(key) => {
            let p = resolve(&c.paths.iter().find(|p| &p.key == key).unwrap().path, c)?;
            no_links(&p)?;
            if p.exists() {
                ensure!(p.is_dir(), "На месте папки находится файл");
                return Ok("Пропущено: папка существует".into());
            }
            fs::create_dir_all(p)?;
            Ok("Папка создана".into())
        }
        Action::Program(key) => install(
            c,
            c.programs.iter().find(|p| &p.key == key).unwrap(),
            force_vencord && key == "vencord",
        ),
        Action::Tweak(key, state) => {
            if !run.plan.readiness["windows"]
                .as_str()
                .unwrap_or("")
                .contains("10")
            {
                return Ok("Пропущено: не поддерживается на этой Windows".into());
            }
            if key == "max_refresh" {
                let displays = system::displays();
                ensure!(!displays.is_empty(), "Нет доступных режимов дисплея");
                if rb.displays.is_empty() {
                    rb.displays = displays.clone();
                    rb_save(&e.root, &run.id, rb)?;
                }
                for d in displays {
                    system::set_display(&d, d.maximum)?;
                }
                return Ok("Частота установлена и проверена".into());
            }
            for (p, n, v) in system::tweak_values(key, state)? {
                record(rb, &e.root, &run.id, "HKCU", &p, &n)?;
                system::write_reg(
                    "HKCU",
                    &p,
                    &n,
                    v.to_le_bytes().to_vec(),
                    winreg::enums::REG_DWORD,
                )?;
            }
            Ok("Значения применены и проверены".into())
        }
        Action::Remove(name) => system::remove_app(name),
        Action::Startup(key) => {
            let a = c.autostart.iter().find(|x| &x.key == key).unwrap();
            let live = system::startup()?;
            ensure!(
                live.as_array()
                    .into_iter()
                    .flatten()
                    .any(|x| x["key"] == *key
                        && x["name"] == a.name
                        && x["hive"] == a.hive
                        && x["category"] == a.category),
                "Запись автозапуска изменилась; пересоздайте план"
            );
            let path = format!(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\{}",
                a.category
            );
            record(rb, &e.root, &run.id, &a.hive, &path, &a.name)?;
            let mut bytes = vec![0; 12];
            bytes[0] = 3;
            system::write_reg(&a.hive, &path, &a.name, bytes, winreg::enums::REG_BINARY)?;
            Ok("Автозапуск отключён; исходная запись сохранена".into())
        }
        Action::Repository(key) => {
            let r = c.repositories.iter().find(|r| &r.key == key).unwrap();
            clone_repo(&r.url, &resolve(&r.target, c)?, &r.branch)
        }
        Action::Restore => {
            ensure!(
                !c.backup.vault_path.trim().is_empty(),
                "Не указан файл Data Vault (.wsvault): задайте путь в разделе «Бэкап» (backup.vault_path) или отключите восстановление архива в профиле"
            );
            ensure!(
                !password.is_empty(),
                "Введите пароль Data Vault перед запуском"
            );
            crate::vault::restore(c, &resolve(&c.backup.vault_path, c)?, password)
        }
        Action::Final => {
            let mut missing = vec![];
            for t in &run.tasks {
                if let Action::Program(k) = &t.action {
                    let p = c.programs.iter().find(|p| &p.key == k).unwrap();
                    if p.source != "git" && !system::installed(p).unwrap_or(false) {
                        missing.push(p.name.clone());
                    }
                }
            }
            ensure!(missing.is_empty(),"Не найдены программы: {}. Поставьте вручную. Напоминание: проверьте драйвер чипсета AMD B550.",missing.join(", "));
            Ok("Постпроверка завершена. Напоминание: проверьте драйвер чипсета AMD B550 на официальной странице.".into())
        }
    }
}
pub fn start(
    e: Arc<Engine>,
    c: Config,
    p: Plan,
    removal_confirmed: bool,
    password: String,
    resume: Option<String>,
    force_vencord: bool,
    no_point_ok: bool,
) -> Result<String> {
    ensure!(!e.busy.swap(true, Ordering::SeqCst), "Выполнение уже идёт");
    let setup = (|| -> Result<Run> {
        ensure!(
            fingerprint(&c) == p.fingerprint,
            "Конфиг изменился: создайте новый план"
        );
        ensure!(
            removal_confirmed
                || !p
                    .tasks
                    .iter()
                    .any(|t| matches!(t.action, Action::Remove(_))),
            "Подтвердите удаления"
        );
        if let Some(id) = resume {
            ensure!(model::key(&id), "Недопустимый id");
            let mut old: Run = serde_json::from_slice(&fs::read(
                e.root.join("runs").join(format!("{}.json", id)),
            )?)?;
            ensure!(
                old.plan.fingerprint == fingerprint(&c),
                "Для продолжения нужен исходный конфиг"
            );
            for t in &mut old.tasks {
                if !["succeeded", "skipped"].contains(&t.status.as_str()) {
                    ensure!(p.tasks.iter().any(|allowed|serde_json::to_value(&allowed.action).ok()==serde_json::to_value(&t.action).ok()),"Продолжение содержит действие вне текущего плана; сформируйте новый запуск");
                    t.status = "pending".into();
                }
            }
            if no_point_ok {
                for t in &mut old.tasks {
                    if matches!(t.action, Action::RestorePoint) && t.status == "pending" {
                        t.status = "skipped".into();
                        t.detail = NO_POINT_DETAIL.into();
                    }
                }
            }
            old.active = true;
            old.finished = false;
            return Ok(old);
        }
        let id = chrono::Local::now().format("%Y%m%d-%H%M%S-%f").to_string();
        Ok(Run {
            id,
            plan: p.clone(),
            active: true,
            paused: false,
            tasks: p.tasks.clone(),
            log: vec![],
            technical: vec![],
            finished: false,
        })
    })();
    let run = match setup {
        Ok(r) => r,
        Err(err) => {
            e.busy.store(false, Ordering::SeqCst);
            return Err(err);
        }
    };
    let id = run.id.clone();
    *e.current.lock().unwrap() = Some(run);
    e.pause.store(false, Ordering::SeqCst);
    e.cancel.store(false, Ordering::SeqCst);
    if let Err(err) = e.save() {
        e.busy.store(false, Ordering::SeqCst);
        return Err(err);
    }
    let return_id = id.clone();
    let started = chrono::Local::now();
    std::thread::spawn(move || {
        let password = zeroize::Zeroizing::new(password);
        let rb_path = e.root.join("runs").join(format!("{}.rollback.json", id));
        let load_rollback = (|| -> Result<Rollback> {
            if rb_path.exists() {
                Ok(serde_json::from_slice(&fs::read(&rb_path)?)?)
            } else {
                Ok(Rollback::default())
            }
        })();
        let mut rb = match load_rollback {
            Ok(r) => r,
            Err(err) => {
                e.note(
                    &format!("Файл отката повреждён: {}. Изменения запрещены.", err),
                    false,
                );
                if let Some(r) = e.current.lock().unwrap().as_mut() {
                    r.active = false;
                }
                let _ = e.save();
                e.busy.store(false, Ordering::SeqCst);
                return;
            }
        };
        let count = e.state().unwrap().tasks.len();
        for i in 0..count {
            while e.pause.load(Ordering::SeqCst) && !e.cancel.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            if e.cancel.load(Ordering::SeqCst) {
                e.note(
                    "Отменено между задачами; активный установщик не прерывался",
                    false,
                );
                break;
            }
            let t = e.state().unwrap().tasks[i].clone();
            if ["succeeded", "skipped", AWAITING].contains(&t.status.as_str()) {
                continue;
            }
            if let Some(r) = e.current.lock().unwrap().as_mut() {
                r.tasks[i].status = "running".into();
            }
            if let Err(err) = e.save() {
                e.note(&format!("Журнал недоступен: {}", err), false);
                break;
            }
            e.note(&t.name, false);
            let mut result = Err(anyhow::anyhow!("Задача не выполнена"));
            for attempt in 0..=c.execution.retries {
                result = execute(&e, &c, &t, &mut rb, &password, force_vencord, started);
                if result.is_ok() {
                    break;
                }
                e.note(
                    &format!("Попытка {}: {}", attempt + 1, result.as_ref().unwrap_err()),
                    true,
                );
                if e.cancel.load(Ordering::SeqCst) {
                    break;
                }
                if !is_transient(result.as_ref().unwrap_err()) {
                    e.note("Ошибка неисправимая; повторные попытки не выполняются", true);
                    break;
                }
            }
            let critical = matches!(t.action, Action::Check) && result.is_err();
            let point_failed = matches!(t.action, Action::RestorePoint) && result.is_err();
            let point_reason = result
                .as_ref()
                .err()
                .map(|x| x.to_string())
                .unwrap_or_default();
            let (status, msg) = match result {
                Ok(s) => (
                    if s.starts_with("Пропущено:") {
                        "skipped"
                    } else {
                        "succeeded"
                    },
                    s,
                ),
                Err(err) if point_failed && no_point_ok => (
                    "skipped",
                    format!("{}. Продолжено без точки: {}", NO_POINT_DETAIL, err),
                ),
                Err(err) => ("failed", err.to_string()),
            };
            if let Some(r) = e.current.lock().unwrap().as_mut() {
                r.tasks[i].status = status.into();
                r.tasks[i].detail = storage::redact(&msg);
            }
            e.note(&msg, true);
            e.note(
                &format!(
                    "{}: {}",
                    t.name,
                    match status {
                        "succeeded" => "готово",
                        "skipped" => "пропущено",
                        _ => "ошибка; см. журнал",
                    }
                ),
                false,
            );
            if critical {
                e.note(
                    "Безопасная остановка: обязательная проверка системы не пройдена",
                    false,
                );
                break;
            }
            if point_failed {
                if no_point_ok {
                    e.note(
                        &format!(
                            "Предупреждение: точка восстановления не создана, продолжаем без неё (подтверждено заранее). {}",
                            point_reason
                        ),
                        false,
                    );
                } else {
                    let mut held = 0;
                    if let Some(r) = e.current.lock().unwrap().as_mut() {
                        for x in r.tasks.iter_mut() {
                            if x.status == "pending"
                                && matches!(x.action, Action::Tweak(_, _) | Action::Remove(_))
                            {
                                x.status = AWAITING.into();
                                x.detail = AWAITING_DETAIL.into();
                                held += 1;
                            }
                        }
                    }
                    e.note(
                        &format!(
                            "Предупреждение: точка восстановления не создана. Твики Windows и удаления встроенных приложений ({}) ожидают подтверждения продолжить без точки; остальные этапы выполняются. {}",
                            held, point_reason
                        ),
                        false,
                    );
                }
            }
        }
        if let Some(r) = e.current.lock().unwrap().as_mut() {
            r.active = false;
            r.paused = false;
            r.finished = r
                .tasks
                .iter()
                .all(|t| ["succeeded", "skipped"].contains(&t.status.as_str()));
            for t in &mut r.tasks {
                if t.status == "running" {
                    t.status = "interrupted".into()
                }
            }
        }
        let _ = e.save();
        e.busy.store(false, Ordering::SeqCst);
    });
    Ok(return_id)
}
pub fn rollback(e: &Engine, id: &str) -> Result<String> {
    ensure!(
        !e.busy.load(Ordering::SeqCst),
        "Сначала завершите выполнение"
    );
    ensure!(model::key(id), "Неверный id");
    let p = e.root.join("runs").join(format!("{}.rollback.json", id));
    let mut r: Rollback = serde_json::from_slice(&fs::read(&p)?)?;
    ensure!(!r.rolled_back, "Этот запуск уже откачен");
    for a in r.registry.iter().rev() {
        system::undo_reg(a)?;
    }
    for d in &r.displays {
        system::set_display(d, d.current)?;
    }
    r.rolled_back = true;
    rb_save(&e.root, id, &r)?;
    Ok("Настройки реестра, автозапуск и частота восстановлены. Установки, удаления Appx и восстановленные файлы автоматически не отменяются.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrong_vault_password_is_not_retried() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a.txt"), b"x").unwrap();
        let mut c = model::defaults();
        c.backup.firefox = false;
        c.backup.sources = vec![model::BackupSource {
            key: "t".into(),
            path: src.display().to_string(),
        }];
        let v = dir.path().join("t.wsvault");
        crate::vault::create(&c, &v, "right-password").unwrap();
        let err = crate::vault::restore(&c, &v, "wrong-password").unwrap_err();
        assert!(!is_transient(&err), "неверный пароль не должен повторяться: {err}");
    }
}
