use crate::{
    model::{self, no_links, resolve, Config},
    bootstrap, storage, system,
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
    Bootstrap,
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
    #[serde(default)]
    pub verification_only: bool,
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
    pub bootstrap: bootstrap::Runtime,
    pub current: Mutex<Option<Run>>,
    pub busy: AtomicBool,
    pub pause: AtomicBool,
    pub cancel: AtomicBool,
}
impl Engine {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            bootstrap: bootstrap::Runtime::default(),
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
    let mut readiness = system::inventory()?;
    let preparation = bootstrap::report(&storage::root()?, Some(c), &readiness, None);
    readiness["winget"] = serde_json::json!(preparation.winget_ready);
    readiness["bootstrap"] = serde_json::to_value(preparation)?;
    let mut warnings = vec![];
    if readiness["admin"] != true {
        warnings.push("Нет прав администратора: реальное выполнение заблокировано".into());
    }
    if c.application.data_drive.is_empty() {
        warnings.push("Диск данных не выбран: выберите его перед запуском".into());
    }
    if readiness["winget"] != true && !p.programs.is_empty() {
        warnings.push("winget отсутствует: подготовка среды предложит установку; при отказе или сбое зависимые задачи будут ожидать winget".into());
    }
    if network && readiness["bootstrap"]["checks"].as_array().into_iter().flatten().any(|x| x["id"]=="internet" && x["status"]!="ОК") {
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
            verification_only: false,
            action,
        });
    };
    push("Подготовка среды".into(), "Осторожно", "winget устанавливается только с подтверждением", Action::Bootstrap);
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
    let displays=system::displays();
    for task in &mut tasks {
        if matches!(&task.action,Action::Tweak(key,state) if key=="max_refresh" && state=="enabled") {
            task.detail=if displays.is_empty() { "Нет доступных режимов дисплея".into() } else {
                displays.iter().map(|d|format!("{}: {}",d.device,
                    system::refresh_decision(d).map(|v|v.message()).unwrap_or_else(|e|e.to_string())))
                    .collect::<Vec<_>>().join("\n")
            };
        }
    }
    Ok(Plan {
        profile: p.name.clone(),
        fingerprint: fingerprint(c),
        tasks,
        warnings,
        readiness,
        displays,
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
/// Временный сбой: подтверждённая сетевая ошибка или занятый файл/установщик.
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
#[derive(Debug)]
struct VerificationPending(String);
impl std::fmt::Display for VerificationPending {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.write_str(&self.0)}
}
impl std::error::Error for VerificationPending {}
fn verification_pending(message:impl Into<String>)->anyhow::Error {anyhow::Error::new(VerificationPending(message.into()))}
fn verification_only(t:&Task)->bool {
    t.verification_only || (matches!(t.action,Action::Program(_)) &&
        (t.status=="needs_verification" || t.detail.contains("Код успеха=true; постпроверка не нашла программу")))
}
fn poll_verification(mut probe:impl FnMut()->Result<bool>,mut wait:impl FnMut(),mut cancelled:impl FnMut()->bool,attempts:usize)->Result<()> {
    let mut last="Программа пока не обнаружена".to_string();
    for attempt in 0..attempts {
        if cancelled(){return Err(verification_pending("Проверка остановлена пользователем; установщик повторно не запускался"));}
        match probe() {Ok(true)=>return Ok(()),Ok(false)=>last="Программа пока не обнаружена".into(),Err(e)=>last=format!("Проверка недоступна: {e}")}
        if attempt+1<attempts {wait();}
    }
    Err(verification_pending(format!("{last}. Нужна проверка результата; «Продолжить» повторит только чтение состояния, без переустановки.")))
}
fn verify_program(e:&Engine,p:&model::Program)->Result<()> {
    poll_verification(||system::installed(p),||{
        for _ in 0..20 {if e.cancel.load(Ordering::SeqCst){break;}std::thread::sleep(std::time::Duration::from_millis(100));}
    },||e.cancel.load(Ordering::SeqCst),6)
}
fn installer_failure(p:&model::Program,result:&system::CommandResult)->anyhow::Error {
    let code=result.code.map(|c|format!("{} (0x{:08X})",c as u32,c as u32)).unwrap_or_else(||"неизвестен".into());
    let output=system::compact_output(&result.output);
    let message=format!("Установщик {} сообщил об ошибке. Код процесса: {code}. Установка не подтверждена. Подробнее: {}\n{output}",p.name,p.url);
    // Неизвестные/аппаратные ошибки не считаются временными только по ненулевому коду.
    let busy=matches!(result.code.map(|c|c as u32),Some(1618 | 0x80070652));
    if busy || network_failure(&result.output){transient(message)}else{anyhow::anyhow!(message)}
}
fn remember_verification(e:&Engine,id:usize,value:bool)->Result<()> {
    {
        let mut current=e.current.lock().unwrap();
        let run=current.as_mut().context("Нет активного журнала установки")?;
        run.tasks.get_mut(id).context("Не найдена задача установки")?.verification_only=value;
    }
    e.save()
}
fn install(e:&Engine, t:&Task, c: &Config, p: &model::Program, force: bool) -> Result<String> {
    if p.source == "git" {
        return clone_repo(&p.url, &resolve(&p.location, c)?, "");
    }
    if verification_only(t) {
        verify_program(e,p)?;
        return Ok("Установка подтверждена повторной проверкой; установщик не запускался".into());
    }
    if !force {
        if let Some(evidence)=system::installed_evidence(p)? {
            return Ok(format!("Пропущено: программа найдена; установка пропущена\nОснование: {evidence}"));
        }
    }
    if p.key == "vencord" {
        let discord = c
            .programs
            .iter()
            .find(|x| x.key == "discord")
            .context("Нет Discord в конфиге")?;
        verify_program(e,discord).map_err(|err|anyhow::anyhow!("Сначала дождитесь подтверждения установки Discord; Vencord не запускался: {err}"))?;
    }
    let result = if p.source == "direct" {
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
        remember_verification(e,t.id,true)?;
        system::command_result(
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
        remember_verification(e,t.id,true)?;
        system::command_result("winget.exe", &args)?
    };
    let restart=p.source=="direct" && matches!(result.code,Some(3010 | 1641));
    if !result.success && !restart {remember_verification(e,t.id,false)?;return Err(installer_failure(p,&result));}
    // Durable marker: resume after a successful installer only rechecks; it cannot reinstall.
    remember_verification(e,t.id,true)
        .map_err(|err|verification_pending(format!("Установщик завершился, но журнал проверки не сохранён: {err}. Не запускайте установку заново до проверки результата.")))?;
    verify_program(e,p).map_err(|err| verification_pending(format!("{}\n{}",err,system::compact_output(&result.output))))?;
    Ok(format!("Установка подтверждена.{}{}",if restart{" Требуется перезагрузка Windows.\n"}else{"\n"},system::compact_output(&result.output)))
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
        Action::Bootstrap => {
            let needed=run.tasks.iter().any(|t| matches!(&t.action,Action::Program(key) if c.programs.iter().any(|p| &p.key==key && ["winget","msstore"].contains(&p.source.as_str()))));
            let (ready,message)=e.bootstrap.prepare(needed,run.plan.readiness["winget_consent"]==true);
            if let Some(r)=e.current.lock().unwrap().as_mut() {r.plan.readiness["winget_ready"]=serde_json::json!(ready);}
            Ok(message)
        }
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
            e, t, c,
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
                let decisions=displays.iter().map(system::refresh_decision).collect::<Result<Vec<_>>>()?;
                if decisions.iter().all(|d|matches!(d,system::RefreshDecision::Skip(_))) {
                    let mut messages=decisions.iter().map(|d|d.message()).collect::<Vec<_>>();
                    messages.dedup();
                    return Ok(messages.join("; "));
                }
                if rb.displays.is_empty() {
                    rb.displays = displays.clone();
                    rb_save(&e.root, &run.id, rb)?;
                }
                for (d,decision) in displays.iter().zip(decisions) {
                    if let system::RefreshDecision::Apply(hz)=decision { system::set_display(d,hz)?; }
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
        Action::Final => check_final_programs(e,c,&run,system::installed),
    }
}
fn check_final_programs(e:&Engine,c:&Config,run:&Run,mut inspect:impl FnMut(&model::Program)->Result<bool>)->Result<String> {
            let mut issues=Vec::new();
            let mut errors=Vec::new();
            for task in &run.tasks {
                if task.status=="waiting_winget" {continue;}
                if let Action::Program(key)=&task.action {
                    let program=c.programs.iter().find(|p|&p.key==key).context("Программа отсутствует в конфиге")?;
                    if program.source=="git" {continue;}
                    match inspect(program) {
                        Ok(true) if task.status=="failed" && !verification_only(task) =>
                            issues.push(format!("{}: установщик завершился с ошибкой; обнаружение приложения само по себе не подтверждает выполнение задачи",program.name)),
                        Ok(true) => {
                            if verification_only(task) && !["succeeded","skipped"].contains(&task.status.as_str()) {
                                if let Some(r)=e.current.lock().unwrap().as_mut() {
                                    r.tasks[task.id].status="succeeded".into();
                                    r.tasks[task.id].detail="Установка подтверждена финальной проверкой; повторный установщик не запускался".into();
                                }
                            }
                        }
                        check => {
                            let reason=match check {Err(err)=>{errors.push(format!("{}: проверка недоступна: {err}",program.name));format!("проверка недоступна: {err}")},_=>"установка пока не подтверждена".into()};
                            issues.push(format!("{}: {}",program.name,reason));
                            if ["succeeded","skipped","needs_verification"].contains(&task.status.as_str()) || verification_only(task) {
                                if let Some(r)=e.current.lock().unwrap().as_mut() {
                                    r.tasks[task.id].status="needs_verification".into();
                                    r.tasks[task.id].verification_only=true;
                                    r.tasks[task.id].detail=format!("{reason}. Продолжение повторит проверку без установки.");
                                }
                            }
                        }
                    }
                }
            }
            final_check_summary(&issues,&errors)
        }
fn final_check_summary(manual:&[String],errors:&[String])->Result<String> {
    ensure!(errors.is_empty(),"Не удалось выполнить финальную проверку:\n{}",errors.join("\n"));
    let mut message="Проверка выбранных программ завершена. Драйверы проверяйте для вашей модели компьютера на сайте производителя.".to_string();
    if !manual.is_empty() {
        message.push_str(&format!("\nПредупреждение. Требуют ручной установки: {}\nПроверьте сведения отдельных задач: если приложение уже установлено, подтвердите его работоспособность вручную. Ошибки установщиков сохранены в их задачах.",manual.join("; ")));
    }
    Ok(message)
}
pub fn start(
    e: Arc<Engine>,
    c: Config,
    mut p: Plan,
    removal_confirmed: bool,
    password: String,
    resume: Option<String>,
    force_vencord: bool,
    no_point_ok: bool,
    winget_consent: bool,
) -> Result<String> {
    p.readiness["winget_consent"]=serde_json::json!(winget_consent);
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
            old.plan.readiness["winget_consent"]=serde_json::json!(winget_consent);
            if !old.tasks.iter().any(|t|matches!(t.action,Action::Bootstrap)) {
                if let Some(t)=p.tasks.iter().find(|t|matches!(t.action,Action::Bootstrap)) {old.tasks.insert(0,t.clone());}
                for (id,t) in old.tasks.iter_mut().enumerate() {t.id=id;}
            }
            for (index,t) in old.tasks.iter_mut().enumerate() {
                t.id=index;
                t.verification_only=verification_only(t);
                if matches!(t.action,Action::Final) {t.status="pending".into();}
                if matches!(t.action,Action::Bootstrap) {t.status="pending".into();}
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
            if e.state().unwrap().plan.readiness["winget_ready"]==false && matches!(&t.action,Action::Program(key) if c.programs.iter().any(|p| &p.key==key && ["winget","msstore"].contains(&p.source.as_str()))) {
                if let Some(r)=e.current.lock().unwrap().as_mut() {r.tasks[i].status="waiting_winget".into();r.tasks[i].detail="Ожидает winget; задача пропущена без запуска установщика".into();}
                let _=e.save();continue;
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
                    e.note("Автоматический повтор не выполняется: сначала нужна проверка причины или результата", true);
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
                    if s.starts_with("Пропущено:") || s.starts_with("Уже установлена максимальная частота ") {
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
                Err(err) if err.downcast_ref::<VerificationPending>().is_some() => ("needs_verification",err.to_string()),
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
                        "needs_verification" => "нужна проверка результата; установщик повторно не запускался",
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

#[cfg(test)]
mod reliability_tests {
    use super::*;
    fn task()->Task {
        serde_json::from_value(serde_json::json!({"id":0,"name":"Discord","risk":"Осторожно","reversible":"","status":"failed","detail":"","action":{"kind":"Program","value":"discord"}})).unwrap()
    }
    #[test]
    fn delayed_registration_retries_reading_until_confirmed() {
        let mut calls=0;let mut waits=0;
        poll_verification(||{calls+=1;Ok(calls==3)},||waits+=1,||false,6).unwrap();
        assert_eq!(calls,3);assert_eq!(waits,2);
    }
    #[test]
    fn missing_or_unreadable_installation_stays_unconfirmed_not_transient() {
        for unreadable in [false,true] {
            let mut calls=0;
            let err=poll_verification(||{calls+=1;if unreadable {anyhow::bail!("источник недоступен")};Ok(false)},||{},||false,3).unwrap_err();
            assert_eq!(calls,3);assert!(err.downcast_ref::<VerificationPending>().is_some());assert!(!is_transient(&err));
            if unreadable {assert!(err.to_string().contains("источник недоступен"));}
        }
    }
    #[test]
    fn cancellation_does_not_start_another_probe() {
        let err=poll_verification(||panic!("must not probe"),||panic!("must not wait"),||true,6).unwrap_err();
        assert!(err.downcast_ref::<VerificationPending>().is_some());
    }
    #[test]
    fn unknown_failed_installer_is_not_retried_as_network_error() {
        let p=model::defaults().programs.into_iter().find(|p|p.key=="nvidia").unwrap();
        let result=system::CommandResult{success:false,code:Some(0xE6000000u32 as i32),output:"Installer failed with exit code: 3858759680".into()};
        let err=installer_failure(&p,&result);
        assert!(!is_transient(&err));assert!(err.to_string().contains("0xE6000000"));
        let busy=system::CommandResult{success:false,code:Some(1618),output:"Another installation is in progress".into()};
        assert!(is_transient(&installer_failure(&p,&busy)));
        let network=system::CommandResult{success:false,code:Some(1),output:"failed to connect".into()};
        assert!(is_transient(&installer_failure(&p,&network)));
    }
    #[test]
    fn old_successful_install_reports_migrate_to_verification_only() {
        let mut t=task();assert!(!verification_only(&t));
        t.detail="Код успеха=true; постпроверка не нашла программу".into();assert!(verification_only(&t));
        t.detail="Сначала установите Discord".into();assert!(!verification_only(&t));
        t.verification_only=true;assert!(verification_only(&t));
    }
    #[test]
    fn started_installation_marker_survives_saving_and_reload() {
        let dir=tempfile::tempdir().unwrap();let e=Engine::new(dir.path().into());let t=task();
        let run=Run{id:"fixture".into(),plan:Plan{profile:"fixture".into(),fingerprint:"".into(),tasks:vec![t.clone()],warnings:vec![],readiness:serde_json::json!({}),displays:vec![]},active:true,paused:false,tasks:vec![t],log:vec![],technical:vec![],finished:false};
        *e.current.lock().unwrap()=Some(run);
        remember_verification(&e,0,true).unwrap();
        let restored:Run=serde_json::from_slice(&fs::read(dir.path().join("runs/fixture.json")).unwrap()).unwrap();
        assert!(verification_only(&restored.tasks[0]));
        remember_verification(&e,0,false).unwrap();
        let restored:Run=serde_json::from_slice(&fs::read(dir.path().join("runs/fixture.json")).unwrap()).unwrap();
        assert!(!verification_only(&restored.tasks[0]));
    }

    #[test]
    fn final_check_confirms_late_registration_but_keeps_real_installer_failures() {
        let dir=tempfile::tempdir().unwrap();let e=Engine::new(dir.path().into());let c=model::defaults();
        let mut t=task();t.status="needs_verification".into();t.verification_only=true;
        let mut run=Run{id:"fixture".into(),plan:Plan{profile:"fixture".into(),fingerprint:"".into(),tasks:vec![],warnings:vec![],readiness:serde_json::json!({}),displays:vec![]},active:true,paused:false,tasks:vec![t],log:vec![],technical:vec![],finished:false};
        *e.current.lock().unwrap()=Some(run.clone());
        check_final_programs(&e,&c,&run,|_|Ok(true)).unwrap();
        assert_eq!(e.state().unwrap().tasks[0].status,"succeeded");
        run.tasks[0].status="failed".into();run.tasks[0].verification_only=false;
        *e.current.lock().unwrap()=Some(run.clone());
        assert!(check_final_programs(&e,&c,&run,|_|Ok(true)).unwrap().contains("Требуют ручной установки:"));
        assert_eq!(e.state().unwrap().tasks[0].status,"failed");
    }
    #[test]
    fn final_summary_succeeds_with_manual_items_and_fails_only_on_probe_errors() {
        assert!(!final_check_summary(&[],&[]).unwrap().contains("Предупреждение"));
        let manual=vec!["NVIDIA App".into(),"Armoury Crate".into()];
        let summary=final_check_summary(&manual,&[]).unwrap();
        assert!(summary.contains("Предупреждение. Требуют ручной установки: NVIDIA App; Armoury Crate"));
        assert!(final_check_summary(&manual,&["Не удалось прочитать состояние системы".into()]).is_err());
    }
    #[test]
    fn final_read_error_is_not_reported_as_missing_and_retains_verification_only() {
        let dir=tempfile::tempdir().unwrap();let e=Engine::new(dir.path().into());let c=model::defaults();
        let mut t=task();t.status="succeeded".into();
        let run=Run{id:"fixture".into(),plan:Plan{profile:"fixture".into(),fingerprint:"".into(),tasks:vec![],warnings:vec![],readiness:serde_json::json!({}),displays:vec![]},active:true,paused:false,tasks:vec![t],log:vec![],technical:vec![],finished:false};
        *e.current.lock().unwrap()=Some(run.clone());
        let error=check_final_programs(&e,&c,&run,|_|anyhow::bail!("источник недоступен")).unwrap_err().to_string();
        assert!(error.contains("источник недоступен"));
        let saved=e.state().unwrap();
        assert_eq!(saved.tasks[0].status,"needs_verification");
        assert!(verification_only(&saved.tasks[0]));
    }
}
