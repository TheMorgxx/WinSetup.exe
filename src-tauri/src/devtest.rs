//! Безопасная диагностика. Никогда не вызывает engine::start/execute/rollback.
use crate::{engine, model, storage, system, vault};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs, io::{Read, Write}, path::{Path, PathBuf}, process::{Command, Stdio}, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};
use std::os::windows::process::CommandExt;

#[derive(Clone, Serialize, Deserialize)]
pub struct Test { pub id: String, pub group: u8, pub name: String, pub timeout_s: u64 }
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum Status { PASS, FAIL, WARN, SKIP }
#[derive(Clone, Serialize, Deserialize)]
pub struct TestResult { pub id: String, pub group: u8, pub name: String, pub status: Status, pub elapsed_ms: u64, pub summary: String, pub technical: String }
#[derive(Clone, Serialize, Deserialize)]
pub struct Log { pub time: String, pub level: Status, pub message: String }
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct State { pub active: bool, pub stopping: bool, pub current: Option<String>, pub id: String, pub header: Value, pub tests: Vec<Test>, pub results: Vec<TestResult>, pub log: Vec<Log>, pub report_path: String, pub error: String }
#[derive(Default)]
pub struct Runner { state: Mutex<State>, stop: AtomicBool, reserved: AtomicBool }
#[derive(Serialize, Deserialize)]
struct Outcome { status: Status, summary: String, technical: String }
fn outcome(status: Status, summary: impl Into<String>, technical: impl Into<String>) -> Outcome { Outcome { status, summary: summary.into(), technical: technical.into() } }
fn pass(s: impl Into<String>) -> Outcome { outcome(Status::PASS, s, "") }
fn pretty(v: &impl Serialize) -> String { serde_json::to_string_pretty(v).unwrap_or_default() }
fn clean(value: &mut Value) {
    match value {
        Value::String(s) => *s = storage::redact(s),
        Value::Array(a) => a.iter_mut().for_each(clean),
        Value::Object(o) => o.values_mut().for_each(clean),
        _ => (),
    }
}
fn sanitized<T: Serialize + for<'de> Deserialize<'de>>(v: T) -> T {
    let mut value = serde_json::to_value(v).expect("Сериализация диагностики");
    clean(&mut value);
    serde_json::from_value(value).expect("Структура диагностики")
}
pub fn list(root: &Path) -> Vec<Test> {
    let mut tests = Vec::new();
    let mut add = |group, id: &str, name: &str| tests.push(Test { id: id.into(), group, name: name.into(), timeout_s: if group == 4 {45} else {60} });
    for (group, id, name) in [
        (1,"environment","Окружение и свободное место"),
        (1,"bootstrap","Подготовка среды"),
        (2,"config","Загрузка, валидация и обратное сохранение конфигурации"),
        (2,"legacy","Совместимость старых конфигураций и тип dev_mode"),
        (2,"secrets","Секреты и маскирование"),
        (3,"catalog","22 пакета по умолчанию и защита от удаления"),
        (5,"displays","Текущий и максимальный режим дисплеев"),
        (5,"appx","Установленные пакеты Appx"),
        (5,"startup","Записи автозапуска (только чтение)"),
        (5,"tweaks","Текущие значения каталога твиков"),
        (5,"restore","Защита системы и прогноз точки восстановления"),
        (6,"vault","Архив Vault: пароль, повреждение и восстановление"),
        (7,"files","Повторное создание дерева папок"),
        (9,"wmi","Разбор времени WMI: наблюдения без assert"),
    ] { add(group,id,name); }
    if let Ok(c) = storage::load(root) {
        for (i,p) in c.profiles.iter().enumerate() { add(3,&format!("plan:{i}"),&format!("План: {}",p.name)); }
        if let Some(p) = c.profiles.iter().find(|p| p.name == c.application.selected_profile) {
            for x in c.programs.iter().filter(|x| p.programs.contains(&x.key)) { add(4,&format!("program:{}",x.key),&format!("Доступность: {}",x.name)); }
            for x in c.repositories.iter().filter(|x| p.repositories.contains(&x.key)) { add(8,&format!("repo:{}",x.key),&format!("Репозиторий: {}",x.key)); }
        }
    }
    tests.sort_by_key(|t| t.group);
    tests
}
impl Runner {
    pub fn state(&self) -> State { self.state.lock().unwrap_or_else(|e| e.into_inner()).clone() }
    fn log(&self, level: Status, message: impl Into<String>) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).log.push(Log { time: chrono::Local::now().to_rfc3339(), level, message: storage::redact(&message.into()) });
    }
    pub fn stop(&self) { self.stop.store(true,Ordering::SeqCst); self.state.lock().unwrap().stopping = true; }
    pub fn start(self: &Arc<Self>, engine: Arc<engine::Engine>, ids: Vec<String>) -> Result<()> {
        ensure!(!ids.is_empty(),"Выберите хотя бы один тест");
        let catalog = list(&engine.root);
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        ensure!(unique.len() == ids.len() && ids.iter().all(|id| catalog.iter().any(|t| &t.id == id)), "Список тестов изменился или содержит неизвестные/повторные ID");
        ensure!(!self.reserved.swap(true,Ordering::SeqCst),"Диагностика уже выполняется");
        if engine.busy.swap(true,Ordering::SeqCst) { self.reserved.store(false,Ordering::SeqCst); bail!("Дождитесь завершения текущей операции"); }
        self.stop.store(false,Ordering::SeqCst);
        let tests: Vec<_> = catalog.into_iter().filter(|t| ids.contains(&t.id)).collect();
        *self.state.lock().unwrap() = State { active: true, tests: tests.clone(), id: report_id(&engine.root), ..State::default() };
        let this = self.clone();
        let e = engine.clone();
        let spawned = std::thread::Builder::new().name("winsetup-devtest".into()).spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| this.run(&e.root, tests)));
            if result.is_err() { this.log(Status::FAIL,"Внутренняя ошибка потока диагностики"); this.state.lock().unwrap().error = "Внутренняя ошибка потока".into(); }
            { let mut state = this.state.lock().unwrap(); state.active = false; state.current = None; }
            if let Err(err) = this.save(&e.root) { this.log(Status::FAIL,format!("Не удалось сохранить отчёт: {err}")); this.state.lock().unwrap().error = storage::redact(&err.to_string()); }
            e.busy.store(false,Ordering::SeqCst);
            this.reserved.store(false,Ordering::SeqCst);
        });
        if let Err(err) = spawned { engine.busy.store(false,Ordering::SeqCst); self.reserved.store(false,Ordering::SeqCst); self.state.lock().unwrap().active = false; return Err(err.into()); }
        Ok(())
    }
    fn run(&self, root: &Path, tests: Vec<Test>) {
        self.log(Status::PASS,"Диагностика начата; изменения Windows запрещены");
        self.state.lock().unwrap().header = sanitized(header(root));
        for test in tests {
            if self.stop.load(Ordering::SeqCst) {
                self.finish(&test, Duration::ZERO, outcome(Status::SKIP,"Остановлено до начала теста",""));
                continue;
            }
            self.state.lock().unwrap().current = Some(test.id.clone());
            self.log(Status::PASS,format!("Начат тест: {}",test.name));
            let began = Instant::now();
            let result = if [6,7].contains(&test.group) { isolated(&test) } else { timed_readonly(root, &test, self) };
            let result = result.unwrap_or_else(|e| outcome(Status::FAIL,"Проверка не пройдена",format!("{e:#}")));
            self.finish(&test,began.elapsed(),result);
        }
        self.log(Status::PASS,"Диагностика завершена");
    }
    fn finish(&self, test: &Test, elapsed: Duration, result: Outcome) {
        self.log(result.status,format!("{}: {}",test.name,result.summary));
        self.state.lock().unwrap().results.push(sanitized(TestResult { id: test.id.clone(), group: test.group, name: test.name.clone(), status: result.status, elapsed_ms: elapsed.as_millis() as u64, summary: result.summary, technical: result.technical }));
    }
    pub fn save(&self, root: &Path) -> Result<String> {
        let mut state = self.state();
        ensure!(!state.id.is_empty(),"Сначала запустите тесты");
        let logs = root.join("logs");
        model::no_links(&logs)?;
        fs::create_dir_all(&logs)?;
        let md = logs.join(format!("{}.md",state.id));
        state.report_path = md.display().to_string();
        storage::atomic(&logs.join(format!("{}.json",state.id)),&serde_json::to_vec_pretty(&sanitized(state.clone()))?,false)?;
        storage::atomic(&md,markdown(&state).as_bytes(),false)?;
        self.state.lock().unwrap().report_path = state.report_path;
        retain_reports(&logs)?;
        Ok(md.display().to_string())
    }
}
fn report_id(root: &Path) -> String {
    let mut now = chrono::Local::now();
    loop {
        let id = now.format("devtest-%Y%m%d-%H%M%S").to_string();
        if !root.join("logs").join(format!("{id}.json")).exists() && !root.join("logs").join(format!("{id}.md")).exists() { return id; }
        now += chrono::Duration::seconds(1);
    }
}
fn retain_reports(logs: &Path) -> Result<()> {
    let re = regex::Regex::new(r"^devtest-\d{8}-\d{6}\.(md|json)$")?;
    let mut ids = std::collections::BTreeSet::new();
    for entry in fs::read_dir(logs)? { let entry=entry?; let name=entry.file_name().to_string_lossy().into_owned(); if entry.file_type()?.is_file() && re.is_match(&name) { ids.insert(name.rsplit_once('.').unwrap().0.to_owned()); } }
    let count=ids.len().saturating_sub(5);
    for id in ids.into_iter().take(count) { for ext in ["md","json"] { let path=logs.join(format!("{id}.{ext}")); model::no_links(&path)?; if path.is_file() { fs::remove_file(path)?; } } }
    Ok(())
}
pub fn markdown(state: &State) -> String {
    let state = sanitized(state.clone());
    let mut s=format!("# Отчёт WinSetup: {}\n\n## Окружение\n\n```json\n{}\n```\n\n",state.id,pretty(&state.header));
    for status in [Status::PASS,Status::FAIL,Status::WARN,Status::SKIP] { s.push_str(&format!("{status:?}: {}  \n",state.results.iter().filter(|r|r.status==status).count())); }
    for r in &state.results { s.push_str(&format!("\n## Группа {} — {}\n\n{:?}, {} мс. {}\n\n```text\n{}\n```\n",r.group,r.name,r.status,r.elapsed_ms,r.summary,r.technical)); }
    s.push_str("\n## Живой журнал\n\n");
    for l in state.log { s.push_str(&format!("{} [{:?}] {}\n",l.time,l.level,l.message)); }
    if !state.error.is_empty() { s.push_str(&format!("\nОшибка отчёта: {}\n",state.error)); }
    storage::redact(&s)
}
pub fn hide_user(s: &str) -> String { hide_user_impl(s) }
fn hide_user_impl(s: &str) -> String {
    regex::Regex::new(r#"(?i)C:[\\/]+Users[\\/]+[^\\/\r\n\"<>]+"#).unwrap().replace_all(s,"%USERPROFILE%").to_string()
}
// Процесс хранится в RAII-обёртке: ошибка чтения/ожидания также убивает и дожидается его.
#[repr(C)]
#[derive(Default)]
struct BasicLimits { process_time: i64, job_time: i64, flags: u32, min_working_set: usize, max_working_set: usize, active_processes: u32, affinity: usize, priority: u32, scheduling: u32 }
#[repr(C)]
#[derive(Default)]
struct ExtendedLimits { basic: BasicLimits, io: [u64;6], process_memory: usize, job_memory: usize, peak_process: usize, peak_job: usize }
#[link(name="kernel32")]
extern "system" {
    fn CreateJobObjectW(attributes: *const std::ffi::c_void, name: *const u16) -> *mut std::ffi::c_void;
    fn SetInformationJobObject(job: *mut std::ffi::c_void, class: i32, info: *const std::ffi::c_void, size: u32) -> i32;
    fn AssignProcessToJobObject(job: *mut std::ffi::c_void, process: *mut std::ffi::c_void) -> i32;
    fn TerminateJobObject(job: *mut std::ffi::c_void, code: u32) -> i32;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
}
struct Job(*mut std::ffi::c_void);
impl Job {
    fn new() -> Result<Self> {
        let job=Self(unsafe {CreateJobObjectW(std::ptr::null(),std::ptr::null())});
        ensure!(!job.0.is_null(),"Не удалось создать Job Object: {}",std::io::Error::last_os_error());
        let mut limits=ExtendedLimits::default(); limits.basic.flags=0x2000; // KILL_ON_JOB_CLOSE
        ensure!(unsafe {SetInformationJobObject(job.0,9,&limits as *const _ as *const _,std::mem::size_of::<ExtendedLimits>() as u32)}!=0,"Не удалось настроить Job Object: {}",std::io::Error::last_os_error());
        Ok(job)
    }
    fn attach(&self,child: &std::process::Child) -> Result<()> {
        use std::os::windows::io::AsRawHandle;
        ensure!(unsafe {AssignProcessToJobObject(self.0,child.as_raw_handle())}!=0,"Не удалось изолировать процесс: {}",std::io::Error::last_os_error()); Ok(())
    }
    fn terminate(&self) { unsafe {TerminateJobObject(self.0,1);} }
}
impl Drop for Job {fn drop(&mut self) {if !self.0.is_null() {unsafe {CloseHandle(self.0);}}}}
struct Child(std::process::Child, Job);
impl Drop for Child { fn drop(&mut self) { self.1.terminate(); let _=self.0.kill(); let _=self.0.wait(); } }
fn command(mut command: Command, timeout: Duration) -> Result<(bool,String)> {
    let job=Job::new()?;
    let mut child=Child(command.creation_flags(0x08000000).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?,job);
    child.1.attach(&child.0)?;
    fn drain(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<String> { std::thread::spawn(move || { let mut out=Vec::new(); let mut b=[0;8192]; loop { let n=pipe.read(&mut b).unwrap_or(0); if n==0 {break;} let remaining=(4*1024*1024usize).saturating_sub(out.len()); out.extend_from_slice(&b[..n.min(remaining)]); } String::from_utf8_lossy(&out).into_owned() }) }
    let out=drain(child.0.stdout.take().unwrap()); let err=drain(child.0.stderr.take().unwrap()); let start=Instant::now();
    let status=loop { if let Some(s)=child.0.try_wait()? {break Some(s);} if start.elapsed()>=timeout { child.1.terminate(); let _=child.0.kill(); child.0.wait()?; break None; } std::thread::sleep(Duration::from_millis(50)); };
    child.1.terminate();
    let output=format!("{}\n{}",out.join().unwrap_or_default(),err.join().unwrap_or_default());
    match status { Some(s)=>Ok((s.success(),output)), None=>bail!("Тайм-аут {} с\n{}",timeout.as_secs(),output) }
}
fn ps(script: &str, timeout: Duration) -> Result<Value> {
    use base64::Engine;
    let script=format!("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new();{script}");
    let encoded=base64::engine::general_purpose::STANDARD.encode(script.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
    let mut cmd=Command::new(PathBuf::from(std::env::var("WINDIR")?).join("System32/WindowsPowerShell/v1.0/powershell.exe"));
    cmd.args(["-NoProfile","-NonInteractive","-EncodedCommand",&encoded]);
    let (ok,out)=command(cmd,timeout)?; ensure!(ok,"{out}"); Ok(serde_json::from_str(out.trim())?)
}
fn tool_version(name: &str) -> String { let mut cmd=Command::new(system::tool(name)); cmd.arg("--version"); match command(cmd,Duration::from_secs(15)) { Ok((true,s))=>s.trim().into(), Ok((false,s))=>format!("Недоступно: {s}"),Err(e)=>format!("Недоступно: {e}") } }
fn header(root: &Path) -> Value {
    let windows=ps(r#"$os=Get-CimInstance Win32_OperatingSystem;@{windows=$os.Caption;version=$os.Version;build=$os.BuildNumber;admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}|ConvertTo-Json"#,Duration::from_secs(15)).unwrap_or_else(|e|json!({"error":e.to_string()}));
    json!({"версия_программы":env!("CARGO_PKG_VERSION"),"Windows":windows,"winget":tool_version("winget"),"git":tool_version("git"),"отпечаток_конфига":fs::read(root.join("winsetup.toml")).map(|b|storage::hash(&b)).unwrap_or_else(|e|e.to_string()),"дата":chrono::Local::now().to_rfc3339()})
}
fn timed_readonly(root: &Path, test: &Test, runner: &Runner) -> Result<Outcome> {
    let root=root.to_owned(); let id=test.id.clone();
    let (tx,rx)=std::sync::mpsc::sync_channel(1);
    let worker=std::thread::spawn(move || { let r=std::panic::catch_unwind(|| check(&root,&id)); let r=r.unwrap_or_else(|_|Err(anyhow::anyhow!("Паника теста"))); let _=tx.send(r); });
    match rx.recv_timeout(Duration::from_secs(test.timeout_s)) {
        Ok(r)=> { let _=worker.join(); r },
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)=> {
            runner.stop();
            runner.log(Status::FAIL,"Тайм-аут: очередь остановлена; ожидание завершения функции чтения для исключения параллельных тестов");
            // Rust-потоки нельзя безопасно принудительно завершать. Существующий plan()
            // не меняем: удерживаем блокировку запуска до окончания его чтения.
            let _=worker.join();
            bail!("Тайм-аут {} с; следующие тесты пропущены",test.timeout_s)
        },
        Err(e)=> { let _=worker.join(); Err(e.into()) }
    }
}
fn canonical(path: &Path) -> Result<PathBuf> {
    let full=path.canonicalize()?;
    let text=full.to_str().context("Путь должен быть Unicode")?;
    // Конфиг Vault принимает обычные абсолютные пути дисков, без префикса \\?\.
    let text=text.strip_prefix(r"\\?\").unwrap_or(text);
    ensure!(text.as_bytes().get(1)==Some(&b':'),"Тестовый TEMP должен находиться на локальном диске");
    Ok(PathBuf::from(text))
}
struct Temp { dir: Option<tempfile::TempDir>, path: PathBuf }
impl Temp {
    fn new() -> Result<Self> {
        let base=std::env::temp_dir(); model::no_links(&base)?;
        let dir=tempfile::Builder::new().prefix("WinSetupDevTest-").tempdir_in(&base)?;
        let path=canonical(dir.path())?;
        Ok(Self {dir:Some(dir),path})
    }
    fn cleanup(&mut self) -> Result<()> {
        if let Some(dir)=self.dir.take() { let _=dir.keep(); }
        ensure!(self.path.file_name().unwrap_or_default().to_string_lossy().starts_with("WinSetupDevTest-"),"Небезопасный путь очистки");
        model::no_links(&self.path)?;
        for attempt in 0..10 { match fs::remove_dir_all(&self.path) { Ok(())=>return Ok(()),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(()),Err(e) if attempt==9=>return Err(e.into()),Err(_)=>std::thread::sleep(Duration::from_millis(100)) } }
        Ok(())
    }
}
impl Drop for Temp { fn drop(&mut self) { let _=self.cleanup(); } }
fn isolated(test: &Test) -> Result<Outcome> {
    ensure!(["vault","files"].contains(&test.id.as_str()),"Недопустимый ID служебного теста");
    let mut temp=Temp::new()?;
    let result=(|| {
        let mut cmd=Command::new(std::env::current_exe()?);
        cmd.args(["--devtest-worker",test.id.as_str()]).current_dir(&temp.path)
            .env("TEMP",&temp.path).env("TMP",&temp.path)
            .env("WINSETUP_DEVTEST_BASE",temp.path.parent().context("Нет родительской папки")?);
        let (ok,out)=command(cmd,Duration::from_secs(test.timeout_s))?;
        ensure!(ok,"Служебная проверка завершилась с ошибкой: {out}");
        Ok(serde_json::from_str::<Outcome>(out.trim())?)
    })();
    temp.cleanup().context("Не удалось удалить временную папку диагностики")?;
    result
}
/// Вызывается до Tauri/setup; не читает конфиг, не создаёт логов рядом с exe.
pub fn worker(args: &[String]) -> i32 {
    let result=(|| -> Result<Outcome> {
        ensure!(args.len()==3 && args[1]=="--devtest-worker" && ["vault","files"].contains(&args[2].as_str()),"Неверные аргументы служебного процесса");
        let root=canonical(&std::env::current_dir()?)?;
        model::no_links(&root)?;
        let base=canonical(&PathBuf::from(std::env::var("WINSETUP_DEVTEST_BASE")?))?;
        ensure!(root.parent()==Some(base.as_path()),"Тестовая папка вне временного каталога");
        let name=root.file_name().context("Нет имени папки")?.to_string_lossy();
        ensure!(regex::Regex::new(r"^WinSetupDevTest-[A-Za-z0-9]+$")?.is_match(&name),"Неверное имя тестовой папки");
        for key in ["TEMP","TMP"] { ensure!(canonical(&PathBuf::from(std::env::var(key)?))?==root,"Неверный {key}"); }
        ensure!(canonical(&std::env::temp_dir())?==root,"Внутренние временные файлы должны оставаться внутри тестовой папки");
        if args[2]=="vault" { vault_check(&root) } else { files_check(&root) }
    })();
    let result=sanitized(result.unwrap_or_else(|e|outcome(Status::FAIL,"Служебная проверка не пройдена",format!("{e:#}"))));
    match serde_json::to_vec(&result).and_then(|v|std::io::stdout().write_all(&v).map_err(serde_json::Error::io)) { Ok(())=>0,Err(_)=>1 }
}
fn within(root: &Path, relative: &str) -> Result<PathBuf> {
    let path=root.join(relative);
    ensure!(path.starts_with(root) && !Path::new(relative).is_absolute() && !Path::new(relative).components().any(|p| matches!(p,std::path::Component::ParentDir)),"Выход за тестовую папку");
    model::no_links(&path)?;
    Ok(path)
}
fn vault_check(root: &Path) -> Result<Outcome> {
    use rand::RngCore;
    let source=within(root,"source")?; fs::create_dir(&source)?;
    let mut expected=Vec::new();
    for i in 0..5 { let mut b=vec![0u8;3*1024*1024+i*17]; rand::rngs::OsRng.fill_bytes(&mut b); let name=format!("data-{i}.bin"); fs::write(source.join(&name),&b)?; expected.push((name,storage::hash(&b))); }
    let mut secret=[0u8;32]; rand::rngs::OsRng.fill_bytes(&mut secret);
    let password=zeroize::Zeroizing::new(storage::hash(&secret));
    use zeroize::Zeroize; secret.zeroize();
    let mut config=model::defaults(); config.backup.firefox=false;
    config.backup.sources=vec![model::BackupSource {key:"sample".into(),path:source.display().to_string()}];
    let archive=within(root,"sample.wsvault")?;
    let created=vault::create(&config,&archive,&password)?;
    let restored=within(root,"restored")?; config.backup.sources[0].path=restored.display().to_string();
    let valid=vault::restore(&config,&archive,&password)?;
    for (name,hash) in &expected { ensure!(&storage::file_hash(&restored.join(name))?==hash,"Не совпал SHA-256 файла {name}"); }
    let wrong=within(root,"wrong-password-target")?; config.backup.sources[0].path=wrong.display().to_string();
    let began=Instant::now();
    let wrong_error=vault::restore(&config,&archive,"incorrect-test-password").err().context("Неверный пароль был принят")?;
    let wrong_ms=began.elapsed().as_millis();
    ensure!(!wrong.exists(),"Неверный пароль привёл к записи назначения");
    let corrupt=within(root,"corrupt.wsvault")?;
    let mut bytes=fs::read(&archive)?; let last=bytes.len()-1; bytes[last]^=1; fs::write(&corrupt,bytes)?;
    let bad=within(root,"corrupt-target")?; config.backup.sources[0].path=bad.display().to_string();
    let corrupt_error=vault::restore(&config,&corrupt,&password).err().context("Повреждение архива не обнаружено")?;
    ensure!(!bad.exists(),"Повреждённый архив привёл к записи назначения");
    let technical=format!("{created}\n{valid}\n5 файлов около 3 МиБ: SHA-256 совпали.\nНеверный пароль: ровно один вызов, {wrong_ms} мс, {wrong_error}\nПовреждение одного байта: {corrupt_error}\n{}",pretty(&expected));
    Ok(outcome(if wrong_ms>15000 {Status::WARN} else {Status::PASS},if wrong_ms>15000 {"Проверки пройдены, ошибка пароля заняла более 15 с"} else {"Шифрование, проверка, восстановление и защита от повреждений пройдены"},technical))
}
fn files_check(root: &Path) -> Result<Outcome> {
    let dirs=["tree","tree/a","tree/a/b","tree/документы"];
    for dir in dirs { fs::create_dir_all(within(root,dir)?)?; }
    let file=within(root,"tree/a/существующий.txt")?;
    fs::write(&file,"Существующие данные остаются без изменений")?;
    let hash=storage::file_hash(&file)?; let modified=fs::metadata(&file)?.modified()?;
    for dir in dirs { fs::create_dir_all(within(root,dir)?)?; }
    ensure!(storage::file_hash(&file)?==hash && fs::metadata(&file)?.modified()?==modified,"Существующий файл изменён");
    ensure!(fs::create_dir_all(&file).is_err(),"Файл ошибочно принят за папку");
    ensure!(storage::file_hash(&file)?==hash,"Ошибка создания повредила файл");
    Ok(pass("Дерево создано дважды; содержимое и время изменения файла сохранены"))
}
pub fn selftest() -> i32 {
    let result=(|| -> Result<i32> {
        let root=storage::root()?;
        let engine=Arc::new(engine::Engine::new(root.clone()));
        let runner=Arc::new(Runner::default());
        runner.start(engine,list(&root).into_iter().map(|t|t.id).collect())?;
        while runner.reserved.load(Ordering::SeqCst) { std::thread::sleep(Duration::from_millis(100)); }
        let s=runner.state();
        Ok(if !s.error.is_empty() || s.results.iter().any(|r|r.status==Status::FAIL) {1} else {0})
    })();
    result.unwrap_or(1)
}
pub fn open_logs(root: &Path) -> Result<()> {
    let logs=root.join("logs"); model::no_links(&logs)?; fs::create_dir_all(&logs)?;
    use std::os::windows::ffi::OsStrExt;
    let path=logs.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<_>>();
    let verb="open".encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    #[link(name="shell32")] extern "system" { fn ShellExecuteW(hwnd:*mut std::ffi::c_void,op:*const u16,file:*const u16,params:*const u16,dir:*const u16,show:i32)->isize; }
    ensure!(unsafe {ShellExecuteW(std::ptr::null_mut(),verb.as_ptr(),path.as_ptr(),std::ptr::null(),std::ptr::null(),1)}>32,"Не удалось открыть папку логов"); Ok(())
}
fn check(root: &Path, id: &str) -> Result<Outcome> {
    match id {
        "environment" => environment(root),
        "bootstrap" => {
            let checks=crate::bootstrap::readonly(root);
            let ok=checks.iter().all(|c|c.status==crate::bootstrap::Status::Ok);
            Ok(outcome(if ok {Status::PASS}else{Status::WARN},"Прочитан статус конфига и winget; скачивание и починка не выполнялись",pretty(&checks)))
        },
        "config" => {
            let current=storage::load(root)?;
            let mut temp=Temp::new()?;
            let result=(|| -> Result<Outcome> {
                let path=within(&temp.path,"roundtrip.toml")?;
                storage::atomic(&path,model::render(&current)?.as_bytes(),false)?;
                let loaded=model::parse(&fs::read_to_string(&path)?)?;
                ensure!(serde_json::to_value(&loaded)?==serde_json::to_value(&current)?,"Конфиг изменился после сохранения/загрузки");
                Ok(pass("Текущий конфиг валиден; временное сохранение и загрузка равны"))
            })();
            temp.cleanup()?; result
        }
        "legacy" => {
            let c=model::defaults(); let text=model::render(&c)?;
            let mut doc:toml::Value=toml::from_str(&text)?;
            let app=doc.get_mut("application").and_then(toml::Value::as_table_mut).context("Нет application")?;
            let keys:Vec<_>=app.keys().filter(|k|k.starts_with("ui_") || k.as_str()=="dev_mode").cloned().collect();
            for key in keys {app.remove(&key);}
            let old=model::parse(&toml::to_string(&doc)?)?;
            ensure!(!old.application.dev_mode,"Старый конфиг включил dev_mode");
            doc["application"].as_table_mut().context("Нет application")?.insert("dev_mode".into(),toml::Value::String("true".into()));
            ensure!(model::parse(&toml::to_string(&doc)?).is_err(),"Строка принята вместо bool");
            for enabled in [false,true] { doc["application"]["dev_mode"]=toml::Value::Boolean(enabled); ensure!(model::parse(&toml::to_string(&doc)?)?.application.dev_mode==enabled,"bool не сохранён"); }
            Ok(pass("Старые конфиги загружаются; dev_mode=false по умолчанию; неверный тип отклонён"))
        }
        "secrets" => {
            let raw=fs::read_to_string(root.join("winsetup.toml"))?;
            model::parse(&raw)?;
            ensure!(storage::redact(&raw)==raw,"В исходном конфиге найдены значения, похожие на секреты (значения скрыты)");
            for sample in ["ghp_DEVELOPMENTTEST", "token=DEVELOPMENTTEST", "password=DEVELOPMENTTEST", "https://user:DEVELOPMENTTEST@example.org/"] { ensure!(!storage::redact(sample).contains("DEVELOPMENTTEST"),"Маскирование тестового секрета не сработало"); }
            Ok(pass("Текущий конфиг и маскирование проверены; секреты в вывод не включены"))
        }
        "catalog" => {
            let c=storage::load(root)?;
            ensure!(model::REMOVABLE.iter().filter(|p|p.default_remove).count()==22,"В каталоге не 22 default_remove=true");
            let p=c.profiles.iter().find(|p|p.name=="Мой ПК").context("Профиль «Мой ПК» отсутствует")?;
            let actual:std::collections::HashSet<_>=p.appx_removal.iter().map(String::as_str).collect();
            let expected:std::collections::HashSet<_>=model::REMOVABLE.iter().filter(|p|p.default_remove).map(|p|p.name).collect();
            ensure!(p.appx_removal.len()==22 && actual==expected,"«Мой ПК»: список удаления отличается от 22 пакетов default_remove=true");
            for p in &c.profiles {ensure!(p.appx_removal.iter().all(|a|model::removable(a)),"В удалении профиля защищённый пакет");}
            Ok(pass("22 пакета по умолчанию совпадают; запрещённых имён в удалении нет"))
        }
        "displays" => {
            let displays=system::displays();
            Ok(outcome(if displays.is_empty(){Status::WARN}else{Status::PASS},format!("Дисплеев: {}",displays.len()),pretty(&displays)))
        }
        "appx" => {
            let apps=ps("ConvertTo-Json -InputObject @(Get-AppxPackage | Select-Object Name,PackageFullName,IsFramework,NonRemovable,SignatureKind) -Depth 5",Duration::from_secs(55))?;
            Ok(outcome(Status::PASS,"Список Appx прочитан",pretty(&apps)))
        }
        "startup" => Ok(outcome(Status::PASS,"Автозапуск прочитан",pretty(&system::startup()?))),
        "tweaks" => {
            let mut values=Vec::new();
            for key in model::TWEAKS { if *key=="max_refresh" {values.push(json!({"ключ":key,"дисплеи":system::displays()}));} else {for (path,name,_) in system::tweak_values(key,"enabled")? {values.push(json!({"ключ":key,"значение":system::snapshot("HKCU",&path,&name)?}));}} }
            Ok(outcome(Status::PASS,"Прочитаны значения всех твиков каталога",pretty(&values)))
        }
        "restore" => restore_readonly(),
        "wmi" => {
            let mut lines=Vec::new(); let mut discrepancy=false;
            for (s,expected) in [("20261012143000.000000-000",Some(0)),("20261012143000.250000+180",Some(10800)),("20261012143000.000000-300",Some(-18000)),("мусор",None)] {
                let result=system::wmi_parts(s);
                discrepancy |= result.as_ref().map(|(_,o)|o.local_minus_utc())!=expected;
                lines.push(format!("{s}: {:?}; ожидаемое смещение {expected:?}",result));
            }
            Ok(outcome(if discrepancy{Status::WARN}else{Status::PASS},"Наблюдения WMI записаны без assert; известный unit-тест не изменён",lines.join("\n")))
        }
        _ if id.starts_with("plan:") => {
            let c=storage::load(root)?;
            let index:usize=id[5..].parse()?;
            let profile=c.profiles.get(index).context("Профиль больше не существует")?;
            let plan=engine::plan(&c,&profile.name,false)?;
            validate_plan(&plan)?;
            Ok(outcome(Status::PASS,format!("План без выполнения: {} этапов",plan.tasks.len()),pretty(&plan)))
        }
        _ if id.starts_with("program:") || id.starts_with("repo:") => network_check(root,id),
        _ => bail!("Неизвестный безопасный тест"),
    }
}
fn validate_plan(plan: &engine::Plan) -> Result<()> {
    use engine::Action;
    let rank=|a:&Action|match a {Action::Bootstrap|Action::Check=>0,Action::RestorePoint=>1,Action::Folder(_)=>2,Action::Program(_)=>3,Action::Tweak(_,_)=>4,Action::Remove(_)=>5,Action::Startup(_)=>6,Action::Repository(_)=>7,Action::Restore=>8,Action::Final=>9};
    ensure!(matches!(plan.tasks.first().map(|t|&t.action),Some(Action::Check)) && matches!(plan.tasks.last().map(|t|&t.action),Some(Action::Final)),"Нет начального/финального этапа");
    ensure!(plan.tasks.windows(2).all(|w|rank(&w[0].action)<=rank(&w[1].action)),"Нарушен порядок этапов");
    if let Some(v)=plan.tasks.iter().position(|t|matches!(&t.action,Action::Program(k) if k=="vencord")) {
        let d=plan.tasks.iter().position(|t|matches!(&t.action,Action::Program(k) if k=="discord")).context("Vencord запланирован без Discord")?;
        ensure!(v>d,"Vencord должен следовать строго после Discord");
    }
    for task in &plan.tasks { if let Action::Remove(name)=&task.action {
        ensure!(model::removable(name),"План удаляет защищённое имя пакета");
        if let Some(app)=plan.readiness["apps"].as_array().into_iter().flatten().find(|a|a["Name"]==*name) {ensure!(app["IsFramework"]!=true && app["NonRemovable"]!=true && app["SignatureKind"]!=4 && app["SignatureKind"]!="System","План удаляет защищённый установленный пакет");}
    } }
    Ok(())
}
fn connection() -> Result<bool> {
    Ok(ps("[bool](@(Get-NetConnectionProfile -ErrorAction Stop | Where-Object { $_.IPv4Connectivity -eq 'Internet' -or $_.IPv6Connectivity -eq 'Internet' }).Count -gt 0) | ConvertTo-Json",Duration::from_secs(8))?.as_bool().unwrap_or(false))
}
fn environment(root: &Path) -> Result<Outcome> {
    let c=storage::load(root)?;
    let inv=ps(r#"$os=Get-CimInstance Win32_OperatingSystem;@{windows=$os.Caption;version=$os.Version;build=$os.BuildNumber;admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);disks=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'|Select-Object DeviceID,FreeSpace,Size);winget=[bool](Get-Command winget -ErrorAction SilentlyContinue);git=[bool](Get-Command git -ErrorAction SilentlyContinue);connection=@(Get-NetConnectionProfile -ErrorAction SilentlyContinue|Select-Object Name,IPv4Connectivity,IPv6Connectivity)}|ConvertTo-Json -Depth 5"#,Duration::from_secs(50))?;
    let mut notes=Vec::new();
    if inv["admin"]!=true {notes.push("Нет прав администратора".into());}
    if inv["winget"]!=true {notes.push("winget не найден".into());}
    if inv["git"]!=true && !Path::new(&system::tool("git")).is_file() {notes.push("git не найден".into());}
    if !inv["connection"].as_array().into_iter().flatten().any(|c|c["IPv4Connectivity"]==4||c["IPv6Connectivity"]==4) {notes.push("Windows не сообщает о подключении к интернету; активный запрос не выполнялся".into());}
    let mut status=Status::PASS;
    if c.application.data_drive.is_empty() {notes.push("Диск данных не выбран".into());} else {
        let free=inv["disks"].as_array().into_iter().flatten().find(|d|d["DeviceID"]==c.application.data_drive).and_then(|d|d["FreeSpace"].as_u64());
        match free {Some(bytes) if bytes/(1024*1024*1024)>=c.execution.minimum_free_gib=>notes.push(format!("Свободно {:.2} ГиБ",bytes as f64/1073741824.0)),Some(_)=>{status=Status::FAIL;notes.push("Недостаточно свободного места".into());},None=>{status=Status::WARN;notes.push("Диск данных не найден".into());}}
    }
    if status==Status::PASS && notes.iter().any(|s|!s.starts_with("Свободно")) {status=Status::WARN;}
    Ok(outcome(status,if notes.is_empty(){"Окружение прочитано".into()}else{notes.join("; ")},pretty(&inv)))
}
fn restore_readonly() -> Result<Outcome> {
    use chrono::TimeZone;
    let v=ps(r#"$points=@(Get-ComputerRestorePoint -ErrorAction Stop|Select-Object SequenceNumber,Description,CreationTime);$policy=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' -ErrorAction SilentlyContinue;$local=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -ErrorAction SilentlyContinue;@{points=$points;policyDisableSR=$policy.DisableSR;localDisableSR=$local.DisableSR;frequency=$local.SystemRestorePointCreationFrequency;service=Get-Service VSS -ErrorAction SilentlyContinue|Select-Object Status,StartType}|ConvertTo-Json -Depth 6"#,Duration::from_secs(55));
    let v=match v {Ok(v)=>v,Err(e)=>return Ok(outcome(Status::WARN,"Состояние защиты системы неизвестно; прогноз недоступен",e.to_string()))};
    let last=v["points"].as_array().into_iter().flatten().filter_map(|p|system::wmi_parts(p["CreationTime"].as_str()?)).filter_map(|(n,o)|o.from_local_datetime(&n).single()).max();
    let latest=last.map(|t|t.to_rfc3339()).unwrap_or_else(||"не найдена".into());
    let disabled=v["policyDisableSR"]==1 || v["localDisableSR"]==1;
    let recent=last.map(|t|chrono::Local::now().signed_duration_since(t)<chrono::Duration::hours(24)).unwrap_or(false);
    let (status,prediction)=if disabled {(Status::WARN,"Пропустит: защита выключена (DisableSR=1)")} else if recent {(Status::WARN,"Пропустит из-за лимита 24 часа")} else {(Status::WARN,"Будет создана при включённой защите системного диска; состояние защиты тома нельзя достоверно подтвердить этим чтением")};
    Ok(outcome(status,format!("{prediction}. Последняя точка: {latest}"),format!("Прогноз при стандартном лимите 24 часа; частота из реестра приведена ниже. Реальное создание не выполнялось.\n{}",pretty(&v))))
}
fn network_error(s: &str) -> bool {
    let s=s.to_lowercase();
    ["network","internet","resolve host","could not resolve","connect","timed out","timeout","0x80072","0x800704cf","сети","сетев","подключ","тайм-аут","соединен"].iter().any(|needle|s.contains(needle))
}
fn network_check(root: &Path, id: &str) -> Result<Outcome> {
    let began=Instant::now();
    let c=storage::load(root)?;
    let profile=c.profiles.iter().find(|p|p.name==c.application.selected_profile).context("Нет выбранного профиля")?;
    match connection() {
        Ok(false)=>return Ok(outcome(Status::WARN,"Нет подтверждённого подключения; сетевой тест не выполнялся","Проверено локальное состояние Get-NetConnectionProfile")),
        Err(e)=>return Ok(outcome(Status::WARN,"Не удалось определить подключение к интернету",e.to_string())),
        Ok(true)=>(),
    }
    if let Some(key)=id.strip_prefix("program:") {
        let p=c.programs.iter().find(|p|p.key==key && profile.programs.contains(&p.key)).context("Программа больше не включена в профиль")?;
        if !["winget","msstore"].contains(&p.source.as_str()) {return Ok(outcome(Status::SKIP,"Для этого источника нет разрешённой проверки winget show",format!("Источник: {}",p.source)));}
        let mut cmd=Command::new(system::tool("winget")); cmd.args(["show","--id",&p.id,"--exact"]);
        if p.source=="msstore" {cmd.args(["--source","msstore"]);}
        let result=command(cmd,Duration::from_secs(45).saturating_sub(began.elapsed()));
        let (ok,out)=match result {Ok(v)=>v,Err(e)=>return Ok(outcome(Status::WARN,"winget недоступен или превышен тайм-аут",e.to_string()))};
        if ok {
            let installer=out.lines().find(|line| {let l=line.to_lowercase(); l.contains("installer type") || l.contains("тип установщика") || l.trim_start().starts_with("type:") || l.trim_start().starts_with("тип:")}).map(str::trim);
            Ok(outcome(if installer.is_some(){Status::PASS}else{Status::WARN},format!("Найден: {}; {}",p.id,installer.unwrap_or("тип установщика не распознан; см. технический вывод")),out))
        } else {
            let lower=out.to_lowercase();
            let missing=lower.contains("no package found") || lower.contains("no applicable package") || lower.contains("пакет не найден") || lower.contains("не найден пакет") || lower.contains("пакеты не найдены");
            Ok(outcome(if missing && !network_error(&out){Status::FAIL}else{Status::WARN},if missing{"Пакет не найден"}else{"winget show не подтвердил доступность: сеть, соглашения источника или ошибка клиента"},out))
        }
    } else {
        let key=id.strip_prefix("repo:").context("Неизвестная проверка сети")?;
        let repo=c.repositories.iter().find(|r|r.key==key && profile.repositories.contains(&r.key)).context("Репозиторий больше не включён в профиль")?;
        model::https(&repo.url)?;
        let mut cmd=Command::new(system::tool("git"));
        let mut temp=Temp::new()?;
        cmd.current_dir(&temp.path).env("GIT_CEILING_DIRECTORIES",&temp.path);
        cmd.args(["ls-remote",&repo.url]).env("GIT_TERMINAL_PROMPT","0").env("GCM_INTERACTIVE","never")
            .env("GIT_CONFIG_NOSYSTEM","1").env("GIT_CONFIG_GLOBAL","NUL")
            .env("GIT_CONFIG_COUNT","2").env("GIT_CONFIG_KEY_0","credential.helper").env("GIT_CONFIG_VALUE_0","")
            .env("GIT_CONFIG_KEY_1","core.askPass").env("GIT_CONFIG_VALUE_1","");
        let result=command(cmd,Duration::from_secs(55).saturating_sub(began.elapsed()));
        temp.cleanup()?;
        match result {
            Ok((true,out))=>Ok(outcome(Status::PASS,"Репозиторий доступен; клонирование не выполнялось",out)),
            Ok((false,out))=>Ok(outcome(if network_error(&out){Status::WARN}else{Status::FAIL},"git ls-remote не подтвердил доступность",out)),
            Err(e)=>Ok(outcome(Status::WARN,"git недоступен или превышен тайм-аут",e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_dev_mode_and_strict_bool() {
        assert_eq!(check(Path::new("unused"), "legacy").unwrap().status, Status::PASS);
        let text=model::render(&model::defaults()).unwrap();
        assert!(!model::parse(&text.replace("dev_mode = false\n","")).unwrap().application.dev_mode);
        assert!(model::parse(&text.replace("dev_mode = false","dev_mode = true")).unwrap().application.dev_mode);
        assert!(model::parse(&text.replace("dev_mode = false","dev_mode = 'true'")).is_err());
    }
    #[test]
    fn report_redacts_strings_without_breaking_json() {
        let v=sanitized(json!({"text":"token=example-secret", "rows":["ghp_example_secret"]}));
        let encoded=serde_json::to_string(&v).unwrap();
        assert!(serde_json::from_str::<Value>(&encoded).is_ok());
        assert!(!encoded.contains("example-secret")); assert!(!encoded.contains("example_secret"));
    }
    #[test]
    fn user_paths_are_hidden() {
        assert_eq!(hide_user(r"C:\Users\Иван\Documents\report.md"),r"%USERPROFILE%\Documents\report.md");
        assert_eq!(hide_user(r"c:/users/Ivan Petrov/Documents"),r"%USERPROFILE%/Documents");
        assert_eq!(hide_user(r#"C:\\Users\\Иван\\Documents"#),r#"%USERPROFILE%\\Documents"#);
    }
    #[test]
    fn retention_only_removes_our_old_reports() {
        let mut temp=Temp::new().unwrap();
        for i in 1..=7 {for ext in ["md","json"] {fs::write(temp.path.join(format!("devtest-20261012-12000{i}.{ext}")),"{}").unwrap();}}
        let other=temp.path.join("other.json"); fs::write(&other,"keep").unwrap();
        retain_reports(&temp.path).unwrap();
        assert!(!temp.path.join("devtest-20261012-120001.md").exists());
        assert!(temp.path.join("devtest-20261012-120003.json").exists());
        assert!(other.exists()); assert_eq!(fs::read_dir(&temp.path).unwrap().count(),11);
        temp.cleanup().unwrap(); assert!(!temp.path.exists());
    }
    #[test]
    fn traversal_is_rejected() {
        let mut temp=Temp::new().unwrap();
        assert!(within(&temp.path,"../outside").is_err());
        assert!(within(&temp.path,r"C:\outside").is_err());
        temp.cleanup().unwrap();
    }
    fn plan(actions: Vec<engine::Action>) -> engine::Plan {
        engine::Plan {profile:"тест".into(),fingerprint:"".into(),warnings:vec![],readiness:json!({"apps":[]}),displays:vec![],tasks:actions.into_iter().enumerate().map(|(id,action)|engine::Task {id,action,verification_only:false,name:"".into(),risk:"".into(),reversible:"".into(),status:"pending".into(),detail:"".into()}).collect()}
    }
    #[test]
    fn rejects_vencord_before_discord_and_protected_packages() {
        use engine::Action::*;
        assert!(validate_plan(&plan(vec![Check,RestorePoint,Program("discord".into()),Program("vencord".into()),Final])).is_ok());
        assert!(validate_plan(&plan(vec![Check,Program("vencord".into()),Program("discord".into()),Final])).is_err());
        assert!(validate_plan(&plan(vec![Check,Remove("Microsoft.WindowsStore".into()),Final])).is_err());
        let mut p=plan(vec![Check,Remove("Microsoft.549981C3F5F10".into()),Final]);
        p.readiness=json!({"apps":[{"Name":"Microsoft.549981C3F5F10","NonRemovable":true}]});
        assert!(validate_plan(&p).is_err());
        assert!(validate_plan(&plan(vec![Check,Program("discord".into()),Folder("x".into()),Final])).is_err());
    }

}
// Реальные тесты намеренно отсутствуют в list(), check() и selftest().
const REAL_GROUP: u8 = 10;
const REAL_TIMEOUT: Duration = Duration::from_secs(60);
const STARTUP_ROOT: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";
const MARKER_NAME: &str = ".winsetup-devtest-marker";

pub fn real_list() -> Vec<Test> {
    [("R1", "Цикл уведомлений Telegram"), ("R2", "Цикл советов и предложений"),
     ("R3", "Цикл одной записи автозапуска"), ("R4", "Создание и удаление тестовой папки")]
        .into_iter().map(|(id,name)|Test {id:id.into(),group:REAL_GROUP,name:name.into(),timeout_s:60}).collect()
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StartupPick { pub key: String, pub name: String, pub category: String, pub command: String }
fn startup_allowed(row: &Value) -> bool {
    row["hive"] == "HKCU" && row["disabled"] == false
        && ["Run","Run32","StartupFolder"].contains(&row["category"].as_str().unwrap_or(""))
        && row["name"].as_str().map(|s| !s.is_empty() && !s.contains(['\\','/','\0']) && !s.to_lowercase().contains("securityhealth")).unwrap_or(false)
        && !row["path"].as_str().unwrap_or("").to_lowercase().contains("securityhealth")
}
fn startup_options() -> Result<Vec<StartupPick>> {
    Ok(system::array(system::startup()?).into_iter().filter(startup_allowed).filter_map(|row| Some(StartupPick {
        key:row["key"].as_str()?.into(), name:row["name"].as_str()?.into(),
        category:row["category"].as_str()?.into(), command:row["path"].as_str()?.into(),
    })).collect())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealJournal {
    version: u32, id: String, test_id: String, owner: String, created: String,
    registry: Vec<system::RegUndo>, touched: Vec<bool>, startup: Option<StartupPick>, folder: Option<String>,
}
fn journal_name(id: &str) -> String { format!("devtest-rollback-{id}.json") }
fn valid_journal_id(id: &str) -> bool { id.len()==32 && id.bytes().all(|c|c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) }
// Совпадает с сериализацией serde_json::Value в system::startup; обычные строки дают другой хеш.
fn startup_identity(category:&str,name:&str)->String {
    storage::hash(format!("{}:{}:{}",json!("HKCU"),json!(category),json!(name)).as_bytes())[..20].into()
}
fn diagnostic_id(id:Option<&str>)->String {
    match id {
        None=>"не получен".into(),
        Some(s) if s.len()==20 && s.bytes().all(|c|c.is_ascii_hexdigit())=>s.into(),
        Some(_)=>"некорректный формат (содержимое скрыто)".into(),
    }
}
fn r3_details(ui_id:Option<&str>,found:Option<&StartupPick>,count:Option<usize>)->String {
    // Команда, путь запуска и содержимое реестра сюда не попадают.
    pretty(&json!({
        "Диагностика R3":"startup-json-id-v2",
        "Идентификатор из интерфейса":diagnostic_id(ui_id),
        "Идентификатор найденной записи":diagnostic_id(found.map(|p|p.key.as_str())),
        "Ожидаемый идентификатор":found.map(|p|startup_identity(&p.category,&p.name)).unwrap_or_else(||"не вычислен: запись не найдена".into()),
        "Имя записи":found.map(|p|storage::redact(&p.name)).unwrap_or_else(||"не найдена".into()),
        "Категория записи":found.map(|p|storage::redact(&p.category)).unwrap_or_else(||"не найдена".into()),
        "Количество доступных записей в списке":count,
        "Список прочитан":count.is_some(),
    }))
}
fn r3_checked(
    ui_id:Option<&str>,read:impl FnOnce()->Result<Vec<StartupPick>>,
    check:impl FnOnce(Option<&StartupPick>)->Result<Outcome>,
)->Outcome {
    let mut count=None;
    let mut found=None;
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Outcome> {
        let rows=read()?;count=Some(rows.len());
        if let Some(key)=ui_id {
            let matches=rows.iter().filter(|p|p.key==key).collect::<Vec<_>>();
            found=matches.first().map(|p|(*p).clone());
            ensure!(!matches.is_empty(),"Выбранная запись недоступна, отключена или запрещена; выберите заново");
            ensure!(matches.len()==1,"Идентификатор автозапуска неоднозначен; изменений нет");
        }
        check(found.as_ref())
    })).unwrap_or_else(|_|Err(anyhow::anyhow!("Внутренняя ошибка R3. Проверьте сохранённые снимки перед новым запуском")));
    let mut result=result.unwrap_or_else(|e|outcome(Status::FAIL,"Реальный тест R3 не завершён",format!("{e:#}")));
    result.technical=format!("{}\n\n{}",r3_details(ui_id,found.as_ref(),count),result.technical);
    result
}
fn registry_targets(test_id: &str, startup: Option<&StartupPick>) -> Result<Vec<(String,String)>> {
    match test_id {
        "R1"|"R2" => Ok(system::tweak_values(if test_id=="R1" {"notify_telegram"} else {"suggestions"},"disabled")?
            .into_iter().map(|(p,n,_)|(p,n)).collect()),
        "R3" => {
            let p=startup.context("Не выбрана запись автозапуска")?;
            ensure!(["Run","Run32","StartupFolder"].contains(&p.category.as_str()) && !p.name.is_empty()
                && !p.name.contains(['\\','/','\0']) && !p.name.to_lowercase().contains("securityhealth")
                && !p.command.to_lowercase().contains("securityhealth"),"Запись автозапуска запрещена");
            // system::startup хеширует JSON-значения строк вместе с кавычками и экранированием.
            let expected=startup_identity(&p.category,&p.name);
            ensure!(p.key==expected,"Идентификатор автозапуска не совпадает: ожидаемый {expected}; полученный {}",diagnostic_id(Some(&p.key)));
            Ok(vec![(format!("{STARTUP_ROOT}\\{}",p.category),p.name.clone())])
        },
        "R4" => Ok(vec![]),
        _ => bail!("Недопустимый реальный тест"),
    }
}
fn data_folder(drive: &str) -> Result<PathBuf> {
    ensure!(drive.len()==2 && drive.as_bytes()[0].is_ascii_alphabetic() && drive.ends_with(':'),"Выберите диск данных");
    Ok(PathBuf::from(format!("{}\\WinSetupDevTest",drive.to_ascii_uppercase())))
}
fn validate_journal(journal: &RealJournal) -> Result<()> {
    ensure!(journal.version==1 && valid_journal_id(&journal.id) && !journal.owner.is_empty(),"Недопустимый формат снимка");
    let targets=registry_targets(&journal.test_id,journal.startup.as_ref())?;
    ensure!(journal.touched.len()==journal.registry.len(),"Снимок не содержит отметки о записях");
    ensure!(journal.registry.len()==targets.len(),"Снимок не содержит точный набор значений теста");
    for (row,(path,name)) in journal.registry.iter().zip(targets) {
        ensure!(row.hive=="HKCU" && row.path==path && row.name==name,"Снимок содержит посторонний путь реестра");
        ensure!(row.existed || row.value.is_none(),"Снимок отсутствующего ключа содержит значение");
        if let Some((kind,bytes))=&row.value {ensure!(*kind<=11 && bytes.len()<=1024*1024,"Недопустимое значение снимка");}
    }
    ensure!((journal.test_id=="R3")==journal.startup.is_some(),"Лишние сведения автозапуска");
    if journal.test_id=="R4" {
        let folder=journal.folder.as_deref().context("Нет тестовой папки")?;
        let drive=folder.get(..2).context("Неверный путь папки")?;
        ensure!(data_folder(drive)?.to_str()==Some(folder),"Снимок содержит постороннюю папку");
    } else {ensure!(journal.folder.is_none(),"Лишняя папка в снимке реестра");}
    Ok(())
}
fn real_owner() -> Result<String> {
    let sid=ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value | ConvertTo-Json",Duration::from_secs(8))?;
    Ok(format!("{}:{}",std::env::var("COMPUTERNAME")?.to_uppercase(),sid.as_str().context("Не получен SID пользователя")?))
}
fn journal_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let logs=root.join("logs"); model::no_links(&logs)?;
    if !logs.exists() {return Ok(vec![]);}
    let mut paths=Vec::new();
    for e in fs::read_dir(&logs)? {
        let e=e?; let name=e.file_name().to_string_lossy().into_owned();
        if name.starts_with("devtest-rollback-") && name.ends_with(".json") {paths.push(e.path());}
    }
    paths.sort(); Ok(paths)
}
fn read_journal(path: &Path) -> Result<RealJournal> {
    model::no_links(path)?;
    ensure!(fs::metadata(path)?.len()<=4*1024*1024,"Снимок слишком большой");
    let journal:RealJournal=serde_json::from_slice(&fs::read(path)?)?;
    validate_journal(&journal)?;
    ensure!(path.file_name().and_then(|s|s.to_str())==Some(journal_name(&journal.id).as_str()),"Имя файла не соответствует снимку");
    Ok(journal)
}
fn write_journal(root: &Path, journal: &RealJournal) -> Result<PathBuf> {
    validate_journal(journal)?;
    let path=root.join("logs").join(journal_name(&journal.id)); model::no_links(&path)?;
    ensure!(!path.exists(),"Файл снимка уже существует");
    // Снимок не маскируется: для отката необходимы точные исходные байты.
    storage::atomic(&path,&serde_json::to_vec_pretty(journal)?,false)?;
    let saved=read_journal(&path)?;
    ensure!(serde_json::to_value(&saved)?==serde_json::to_value(journal)?,"Снимок не прошёл проверку чтением");
    Ok(path)
}
pub fn real_info(root: &Path, include_startup: bool) -> Result<Value> {
    let mut pending=Vec::new();
    for path in journal_paths(root)? {
        pending.push(match read_journal(&path) {
            Ok(j)=>json!({"file":path.file_name().unwrap().to_string_lossy(),"test":j.test_id,"created":j.created,"details":manual_restore(&j),"valid":true}),
            Err(e)=>json!({"file":path.file_name().unwrap().to_string_lossy(),"valid":false,"details":format!("Снимок не прочитан: {e}. Автоматическая запись запрещена; сохраните файл для ручного восстановления.")}),
        });
    }
    let mut info=json!({"tests":real_list(),"pending":pending,"startup":[],"startup_error":"","data_drive":storage::load(root).map(|c|c.application.data_drive).unwrap_or_default(),"targets":{"R1":registry_targets("R1",None)?,"R2":registry_targets("R2",None)?}});
    if include_startup { match startup_options() {Ok(rows)=>info["startup"]=json!(rows),Err(e)=>info["startup_error"]=json!(e.to_string())} }
    Ok(sanitized(info))
}
trait RegistryAccess {
    fn read(&mut self, path: &str, name: &str) -> Result<system::RegUndo>;
    fn disable(&mut self, row: &system::RegUndo, startup: bool) -> Result<()>;
    fn undo(&mut self, row: &system::RegUndo) -> Result<()>;
}
struct ExistingRegistry;
impl RegistryAccess for ExistingRegistry {
    fn read(&mut self,path:&str,name:&str)->Result<system::RegUndo> {system::snapshot("HKCU",path,name)}
    fn disable(&mut self,row:&system::RegUndo,startup:bool)->Result<()> {
        // Тот же payload и тот же механизм system::write_reg, что у engine::Action.
        if startup {let mut bytes=vec![0;12];bytes[0]=3;system::write_reg("HKCU",&row.path,&row.name,bytes,winreg::enums::REG_BINARY)}
        else {system::write_reg("HKCU",&row.path,&row.name,0u32.to_le_bytes().to_vec(),winreg::enums::REG_DWORD)}
    }
    fn undo(&mut self,row:&system::RegUndo)->Result<()> {system::undo_reg(row)}
}
fn same_registry(a: &system::RegUndo,b: &system::RegUndo) -> bool {
    a.hive==b.hive && a.path==b.path && a.name==b.name && a.existed==b.existed && a.value==b.value
}
fn expected_disabled(row: &system::RegUndo,startup:bool) -> bool {
    if !row.existed {return false;}
    if startup {let mut bytes=vec![0;12];bytes[0]=3;row.value==Some((3,bytes))}
    else {row.value==Some((4,vec![0;4]))}
}
fn restore_registry(registry: &mut impl RegistryAccess, rows: &[system::RegUndo], touched: &[bool]) -> Result<()> {
    let mut errors=Vec::new();
    for (row,changed) in rows.iter().zip(touched).rev() {if !changed {continue;} if let Err(e)=registry.undo(row) {errors.push(format!("HKCU\\{} [{}]: {e}",row.path,row.name));}}
    // Проверка после всего отката: несколько значений могут находиться в одном исходно отсутствующем ключе.
    for row in rows {match registry.read(&row.path,&row.name) {
        Ok(actual) if same_registry(row,&actual)=>(),
        Ok(actual)=>errors.push(format!("HKCU\\{} [{}]: состояние не вернулось; сейчас {}",row.path,row.name,pretty(&actual))),
        Err(e)=>errors.push(format!("HKCU\\{} [{}]: не удалось проверить возврат: {e}",row.path,row.name)),
    }}
    ensure!(errors.is_empty(),"{}",errors.join("\n")); Ok(())
}
fn manual_restore(journal: &RealJournal) -> String {
    let mut lines=vec![format!("Снимок: {}. Пользователь/компьютер: {}.",journal_name(&journal.id),journal.owner)];
    for r in &journal.registry {
        let previous=match &r.value {
            Some((kind,bytes))=>format!("тип {kind}; исходные байты HEX: {}",bytes.iter().map(|b|format!("{b:02X}")).collect::<Vec<_>>().join(" ")),
            None if r.existed=>"значения не было; удалить только это значение, ключ оставить".into(),
            None=>"ключа и значения не было; удалить значение и затем только пустой конечный ключ".into(),
        };
        lines.push(format!("HKCU\\{}\nЗначение: {}\nРаньше: {previous}",r.path,r.name));
    }
    if let Some(folder)=&journal.folder {lines.push(format!("Папки {folder} раньше не было. Проверьте файл {MARKER_NAME} с содержимым WinSetupDevTest:{} и отсутствие чужих файлов; только затем удалите тестовую папку. Без маркера автоматическое удаление запрещено.",journal.id));}
    lines.push("Для реестра: откройте редактор реестра под тем же пользователем и восстановите указанные типы/байты (3 = REG_BINARY, 4 = REG_DWORD, little-endian); исходно отсутствующие значения удалите. Другие значения и непустые ключи не удаляйте. Файл снимка сохраните до проверки возврата.".into());
    lines.join("\n\n")
}
fn deadline(start: Instant) -> Result<()> { ensure!(start.elapsed()<REAL_TIMEOUT,"Тайм-аут 60 с; применение прекращено, требуется завершить откат");Ok(()) }
fn marker_text(j: &RealJournal) -> String {format!("WinSetupDevTest:{}",j.id)}
fn checked_marker(folder:&Path,expected:&str)->Result<PathBuf> {
    model::no_links(folder)?;
    let marker=folder.join(MARKER_NAME);model::no_links(&marker)?;
    ensure!(fs::metadata(&marker)?.len()<=128 && fs::read_to_string(&marker)?==expected,"Нет нашего маркера; папка не удалена");
    let entries=fs::read_dir(folder)?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(entries.len()==1 && entries[0].file_name()==MARKER_NAME,"В папке появились чужие файлы; удаление запрещено");
    Ok(marker)
}
fn restore_folder(j: &RealJournal) -> Result<()> {
    validate_journal(j)?;
    let folder=PathBuf::from(j.folder.as_ref().context("Нет папки в снимке")?);
    model::no_links(&folder)?;
    if !folder.try_exists()? {return Ok(());}
    ensure!(folder.is_dir(),"Тестовый путь больше не является папкой");
    let marker=checked_marker(&folder,&marker_text(j))?;
    // Не используем рекурсивное удаление: чужое содержимое, появившееся одновременно, не удалится.
    fs::remove_file(&marker)?;
    if let Err(e)=fs::remove_dir(&folder) {
        if model::no_links(&folder).is_ok() && folder.is_dir() {
            if let Ok(mut f)=fs::OpenOptions::new().write(true).create_new(true).open(&marker) {let _=f.write_all(marker_text(j).as_bytes());let _=f.sync_all();}
        }
        return Err(e.into());
    }
    ensure!(!folder.try_exists()?,"Папка не удалена");Ok(())
}
fn restore_saved(path: &Path,j: &RealJournal, registry:&mut impl RegistryAccess) -> Result<()> {
    validate_journal(j)?;
    if j.test_id=="R4" {restore_folder(j)?;} else {restore_registry(registry,&j.registry,&j.touched)?;}
    model::no_links(path)?;
    // Снимок удаляется только после подтверждённого полного возврата.
    fs::remove_file(path)?; Ok(())
}
fn registry_cycle(root:&Path,j:&RealJournal,start:Instant,registry:&mut impl RegistryAccess) -> Result<Outcome> {
    let path=write_journal(root,j)?;
    let mut pending=j.clone();
    let applied=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
        for (index,row) in j.registry.iter().enumerate() {
            deadline(start)?;
            let mut expected=row.clone();
            if !row.existed && j.registry[..index].iter().any(|r|r.path==row.path) {expected.existed=true;}
            ensure!(same_registry(&expected,&registry.read(&row.path,&row.name)?),"Значение изменилось после снимка; применение остановлено");
            let mut intent=pending.clone();intent.touched[index]=true;
            storage::atomic(&path,&serde_json::to_vec_pretty(&intent)?,false)?;
            pending=intent;
            deadline(start)?;
            registry.disable(row,j.test_id=="R3")?;
            ensure!(expected_disabled(&registry.read(&row.path,&row.name)?,j.test_id=="R3"),"Отключение не подтверждено чтением");
        }
        deadline(start)
    })).unwrap_or_else(|_|Err(anyhow::anyhow!("Внутренняя ошибка применения")));
    let restored=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||restore_saved(&path,&pending,registry)))
        .unwrap_or_else(|_|Err(anyhow::anyhow!("Внутренняя ошибка отката")));
    match restored {
        Err(e)=>Ok(outcome(Status::FAIL,"ВНИМАНИЕ: ОТКАТ НЕ ЗАВЕРШЁН — сохранён снимок",format!("ОСТАЛИСЬ НЕВОССТАНОВЛЕННЫЕ ИЛИ НЕПРОВЕРЕННЫЕ ИЗМЕНЕНИЯ:\n{e:#}\n\n{}",manual_restore(j)))),
        Ok(())=>match applied.and_then(|_|deadline(start)) {
            Ok(())=>Ok(outcome(Status::PASS,"Отключение проверено; исходные типы, байты и отсутствие значений/ключей восстановлены",format!("Значений проверено: {}. Снимок удалён после проверки возврата.",j.registry.len()))),
            Err(e)=>Ok(outcome(Status::FAIL,"Проверка не завершена; исходное состояние восстановлено",format!("{e:#}"))),
        },
    }
}
fn folder_cycle(root:&Path,j:&RealJournal,start:Instant) -> Result<Outcome> {
    let folder=PathBuf::from(j.folder.as_ref().context("Нет папки")?);model::no_links(&folder)?;
    if folder.try_exists()? {return Ok(outcome(Status::SKIP,"WinSetupDevTest уже существует; чужая папка не изменена",folder.display().to_string()));}
    let path=write_journal(root,j)?;
    let applied=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
        deadline(start)?;fs::create_dir(&folder)?;
        let marker=folder.join(MARKER_NAME);
        let mut f=fs::OpenOptions::new().write(true).create_new(true).open(&marker)?;
        f.write_all(marker_text(j).as_bytes())?;f.sync_all()?;drop(f);
        let before=storage::file_hash(&marker)?;let modified=fs::metadata(&marker)?.modified()?;
        deadline(start)?;fs::create_dir_all(&folder)?;
        ensure!(storage::file_hash(&marker)?==before && fs::metadata(&marker)?.modified()?==modified,"Повторное создание изменило маркер");
        deadline(start)
    })).unwrap_or_else(|_|Err(anyhow::anyhow!("Внутренняя ошибка файлового теста")));
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||restore_saved(&path,j,&mut ExistingRegistry))).unwrap_or_else(|_|Err(anyhow::anyhow!("Внутренняя ошибка удаления тестовой папки"))) {
        Err(e)=>Ok(outcome(Status::FAIL,"ВНИМАНИЕ: ПАПКА НЕ УДАЛЕНА — сохранён снимок",format!("{e:#}\n\n{}",manual_restore(j)))),
        Ok(())=>match applied.and_then(|_|deadline(start)) {
            Ok(())=>Ok(pass("Папка создана дважды без изменения маркера и удалена; отсутствие проверено")),
            Err(e)=>Ok(outcome(Status::FAIL,"Файловая проверка не завершена; исходное отсутствие папки восстановлено",e.to_string())),
        },
    }
}
fn real_check(root:&Path,id:&str,owner:&str,drive:&str,startup:Option<&StartupPick>) -> Result<Outcome> {
    let start=Instant::now();
    if id=="R3" && startup.is_none() {return Ok(outcome(Status::SKIP,"Запись автозапуска не выбрана; изменений нет",""));}
    // Для R3 свежий список и выбор проверяются в r3_checked непосредственно перед этим вызовом.
    let mut j=RealJournal {version:1,id:format!("{:032x}",rand::random::<u128>()),test_id:id.into(),owner:owner.into(),created:chrono::Local::now().to_rfc3339(),registry:vec![],touched:vec![],startup:if id=="R3" {startup.cloned()}else{None},folder:None};
    if id=="R4" {j.folder=Some(data_folder(drive)?.display().to_string());return folder_cycle(root,&j,start);}
    for (path,name) in registry_targets(id,startup)? {
        // undo_reg удаляет только конечный ключ: отсутствующие промежуточные ключи не создаём.
        let parent=path.rsplit_once('\\').context("Нет родителя ключа")?.0;
        if let Err(e)=winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER).open_subkey(parent) {
            return Ok(outcome(Status::SKIP,"Родитель ключа недоступен; нельзя гарантировать полный возврат",format!("HKCU\\{parent}: {e}")));
        }
        j.registry.push(system::snapshot("HKCU",&path,&name)?);
    }
    j.touched=vec![false;j.registry.len()];
    deadline(start)?;registry_cycle(root,&j,start,&mut ExistingRegistry)
}
impl Runner {
    pub fn start_real(self:&Arc<Self>, engine:Arc<engine::Engine>, startup_key:Option<String>, confirmed:bool) -> Result<()> {
        ensure!(confirmed,"Не подтверждены реальные изменения");
        ensure!(storage::load(&engine.root)?.application.dev_mode,"Включите режим разработчика");
        ensure!(journal_paths(&engine.root)?.is_empty(),"Сначала откатите сохранённые значения прошлого запуска");
        self.launch_real(engine,startup_key,false)
    }
    pub fn recover_real(self:&Arc<Self>, engine:Arc<engine::Engine>, confirmed:bool) -> Result<()> {
        ensure!(confirmed,"Подтвердите возврат сохранённых значений");
        ensure!(!journal_paths(&engine.root)?.is_empty(),"Сохранённых снимков нет");
        self.launch_real(engine,None,true)
    }
    fn launch_real(self:&Arc<Self>, engine:Arc<engine::Engine>, startup_key:Option<String>, recovery:bool) -> Result<()> {
        ensure!(!self.reserved.swap(true,Ordering::SeqCst),"Диагностика уже выполняется");
        if engine.busy.swap(true,Ordering::SeqCst) {self.reserved.store(false,Ordering::SeqCst);bail!("Дождитесь завершения текущей операции");}
        self.stop.store(false,Ordering::SeqCst);
        *self.state.lock().unwrap()=State {active:true,id:report_id(&engine.root),tests:if recovery {vec![]}else{real_list()},..State::default()};
        let this=self.clone();let e=engine.clone();let diagnostic_key=startup_key.clone();
        let spawned=std::thread::Builder::new().name("winsetup-real-tests".into()).spawn(move || {
            let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||this.run_real(&e.root,startup_key,recovery)))
                .unwrap_or_else(|_|Err(anyhow::anyhow!("Внутренняя ошибка. Проверьте сохранённые снимки перед новым запуском")));
            if let Err(err)=result {
                if !recovery && !this.state().results.iter().any(|r|r.id=="R3") {
                    this.finish(&real_list().into_iter().find(|t|t.id=="R3").unwrap(),Duration::ZERO,
                        outcome(Status::FAIL,"R3 не начат: ошибка подготовки",format!("{}\n\n{err:#}",r3_details(diagnostic_key.as_deref(),None,None))));
                }
                this.log(Status::FAIL,format!("{err:#}"));this.state.lock().unwrap().error=storage::redact(&format!("{err:#}"));
            }
            {let mut state=this.state.lock().unwrap();state.active=false;state.current=None;}
            if let Err(err)=this.save(&e.root) {this.log(Status::FAIL,format!("Ошибка записи отчёта: {err}"));this.state.lock().unwrap().error=storage::redact(&err.to_string());}
            e.busy.store(false,Ordering::SeqCst);this.reserved.store(false,Ordering::SeqCst);
        });
        if let Err(err)=spawned {engine.busy.store(false,Ordering::SeqCst);self.reserved.store(false,Ordering::SeqCst);self.state.lock().unwrap().active=false;return Err(err.into());}
        Ok(())
    }
    fn run_real(&self,root:&Path,startup_key:Option<String>,recovery:bool) -> Result<()> {
        let owner=real_owner()?;
        self.state.lock().unwrap().header=json!({"версия_программы":env!("CARGO_PKG_VERSION"),"дата":chrono::Local::now().to_rfc3339(),"режим":if recovery {"Возврат сохранённых значений"}else{"Реальные обратимые тесты"},"пользователь_и_компьютер":owner,"отпечаток_конфига":fs::read(root.join("winsetup.toml")).map(|b|storage::hash(&b)).unwrap_or_default()});
        self.log(Status::WARN,"Отдельный запуск реальных изменений; снимки сохраняются до подтверждённого возврата");
        if recovery {
            let paths=journal_paths(root)?;
            let tests:Vec<_>=paths.iter().map(|p|Test {id:format!("recover:{}",p.file_name().unwrap().to_string_lossy()),group:REAL_GROUP,name:format!("Откат {}",p.file_name().unwrap().to_string_lossy()),timeout_s:60}).collect();
            self.state.lock().unwrap().tests=tests.clone();
            for (path,test) in paths.iter().zip(tests) {
                if self.stop.load(Ordering::SeqCst) {self.finish(&test,Duration::ZERO,outcome(Status::SKIP,"Откат этого снимка ещё не выполнялся","Снимок оставлен на диске"));continue;}
                self.state.lock().unwrap().current=Some(test.id.clone());self.log(Status::WARN,test.name.clone());let start=Instant::now();
                let result=(|| -> Result<Outcome> {
                    let journal=read_journal(path)?;ensure!(journal.owner==owner,"Снимок другого пользователя или компьютера; автоматический откат запрещён");
                    deadline(start)?;
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||restore_saved(path,&journal,&mut ExistingRegistry))).unwrap_or_else(|_|Err(anyhow::anyhow!("Внутренняя ошибка возврата сохранённого снимка"))) {
                        Ok(())=>{deadline(start)?;Ok(pass("Сохранённые значения возвращены и проверены; снимок удалён"))},
                        Err(e)=>Ok(outcome(Status::FAIL,"ВНИМАНИЕ: ОТКАТ НЕ ЗАВЕРШЁН",format!("{e:#}\n\n{}",manual_restore(&journal)))),
                    }
                })().unwrap_or_else(|e|outcome(Status::FAIL,"Снимок не восстановлен; требуется проверить файл",format!("{e:#}\nФайл: {}",path.display())));
                self.finish(&test,start.elapsed(),result);
            }
        } else {
            ensure!(journal_paths(root)?.is_empty(),"Обнаружен незавершённый откат; новые изменения запрещены");
            let c=storage::load(root)?;ensure!(c.application.dev_mode,"Режим разработчика отключён");
            // R3 получает исходный ID интерфейса; ошибки чтения/выбора становятся результатом R3.
            for test in real_list() {
                if self.stop.load(Ordering::SeqCst) {self.finish(&test,Duration::ZERO,outcome(Status::SKIP,"Остановлено до начала теста",""));continue;}
                self.state.lock().unwrap().current=Some(test.id.clone());self.log(Status::WARN,format!("Начат {}: {}",test.id,test.name));let start=Instant::now();
                let result=if test.id=="R3" {
                    Ok(r3_checked(startup_key.as_deref(),startup_options,|selected|real_check(root,"R3",&owner,&c.application.data_drive,selected)))
                } else if test.id=="R4" && c.application.data_drive.is_empty() {Ok(outcome(Status::SKIP,"Диск данных не выбран; папка не создавалась",""))}
                    else {real_check(root,&test.id,&owner,&c.application.data_drive,None)};
                self.finish(&test,start.elapsed(),result.unwrap_or_else(|e|outcome(Status::FAIL,"Реальный тест не завершён",format!("{e:#}"))));
                if !journal_paths(root)?.is_empty() {self.stop();self.log(Status::FAIL,"ОСТАЛСЯ СНИМОК ОТКАТА. Следующие реальные тесты остановлены.");}
            }
        }
        self.log(if self.state().results.iter().any(|r|r.status==Status::FAIL){Status::FAIL}else{Status::PASS},"Запуск реальных тестов завершён");Ok(())
    }
}
#[cfg(test)]
mod real_tests {
    use super::*;
    use std::collections::{BTreeMap,BTreeSet};
    #[derive(Default)]
    struct FakeRegistry {
        keys:BTreeSet<String>, values:BTreeMap<(String,String),(u32,Vec<u8>)>, writes:usize, undos:usize,
        fail_write:bool, fail_undo:bool,
    }
    impl RegistryAccess for FakeRegistry {
        fn read(&mut self,path:&str,name:&str)->Result<system::RegUndo> {
            Ok(system::RegUndo {hive:"HKCU".into(),path:path.into(),name:name.into(),existed:self.keys.contains(path),value:self.values.get(&(path.into(),name.into())).cloned()})
        }
        fn disable(&mut self,row:&system::RegUndo,startup:bool)->Result<()> {
            self.writes+=1;self.keys.insert(row.path.clone());
            let value=if startup {let mut bytes=vec![0;12];bytes[0]=3;(3,bytes)}else{(4,vec![0;4])};
            self.values.insert((row.path.clone(),row.name.clone()),value);
            ensure!(!self.fail_write,"Имитированная ошибка после записи");Ok(())
        }
        fn undo(&mut self,row:&system::RegUndo)->Result<()> {
            self.undos+=1;ensure!(!self.fail_undo,"Имитированная ошибка отката");
            if let Some(value)=&row.value {self.keys.insert(row.path.clone());self.values.insert((row.path.clone(),row.name.clone()),value.clone());}
            else {self.values.remove(&(row.path.clone(),row.name.clone()));if !row.existed && !self.values.keys().any(|(path,_)|path==&row.path) {self.keys.remove(&row.path);}}
            Ok(())
        }
    }
    fn journal(id:&str, fake:&mut FakeRegistry)->RealJournal {
        let registry=registry_targets(id,None).unwrap().into_iter().map(|(p,n)|fake.read(&p,&n).unwrap()).collect::<Vec<_>>();
        RealJournal {version:1,id:"a".repeat(32),test_id:id.into(),owner:"тест".into(),created:"тест".into(),touched:vec![false;registry.len()],registry,startup:None,folder:None}
    }
    #[test]
    fn real_ids_cannot_enter_safe_catalog() {
        let safe=list(Path::new("nonexistent-devtest-fixture"));
        assert!(safe.iter().all(|t|t.group!=REAL_GROUP && !["R1","R2","R3","R4"].contains(&t.id.as_str())));
        assert_eq!(real_list().len(),4);
    }
    #[test]
    fn startup_identity_matches_existing_reader_and_rejects_forgery() {
        // Строки для хеша соответствуют Display serde_json::Value в system::startup.
        for (category,name,encoded) in [
            ("Run","Example",r#""HKCU":"Run":"Example""#),
            ("Run32","Пример",r#""HKCU":"Run32":"Пример""#),
            ("StartupFolder","Example \"quoted\".lnk",r#""HKCU":"StartupFolder":"Example \"quoted\".lnk""#),
        ] {
            let mut pick=StartupPick {key:storage::hash(encoded.as_bytes())[..20].into(),name:name.into(),category:category.into(),command:"C:\\Example.exe".into()};
            assert_eq!(registry_targets("R3",Some(&pick)).unwrap(),vec![(format!("{STARTUP_ROOT}\\{category}"),name.into())]);
            pick.key=storage::hash(format!("HKCU:{category}:{name}").as_bytes())[..20].into();
            assert!(registry_targets("R3",Some(&pick)).is_err());
            pick.key="00000000000000000000".into();
            assert!(registry_targets("R3",Some(&pick)).is_err());
        }
    }
    fn r3_fixture()->StartupPick {
        let row=json!({"hive":"HKCU","category":"Run","name":"Пример \"quoted\""});
        // Контракт существующего system::startup, без чтения или записи реестра.
        let key=storage::hash(format!("{}:{}:{}",row["hive"],row["category"],row["name"]).as_bytes())[..20].to_owned();
        StartupPick {key,name:row["name"].as_str().unwrap().into(),category:"Run".into(),command:"C:\\private.exe --token=not-for-report".into()}
    }
    fn r3_diag(result:&Outcome)->Value {
        serde_json::from_str(result.technical.split("\n\n").next().unwrap()).unwrap()
    }
    #[test]
    fn r3_diagnostics_survive_ui_roundtrip_and_both_saved_reports() {
        let pick=r3_fixture();
        let info=sanitized(json!({"startup":[pick.clone()]}));
        // UI берёт option.value из key и отправляет startup_key без вычисления хеша.
        let payload:Value=serde_json::from_str(&json!({"startup_key":info["startup"][0]["key"]}).to_string()).unwrap();
        let result=r3_checked(payload["startup_key"].as_str(),||Ok(vec![pick.clone()]),|selected| {
            registry_targets("R3",selected)?;
            bail!("Имитированная ошибка после выбора")
        });
        assert_eq!(result.status,Status::FAIL);
        let diag=r3_diag(&result);
        assert_eq!(diag["Идентификатор из интерфейса"],pick.key);
        assert_eq!(diag["Идентификатор найденной записи"],pick.key);
        assert_eq!(diag["Ожидаемый идентификатор"],pick.key);
        assert_eq!(diag["Имя записи"],pick.name);
        assert_eq!(diag["Категория записи"],"Run");
        assert_eq!(diag["Количество доступных записей в списке"],1);
        let temp=tempfile::tempdir().unwrap();let runner=Runner::default();
        runner.state.lock().unwrap().id="devtest-20261013-220000".into();
        runner.finish(&real_list().into_iter().find(|t|t.id=="R3").unwrap(),Duration::ZERO,result);
        let md=runner.save(temp.path()).unwrap();
        let saved:State=serde_json::from_slice(&fs::read(Path::new(&md).with_extension("json")).unwrap()).unwrap();
        let technical=&saved.results[0].technical;
        assert!(technical.contains(&pick.key));
        assert!(technical.contains("Ожидаемый идентификатор"));
        assert!(fs::read_to_string(md).unwrap().contains(technical));
        assert!(!technical.contains("private.exe"));assert!(!technical.contains("not-for-report"));
    }
    #[test]
    fn r3_diagnostics_include_failed_lookup_read_and_panic() {
        let pick=r3_fixture();let wrong="00000000000000000000";
        let missing=r3_checked(Some(wrong),||Ok(vec![pick.clone()]),|_|panic!("Проверка не должна вызываться"));
        assert_eq!(missing.status,Status::FAIL);
        assert_eq!(r3_diag(&missing)["Идентификатор из интерфейса"],wrong);
        assert_eq!(r3_diag(&missing)["Количество доступных записей в списке"],1);
        assert_eq!(r3_diag(&missing)["Имя записи"],"не найдена");
        let read_error=r3_checked(Some(&pick.key),||bail!("Чтение недоступно"),|_|panic!("Проверка не должна вызываться"));
        assert_eq!(read_error.status,Status::FAIL);assert_eq!(r3_diag(&read_error)["Список прочитан"],false);
        assert!(r3_diag(&read_error)["Количество доступных записей в списке"].is_null());
        let panic_result=r3_checked(Some(&pick.key),||Ok(vec![pick.clone()]),|_|panic!("Имитированный сбой"));
        assert_eq!(panic_result.status,Status::FAIL);
        assert_eq!(r3_diag(&panic_result)["Идентификатор найденной записи"],pick.key);
        let duplicate=r3_checked(Some(&pick.key),||Ok(vec![pick.clone(),pick.clone()]),|_|panic!("Неоднозначный выбор запрещён"));
        assert_eq!(duplicate.status,Status::FAIL);assert_eq!(r3_diag(&duplicate)["Количество доступных записей в списке"],2);
    }
    #[test]
    fn r3_mismatch_reports_expected_and_actual_without_secret_input() {
        let mut pick=r3_fixture();pick.key="00000000000000000000".into();
        let expected=startup_identity(&pick.category,&pick.name);
        let result=r3_checked(Some(&pick.key),||Ok(vec![pick.clone()]),|selected| {
            registry_targets("R3",selected)?;Ok(pass("Проверено"))
        });
        assert_eq!(result.status,Status::FAIL);
        assert_eq!(r3_diag(&result)["Ожидаемый идентификатор"],expected);
        assert!(result.technical.contains(&format!("ожидаемый {expected}; полученный {}",pick.key)));
        pick.name="token=do-not-print".into();
        let details=r3_details(Some("password=do-not-print"),Some(&pick),Some(1));
        assert!(!details.contains("do-not-print"));assert!(!details.contains("private.exe"));
    }
    #[test]
    fn r3_rollback_failures_keep_diagnostics_and_snapshot() {
        let pick=r3_fixture();let temp=tempfile::tempdir().unwrap();
        let mut fake=FakeRegistry::default();
        let registry=registry_targets("R3",Some(&pick)).unwrap().iter().map(|(p,n)|fake.read(p,n).unwrap()).collect::<Vec<_>>();
        let journal=RealJournal {version:1,id:"b".repeat(32),test_id:"R3".into(),owner:"тест".into(),created:"тест".into(),registry,touched:vec![false],startup:Some(pick.clone()),folder:None};
        fake.fail_undo=true;
        let result=r3_checked(Some(&pick.key),||Ok(vec![pick.clone()]),|_|registry_cycle(temp.path(),&journal,Instant::now(),&mut fake));
        assert_eq!(result.status,Status::FAIL);assert!(result.summary.contains("ОТКАТ НЕ ЗАВЕРШЁН"));
        assert_eq!(r3_diag(&result)["Идентификатор найденной записи"],pick.key);
        assert_eq!(r3_diag(&result)["Количество доступных записей в списке"],1);
        assert_eq!(journal_paths(temp.path()).unwrap().len(),1);
    }
    #[test]
    fn startup_excludes_securityhealth_hklm_and_disabled() {
        let good=json!({"hive":"HKCU","disabled":false,"name":"Example","category":"Run","path":"C:\\Example.exe"});
        assert!(startup_allowed(&good));
        for (field,value) in [("hive",json!("HKLM")),("disabled",json!(true)),("name",json!("SecurityHealth")),("path",json!("C:\\Windows\\SECURITYHEALTHSystray.exe")),("category",json!("Other"))] {
            let mut row=good.clone();row[field]=value;assert!(!startup_allowed(&row));
        }
    }
    #[test]
    fn recovery_rejects_other_registry_and_folder_paths() {
        let mut fake=FakeRegistry::default();let original=journal("R1",&mut fake);
        assert!(validate_journal(&original).is_ok());
        let mut j=original.clone();j.registry[0].hive="HKLM".into();assert!(validate_journal(&j).is_err());
        let mut j=original.clone();j.registry[0].path=r"Software\Other".into();assert!(validate_journal(&j).is_err());
        let mut j=original.clone();j.registry[0].value=Some((4,vec![0;4]));assert!(validate_journal(&j).is_err());
        let mut j=original;j.test_id="R4".into();j.registry.clear();j.touched.clear();
        for folder in [r"D:\",r"D:\WinSetupDevTest\..\Other",r"D:\Other",r"\\server\share\WinSetupDevTest"] {j.folder=Some(folder.into());assert!(validate_journal(&j).is_err());}
        j.folder=Some(r"D:\WinSetupDevTest".into());assert!(validate_journal(&j).is_ok());
    }
    #[test]
    fn cycles_restore_missing_keys_and_missing_values_exactly() {
        for id in ["R1","R2"] {for existed in [false,true] {
            let temp=tempfile::tempdir().unwrap();let mut fake=FakeRegistry::default();
            if existed {for (path,_) in registry_targets(id,None).unwrap() {fake.keys.insert(path);}}
            let j=journal(id,&mut fake);let before_keys=fake.keys.clone();
            let result=registry_cycle(temp.path(),&j,Instant::now(),&mut fake).unwrap();
            assert_eq!(result.status,Status::PASS);assert_eq!(fake.keys,before_keys);assert!(fake.values.is_empty());
            assert!(journal_paths(temp.path()).unwrap().is_empty());
        }}
    }
    #[test]
    fn partial_write_error_still_restores_original_bytes() {
        let temp=tempfile::tempdir().unwrap();let mut fake=FakeRegistry::default();
        let (path,name)=registry_targets("R1",None).unwrap().remove(0);fake.keys.insert(path.clone());
        fake.values.insert((path,name),(4,9u32.to_le_bytes().to_vec()));
        let before=fake.values.clone();let j=journal("R1",&mut fake);fake.fail_write=true;
        let result=registry_cycle(temp.path(),&j,Instant::now(),&mut fake).unwrap();
        assert_eq!(result.status,Status::FAIL);assert_eq!(fake.values,before);assert_eq!(fake.undos,1);
        assert!(journal_paths(temp.path()).unwrap().is_empty());
    }
    #[test]
    fn failed_rollback_keeps_durable_snapshot_and_manual_details() {
        let temp=tempfile::tempdir().unwrap();let mut fake=FakeRegistry::default();let j=journal("R1",&mut fake);fake.fail_undo=true;
        let result=registry_cycle(temp.path(),&j,Instant::now(),&mut fake).unwrap();
        assert_eq!(result.status,Status::FAIL);assert!(result.summary.contains("ОТКАТ НЕ ЗАВЕРШЁН"));assert!(result.technical.contains(&j.registry[0].path));
        let paths=journal_paths(temp.path()).unwrap();assert_eq!(paths.len(),1);
        let saved=read_journal(&paths[0]).unwrap();assert_eq!(saved.touched,vec![true]);
        fake.fail_undo=false;restore_saved(&paths[0],&saved,&mut fake).unwrap();
        assert!(fake.keys.is_empty());assert!(fake.values.is_empty());assert!(!paths[0].exists());
    }
    #[test]
    fn no_mutation_without_snapshot_or_after_timeout() {
        let temp=tempfile::tempdir().unwrap();let root=temp.path().join("not-a-directory");fs::write(&root,"x").unwrap();
        let mut fake=FakeRegistry::default();let j=journal("R1",&mut fake);
        assert!(registry_cycle(&root,&j,Instant::now(),&mut fake).is_err());assert_eq!(fake.writes,0);
        let result=registry_cycle(temp.path(),&j,Instant::now()-Duration::from_secs(61),&mut fake).unwrap();
        assert_eq!(result.status,Status::FAIL);assert_eq!(fake.writes,0);assert_eq!(fake.undos,0);
        assert!(journal_paths(temp.path()).unwrap().is_empty());
    }
    #[test]
    fn untouched_external_change_is_not_overwritten_by_rollback() {
        let temp=tempfile::tempdir().unwrap();let mut fake=FakeRegistry::default();let j=journal("R1",&mut fake);
        let row=&j.registry[0];fake.keys.insert(row.path.clone());fake.values.insert((row.path.clone(),row.name.clone()),(4,8u32.to_le_bytes().to_vec()));
        let before=fake.values.clone();let result=registry_cycle(temp.path(),&j,Instant::now(),&mut fake).unwrap();
        assert_eq!(result.status,Status::FAIL);assert_eq!(fake.values,before);assert_eq!(fake.writes,0);assert_eq!(fake.undos,0);
        assert_eq!(journal_paths(temp.path()).unwrap().len(),1);
    }
    #[test]
    fn folder_guard_rejects_missing_wrong_marker_and_foreign_files() {
        let temp=tempfile::tempdir().unwrap();let marker=temp.path().join(MARKER_NAME);
        assert!(checked_marker(temp.path(),"ours").is_err());
        fs::write(&marker,"foreign").unwrap();assert!(checked_marker(temp.path(),"ours").is_err());
        fs::write(&marker,"ours").unwrap();assert_eq!(checked_marker(temp.path(),"ours").unwrap(),marker);
        let foreign=temp.path().join("user-document.txt");fs::write(&foreign,"keep").unwrap();
        assert!(checked_marker(temp.path(),"ours").is_err());
        assert_eq!(fs::read_to_string(&foreign).unwrap(),"keep");assert!(marker.exists());
    }
    #[test]
    fn report_rotation_never_deletes_pending_rollback() {
        let temp=tempfile::tempdir().unwrap();let mut fake=FakeRegistry::default();let j=journal("R1",&mut fake);
        let path=write_journal(temp.path(),&j).unwrap();
        for n in 1..=7 {fs::write(temp.path().join("logs").join(format!("devtest-20261012-12000{n}.json")),"{}").unwrap();}
        retain_reports(&temp.path().join("logs")).unwrap();
        assert!(path.exists());assert_eq!(read_journal(&path).unwrap().id,j.id);
    }
}