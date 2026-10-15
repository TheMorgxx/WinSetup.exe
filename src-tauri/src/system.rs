use anyhow::{ensure, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    io::Read,
    os::windows::process::CommandExt,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
#[derive(Debug)]
pub(crate) struct ReadTimeout(pub String);
impl std::fmt::Display for ReadTimeout {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {write!(f,"Истёк тайм-аут команды чтения: {}",self.0)}
}
impl std::error::Error for ReadTimeout {}
#[derive(Debug)]
struct ReadCancelled;
impl std::fmt::Display for ReadCancelled {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.write_str("Проверка остановлена пользователем")}
}
impl std::error::Error for ReadCancelled {}
pub(crate) fn read_interrupted(err:&anyhow::Error)->bool {
    err.is::<ReadTimeout>() || err.is::<ReadCancelled>()
}
fn check_read_cancel(cancel:Option<&AtomicBool>)->Result<()> {
    if cancel.is_some_and(|c|c.load(Ordering::SeqCst)) {return Err(ReadCancelled.into());}
    Ok(())
}
fn retry_read<T>(mut read:impl FnMut()->Result<T>,cancel:Option<&AtomicBool>)->Result<T> {
    check_read_cancel(cancel)?;
    match read() {
        Err(err) if err.is::<ReadTimeout>() => {check_read_cancel(cancel)?;read()},
        result => result,
    }
}
fn raw_command(exe: &str, args: &[String], timeout: Option<Duration>) -> Result<(bool, Option<i32>, String, String)> {
    raw_command_cancellable(exe,args,timeout,None)
}
fn raw_command_cancellable(exe:&str,args:&[String],timeout:Option<Duration>,cancel:Option<&AtomicBool>)->Result<(bool,Option<i32>,String,String)> {
    check_read_cancel(cancel)?;
    let mut child = Command::new(exe)
        .args(args)
        .creation_flags(0x08000000)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Не удалось запустить {}", exe))?;
    let drain = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut out = vec![];
            let mut b = [0; 8192];
            loop {
                let n = pipe.read(&mut b).unwrap_or(0);
                if n == 0 {
                    break;
                }
                if out.len() < 4 * 1024 * 1024 {
                    let keep = n.min(4 * 1024 * 1024 - out.len());
                    out.extend_from_slice(&b[..keep]);
                }
            }
            String::from_utf8_lossy(&out).to_string()
        })
    };
    let stdout = drain(Box::new(child.stdout.take().unwrap()));
    let stderr = drain(Box::new(child.stderr.take().unwrap()));
    let began = std::time::Instant::now();
    let status = loop {
        if let Err(err)=check_read_cancel(cancel) {
            let _=child.kill();let _=child.wait();break Err(err);
        }
        match child.try_wait() {
            Ok(Some(s)) => break Ok(s),
            Ok(None) if timeout.map(|limit| began.elapsed() >= limit).unwrap_or(false) => {
                let _ = child.kill(); let _ = child.wait();
                break Err(ReadTimeout(exe.into()).into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => {
                let _ = child.kill(); let _ = child.wait();
                break Err(e.into());
            }
        }
    };
    let status = status?;
    while !stdout.is_finished() || !stderr.is_finished() {
        check_read_cancel(cancel)?;
        if timeout.is_some_and(|limit|began.elapsed()>=limit) {return Err(ReadTimeout(exe.into()).into());}
        std::thread::sleep(Duration::from_millis(100));
    }
    let out = stdout.join().map_err(|_| anyhow::anyhow!("Ошибка чтения stdout"))?;
    let err = stderr.join().map_err(|_| anyhow::anyhow!("Ошибка чтения stderr"))?;
    Ok((status.success(), status.code(), out, err))
}
#[derive(Debug)]
pub struct CommandResult {
    pub success: bool,
    pub code: Option<i32>,
    pub output: String,
}
pub fn command_result(exe: &str, args: &[String]) -> Result<CommandResult> {
    // Установщики не завершаются принудительно: отмена профиля действует между задачами.
    let (success, code, out, err) = raw_command(exe, args, None)?;
    Ok(CommandResult {success, code, output: format!("{out}\n{err}")})
}
pub fn command(exe: &str, args: &[String]) -> Result<(bool, String)> {
    let result = command_result(exe, args)?;
    Ok((result.success, result.output))
}
pub fn compact_output(output: &str) -> String {
    let ansi = regex::Regex::new(r"\x1b\[[0-9;?]*[ -/]*[@-~]").unwrap();
    let clean = ansi.replace_all(output, "");
    let chars: Vec<char> = clean.chars().filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t')).collect();
    if chars.len() <= 6000 {return chars.into_iter().collect::<String>().trim().into();}
    format!("{}\n… Длинный вывод сокращён; начало и конец сохранены …\n{}",
        chars[..1400].iter().collect::<String>().trim(),
        chars[chars.len()-3600..].iter().collect::<String>().trim())
}
fn ps_with_timeout(script: &str, input: &Value, timeout: Option<Duration>) -> Result<Value> {
    ps_cancellable(script,input,timeout,None)
}
fn ps_cancellable(script:&str,input:&Value,timeout:Option<Duration>,cancel:Option<&AtomicBool>)->Result<Value> {
    let data = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(input)?);
    let script=format!("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);try {{$i=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{data}'))|ConvertFrom-Json);{script}}} catch {{[Console]::Error.WriteLine($_.Exception.Message);exit 1}}");
    let encoded = base64::engine::general_purpose::STANDARD.encode(
        script.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
    let (ok, _, out, err) = raw_command_cancellable(
        &format!("{}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",std::env::var("WINDIR")?),
        &["-NoProfile".into(),"-NonInteractive".into(),"-EncodedCommand".into(),encoded],timeout,cancel)?;
    ensure!(ok, "{}", compact_output(&format!("{out}\n{err}")));
    let out = out.trim_start_matches('\u{feff}').trim();
    if out.is_empty() {return Ok(Value::Null);}
    serde_json::from_str(out).with_context(|| format!("Некорректный ответ PowerShell: {}", compact_output(out)))
}
pub fn ps(script: &str, input: &Value) -> Result<Value> {ps_with_timeout(script,input,None)}
#[cfg(test)]
fn ps_readonly(script: &str, input: &Value) -> Result<Value> {retry_read(||ps_cancellable(script,input,Some(Duration::from_secs(30)),None),None)}
pub fn array(v: Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a,
        Value::Null => vec![],
        x => vec![x],
    }
}
pub fn firefox_running() -> Result<bool> {
    Ok(ps(
        "[bool](Get-Process firefox -ErrorAction SilentlyContinue)|ConvertTo-Json",
        &json!({}),
    )?
    .as_bool()
    .unwrap_or(true))
}
pub fn tool(name: &str) -> String {
    if name == "git" {
        let p = PathBuf::from(std::env::var("ProgramFiles").unwrap_or_default())
            .join("Git/cmd/git.exe");
        if p.exists() {
            return p.display().to_string();
        }
    }
    format!("{}.exe", name)
}
pub fn inventory() -> Result<Value> {
    let v = ps(
        r#"$os=Get-CimInstance Win32_OperatingSystem;$cv=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion';$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);$apps=@(Get-AppxPackage|Select-Object Name,PackageFullName,IsFramework,NonRemovable,SignatureKind);$disks=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'|Select-Object DeviceID,FreeSpace,Size);@{admin=$admin;windows=$os.Caption;build=$os.BuildNumber;version=$cv.DisplayVersion;architecture=$os.OSArchitecture;winget=[bool](Get-Command winget -ErrorAction SilentlyContinue);git=[bool]((Get-Command git -ErrorAction SilentlyContinue) -or (Test-Path "$env:ProgramFiles\Git\cmd\git.exe"));disks=$disks;apps=$apps}|ConvertTo-Json -Depth 5"#,
        &json!({}),
    )?;
    Ok(v)
}
// Источники и границы таблицы: fixes3-report.md. Не использовать частичные имена.
fn registry_identity(p:&crate::model::Program)->Option<(&'static [&'static str],&'static [&'static str])> {
    if p.source!="winget" {return None;}
    Some(match p.id.as_str() {
        "Valve.Steam" => (&["Steam"], &["Valve Corporation"]),
        "Mozilla.Firefox" => (&[], &["Mozilla"]),
        "Telegram.TelegramDesktop" => (&["Telegram Desktop"], &["Telegram FZ-LLC"]),
        "Git.Git" => (&["Git"], &["The Git Development Community"]),
        "Discord.Discord" => (&["Discord"], &["Discord Inc.","Discord Inc"]),
        "Anthropic.Claude" => (&["Claude"], &["Anthropic","Anthropic, PBC","Anthropic PBC"]),
        "Asus.ArmouryCrate" => (&["ARMOURY CRATE","Armoury Crate"], &["ASUSTeK COMPUTER INC.","ASUSTeK COMPUTER INC"]),
        _ => return None,
    })
}
fn registry_matches(p: &crate::model::Program, app: &Value) -> bool {
    let name=app["name"].as_str().unwrap_or("").trim();
    let publisher=app["publisher"].as_str().unwrap_or("").trim().to_ascii_lowercase();
    let version=app["version"].as_str().unwrap_or("").trim();
    if !p.version.is_empty() && version!=p.version {return false;}
    if p.source=="direct" {return !p.detect_name.is_empty() && name.eq_ignore_ascii_case(&p.detect_name);}
    let Some((names,publishers))=registry_identity(p) else {return false;};
    let exact_name=names.iter().any(|n|name.eq_ignore_ascii_case(n)) ||
        (p.id=="Mozilla.Firefox" && ["x64","x86","arm64"].iter().any(|arch|
            ["en-US","ru","en-GB","zh-CN","de","el","ja","es-ES","es-MX","nb-NO"].iter()
                .any(|locale|name.eq_ignore_ascii_case(&format!("Mozilla Firefox ({arch} {locale})")))));
    exact_name && publishers.iter().any(|s|s.eq_ignore_ascii_case(&publisher))
}
fn winget_list_evidence(output: &str, p: &crate::model::Program) -> Option<String> {
    let mut table=false;
    for line in output.lines() {
        let line=line.trim();
        if line.len()>=3 && line.chars().all(|c|c=='-') { table=true;continue; }
        if !table { continue; }
        let fields=line.split_whitespace().collect::<Vec<_>>();
        if !fields.last().map(|s|s.eq_ignore_ascii_case(&p.source)).unwrap_or(false) {continue;}
        for index in 1..fields.len() {
            // После Id идут Version, необязательная Available и Source.
            let tail=fields.len()-index;
            if ![3,4].contains(&tail) || !fields[index].eq_ignore_ascii_case(&p.id) {continue;}
            let version=fields[index+1];
            let version_like=|v:&str|v.chars().next().map(|c|c.is_ascii_digit()).unwrap_or(false)
                || v.eq_ignore_ascii_case("Unknown") || v.eq_ignore_ascii_case("Неизвестно");
            if !version_like(version) || (tail==4 && !version_like(fields[index+2])) {continue;}
            if !p.version.is_empty() && version!=p.version {continue;}
            return Some(format!("winget list --id {} --exact --source {}: найдено; имя: {}; версия: {}",
                p.id,p.source,fields[..index].join(" "),version));
        }
    }
    None
}
#[cfg(test)]
fn winget_list_matches(output: &str, p: &crate::model::Program) -> bool {
    winget_list_evidence(output,p).is_some()
}
fn latest_discord_app(root: &std::path::Path) -> Option<PathBuf> {
    std::fs::read_dir(root).ok()?.filter_map(|e|e.ok()).filter_map(|e|{
        if !e.file_type().ok()?.is_dir() {return None;}
        let name=e.file_name().to_str()?.to_owned();
        let version=name.strip_prefix("app-")?.split('.').map(str::parse::<u32>).collect::<std::result::Result<Vec<_>,_>>().ok()?;
        if version.len()<3 || !e.path().join("Discord.exe").is_file() {return None;}
        Some((version,e.path()))
    }).max_by(|a,b|a.0.cmp(&b.0)).map(|x|x.1)
}
fn vencord_at(discord: &std::path::Path, data: &std::path::Path) -> Result<bool> {
    // Read-only verification of the stable Discord patch written by Vencord/Installer.
    // A downloaded patcher alone is insufficient; the active app.asar must require it.
    let Some(app)=latest_discord_app(discord) else {return Ok(false)};
    let patcher=data.join("dist/patcher.js");
    if !patcher.is_file() || std::fs::metadata(&patcher)?.len()==0 {return Ok(false);}
    let resources=app.join("resources");
    if !resources.join("_app.asar").is_file() {return Ok(false);}
    let path=resources.join("app.asar");
    if !path.is_file() || std::fs::metadata(&path)?.len()>1024*1024 {return Ok(false);}
    let bytes=std::fs::read(path)?;
    let text=String::from_utf8_lossy(&bytes);
    let require=regex::Regex::new(r#"require\(("(?:[^"\\]|\\.)*")\)"#)?;
    let expected=patcher.canonicalize()?;
    for capture in require.captures_iter(&text) {
        if let Ok(value)=serde_json::from_str::<String>(&capture[1]) {
            if PathBuf::from(value).canonicalize().ok().as_ref()==Some(&expected) {return Ok(true);}
        }
    }
    Ok(false)
}
pub fn installed(p: &crate::model::Program) -> Result<bool> {
    installed_check(p,&mut None,None)
}
pub fn installed_evidence(p: &crate::model::Program) -> Result<Option<String>> {
    installed_evidence_cancellable(p,None)
}
pub(crate) fn installed_evidence_cancellable(p:&crate::model::Program,cancel:Option<&AtomicBool>)->Result<Option<String>> {
    let mut evidence=None;
    if installed_check(p,&mut evidence,cancel)? {
        Ok(Some(evidence.unwrap_or_else(||"Проверка Vencord: подтверждён загрузчик модификации в текущей версии Discord и файл patcher.js".into())))
    } else { Ok(None) }
}
pub(crate) fn uninstall_evidence(p:&crate::model::Program,cancel:Option<&AtomicBool>)->Result<Option<String>> {
    check_read_cancel(cancel)?;
    ensure!(p.source=="direct" || registry_identity(p).is_some(),"Для {} нет подтверждённого правила Uninstall",p.name);
    let apps=retry_read(||ps_cancellable(r#"
$roots=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
$apps=@(foreach($root in $roots){if(Test-Path -LiteralPath $root){Get-ItemProperty ($root+'\*') -ErrorAction Stop|ForEach-Object {@{name=[string]$_.DisplayName;publisher=[string]$_.Publisher;version=[string]$_.DisplayVersion}}}})
ConvertTo-Json -InputObject $apps -Depth 3
"#,&json!({}),Some(Duration::from_secs(30)),cancel),cancel)?;
    Ok(array(apps).iter().find(|a|registry_matches(p,a)).map(|app|format!(
        "Uninstall: {}; издатель: {}; версия: {}; точное совпадение {}",
        app["name"].as_str().unwrap_or(""),app["publisher"].as_str().filter(|s|!s.is_empty()).unwrap_or("не указан"),
        app["version"].as_str().filter(|s|!s.is_empty()).unwrap_or("не указана"),
        if p.source=="direct" {"detect_name"} else {"имени и разрешённого издателя"})))
}
fn installed_check(p: &crate::model::Program, evidence: &mut Option<String>,cancel:Option<&AtomicBool>) -> Result<bool> {
    check_read_cancel(cancel)?;
    if p.source=="git" {return Ok(false);}
    if p.source=="winget" && p.id=="Vendicated.Vencord" {
        ensure!(p.version.is_empty(),"Версия установщика Vencord не подтверждает версию модификации Discord; автоматическая проверка закреплённой версии недоступна");
        let local=std::env::var_os("LOCALAPPDATA").context("Не найден LOCALAPPDATA для проверки Discord")?;
        let data=if let Some(path)=std::env::var_os("VENCORD_USER_DATA_DIR").filter(|s|!s.is_empty()) {PathBuf::from(path)}
            else if let Some(path)=std::env::var_os("DISCORD_USER_DATA_DIR").filter(|s|!s.is_empty()) {PathBuf::from(path).join("../VencordData")}
            else {PathBuf::from(std::env::var_os("XDG_CONFIG_HOME").filter(|s|!s.is_empty()).or_else(||std::env::var_os("APPDATA")).context("Не найден каталог настроек для проверки Vencord")?).join("Vencord")};
        return vencord_at(&PathBuf::from(local).join("Discord"),&data);
    }
    let mut registry_error=None;
    if p.source=="direct" || registry_identity(p).is_some() {
        match uninstall_evidence(p,cancel) {
            Ok(Some(found)) => {*evidence=Some(found);return Ok(true);},
            Ok(None) => {},
            Err(e) if read_interrupted(&e) => return Err(e),
            Err(e) => registry_error=Some(e),
        }
        if p.source=="direct" {return match registry_error {Some(e)=>Err(e),None=>Ok(false)};}
    }
    let args=vec!["list".into(),"--id".into(),p.id.clone(),"--exact".into(),"--source".into(),p.source.clone(),
        "--accept-source-agreements".into(),"--disable-interactivity".into()];
    let (ok,code,out,err)=retry_read(||raw_command_cancellable("winget.exe",&args,Some(Duration::from_secs(60)),cancel),cancel)?;
    if ok {
        *evidence=winget_list_evidence(&out,p);
        if evidence.is_some() {return Ok(true);}
        let mut any_version=p.clone();any_version.version.clear();
        if winget_list_evidence(&out,&any_version).is_some() {return Ok(false);}
    }
    // APPINSTALLER_CLI_ERROR_NO_APPLICATIONS_FOUND: absence, not a failed system probe.
    if code.map(|c|c as u32)==Some(0x8A150014) {
        return match registry_error {Some(e)=>Err(e),None=>Ok(false)};
    }
    ensure!(ok,"Не удалось проверить {} через winget list (код {:?}): {}",p.name,code,compact_output(&format!("{out}\n{err}")));
    if let Some(e)=registry_error {return Err(e);}
    // Частичное совпадение или нераспознанная строка не доказывают установку.
    Ok(false)
}
pub fn remove_app(name: &str) -> Result<String> {
    ensure!(crate::model::removable(name), "Защищённый пакет");
    ps(r#"$p=@(Get-AppxPackage|Where-Object {$_.Name -eq $i.name});if(!$p){'Пакет уже отсутствует'|ConvertTo-Json;exit};foreach($a in $p){if($a.IsFramework -or $a.NonRemovable -or $a.SignatureKind.ToString() -eq 'System'){throw 'Защищённый пакет: удаление запрещено'};Remove-AppxPackage -Package $a.PackageFullName};if(Get-AppxPackage|Where-Object {$_.Name -eq $i.name}){throw 'Постпроверка удаления не пройдена: пакет всё ещё установлен'};'Пакет удалён у текущего пользователя'|ConvertTo-Json"#,&json!({"name":name})).map(|v|v.as_str().map(str::to_string).unwrap_or_else(||v.to_string()))
}
const RESTORE_DESCRIPTION: &str = "WinSetup";
/// Разбирает WMI-время "yyyymmddHHMMSS.ffffff±UUU" (UUU — смещение от UTC в минутах).
pub(crate) fn wmi_parts(s: &str) -> Option<(chrono::NaiveDateTime, chrono::FixedOffset)> {
    let s = s.trim();
    if !s.is_ascii() || s.len() != 25 || &s[14..15] != "." {
        return None;
    }
    let naive = chrono::NaiveDateTime::parse_from_str(&s[..14], "%Y%m%d%H%M%S").ok()?;
    let micros: u32 = s[15..21].parse().ok()?;
    let naive = chrono::Timelike::with_nanosecond(&naive, micros.checked_mul(1000)?)?;
    let minutes: i32 = s[22..25].parse().ok()?;
    let sign = match &s[21..22] {
        "+" => 1,
        "-" => -1,
        _ => return None,
    };
    Some((naive, chrono::FixedOffset::east_opt(sign * minutes * 60)?))
}
/// Время создания точки попадает в [start, now + 5 мин]. Строка WMI у точек восстановления
/// иногда содержит смещение "-000" при локальном времени, поэтому проверяются оба толкования:
/// с учётом указанного смещения и как локальное время. Устаревшую точку это не пропустит:
/// новизна дополнительно подтверждается номером SequenceNumber (см. fresh_sequence).
fn created_in_window(
    created: &str,
    start: chrono::DateTime<chrono::Local>,
    now: chrono::DateTime<chrono::Local>,
) -> bool {
    use chrono::TimeZone;
    let Some((naive, offset)) = wmi_parts(created) else {
        return false;
    };
    let end = now + chrono::Duration::minutes(5);
    let inside = |t: chrono::DateTime<chrono::Local>| t >= start && t <= end;
    let by_offset = offset
        .from_local_datetime(&naive)
        .single()
        .map(|t| t.with_timezone(&chrono::Local));
    let as_local = chrono::Local.from_local_datetime(&naive).earliest();
    by_offset.map(inside).unwrap_or(false) || as_local.map(inside).unwrap_or(false)
}
/// Номер новой точки: описание уже отфильтровано, номер больше, чем был до Checkpoint-Computer,
/// и время создания не раньше начала запуска.
fn fresh_sequence(
    points: Value,
    before: u64,
    start: chrono::DateTime<chrono::Local>,
    now: chrono::DateTime<chrono::Local>,
) -> Option<u64> {
    array(points)
        .iter()
        .filter_map(|p| {
            let seq = p["seq"].as_u64()?;
            if seq > before && created_in_window(p["created"].as_str()?, start, now) {
                Some(seq)
            } else {
                None
            }
        })
        .max()
}
pub fn restore_point(started: chrono::DateTime<chrono::Local>) -> Result<String> {
    let started = chrono::Timelike::with_nanosecond(&started, 0).unwrap_or(started);
    let v = ps(
        r#"$before=0;try{$b=@(Get-ComputerRestorePoint|Sort-Object SequenceNumber|Select-Object -Last 1);if($b.Count -gt 0 -and $b[0]){$before=[int]$b[0].SequenceNumber}}catch{};$cw=$null;try{Checkpoint-Computer -Description $i.desc -RestorePointType MODIFY_SETTINGS -WarningVariable cw -WarningAction SilentlyContinue}catch{if($_.FullyQualifiedErrorId -like 'ServiceDisabled*'){throw 'Не удалось создать точку восстановления: необходимая служба Windows отключена (ServiceDisabled). Проверьте Защиту системы. WinSetup не включает службы автоматически; продолжение без точки требует подтверждения.'};throw};$w=@();foreach($m in @($cw)){if($m){$w+=[string]$m}};$points=@();$err='';try{$points=@(Get-ComputerRestorePoint|Where-Object{$_.Description -eq $i.desc}|ForEach-Object{@{seq=[int]$_.SequenceNumber;created=[string]$_.CreationTime}})}catch{$err=[string]$_.Exception.Message};@{before=$before;points=@($points);warnings=@($w);error=$err}|ConvertTo-Json -Depth 4"#,
        &json!({"desc":RESTORE_DESCRIPTION}),
    )?;
    let warnings = v["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|x| x.as_str())
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .collect::<Vec<_>>()
        .join(" | ");
    let check_error = v["error"].as_str().unwrap_or("").trim().to_string();
    let before = v["before"].as_u64().unwrap_or(0);
    if let Some(seq) = fresh_sequence(v["points"].clone(), before, started, chrono::Local::now()) {
        let mut msg = format!(
            "Точка восстановления создана и подтверждена через Get-ComputerRestorePoint (№{})",
            seq
        );
        if !warnings.is_empty() {
            msg.push_str(&format!(". Предупреждение Windows: {}", warnings));
        }
        return Ok(msg);
    }
    let mut msg = format!(
        "Точка восстановления «{}» не найдена в Get-ComputerRestorePoint после начала запуска. Возможные причины: лимит Windows (одна точка за 24 часа) или выключена защита системы; лимит и защита не изменяются",
        RESTORE_DESCRIPTION
    );
    if !warnings.is_empty() {
        msg.push_str(&format!(". Предупреждение Windows: {}", warnings));
    }
    if !check_error.is_empty() {
        msg.push_str(&format!(". Ошибка проверки точек: {}", check_error));
    }
    anyhow::bail!(msg)
}
pub fn startup() -> Result<Value> {
    let raw = ps(
        r#"$out=@();foreach($h in @('HKCU','HKLM')){foreach($cat in @('Run','Run32')){$p=if($cat -eq 'Run32'){"${h}:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"}else{"${h}:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"};if(Test-Path $p){$k=Get-Item $p;foreach($n in $k.GetValueNames()){$ap="${h}:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$cat";$state=$null;if(Test-Path $ap){$state=(Get-Item $ap).GetValue($n)};$out+=@{hive=$h;category=$cat;name=$n;path=$k.GetValue($n);disabled=($state -and $state[0] -in @(3,7))}}}}};foreach($h in @('HKCU','HKLM')){$p=if($h -eq 'HKCU'){[Environment]::GetFolderPath('Startup')}else{[Environment]::GetFolderPath('CommonStartup')};foreach($f in Get-ChildItem -LiteralPath $p -File -ErrorAction SilentlyContinue|Where-Object Name -ne 'desktop.ini'){$ap="${h}:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";$state=$null;if(Test-Path $ap){$state=(Get-Item $ap).GetValue($f.Name)};$out+=@{hive=$h;category='StartupFolder';name=$f.Name;path=$f.FullName;disabled=($state -and $state[0] -in @(3,7))}}};ConvertTo-Json -InputObject @($out) -Depth 4"#,
        &json!({}),
    )?;
    let mut rows = array(raw);
    for a in &mut rows {
        a["key"] = json!(crate::storage::hash(
            format!("{}:{}:{}", a["hive"], a["category"], a["name"]).as_bytes()
        )[..20]
            .to_string());
    }
    Ok(json!(rows))
}
#[derive(Clone, Serialize, Deserialize)]
pub struct RegUndo {
    pub hive: String,
    pub path: String,
    pub name: String,
    pub existed: bool,
    pub value: Option<(u32, Vec<u8>)>,
}
fn hive(s: &str) -> Result<winreg::RegKey> {
    match s {
        "HKCU" => Ok(winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)),
        "HKLM" => Ok(winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)),
        _ => anyhow::bail!("Неверный hive"),
    }
}
pub fn allowed_registry(h: &str, p: &str, n: &str) -> bool {
    if ["HKCU", "HKLM"].contains(&h)
        && ["Run", "Run32", "StartupFolder"].iter().any(|c| {
            p == format!(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\{}",
                c
            )
        })
    {
        return !n.is_empty() && !n.contains(['\\', '/', '\0']);
    }
    h == "HKCU"
        && [
            "notify_snip",
            "notify_discord",
            "notify_telegram",
            "suggestions",
        ]
        .iter()
        .any(|key| {
            tweak_values(key, "disabled")
                .unwrap_or_default()
                .iter()
                .any(|(path, name, _)| path == p && name == n)
        })
}
pub fn snapshot(h: &str, p: &str, n: &str) -> Result<RegUndo> {
    let root = hive(h)?;
    match root.open_subkey(p) {
        Ok(k) => Ok(RegUndo {
            hive: h.into(),
            path: p.into(),
            name: n.into(),
            existed: true,
            value: match k.get_raw_value(n) {
                Ok(v) => Some((v.vtype as u32, v.bytes.to_vec())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e.into()),
            },
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RegUndo {
            hive: h.into(),
            path: p.into(),
            name: n.into(),
            existed: false,
            value: None,
        }),
        Err(e) => Err(e.into()),
    }
}
pub fn write_reg(
    h: &str,
    p: &str,
    n: &str,
    bytes: Vec<u8>,
    kind: winreg::enums::RegType,
) -> Result<()> {
    ensure!(allowed_registry(h, p, n), "Действие с реестром запрещено");
    let (k, _) = hive(h)?.create_subkey(p)?;
    k.set_raw_value(
        n,
        &winreg::RegValue {
            bytes: bytes.clone().into(),
            vtype: kind,
        },
    )?;
    ensure!(
        k.get_raw_value(n)?.bytes == bytes,
        "Постпроверка реестра не пройдена"
    );
    Ok(())
}
pub fn undo_reg(r: &RegUndo) -> Result<()> {
    use winreg::enums::*;
    ensure!(
        allowed_registry(&r.hive, &r.path, &r.name),
        "Действие отката запрещено"
    );
    if let Some((t, b)) = &r.value {
        let kind = match t {
            0 => REG_NONE,
            1 => REG_SZ,
            2 => REG_EXPAND_SZ,
            3 => REG_BINARY,
            4 => REG_DWORD,
            5 => REG_DWORD_BIG_ENDIAN,
            6 => REG_LINK,
            7 => REG_MULTI_SZ,
            8 => REG_RESOURCE_LIST,
            9 => REG_FULL_RESOURCE_DESCRIPTOR,
            10 => REG_RESOURCE_REQUIREMENTS_LIST,
            11 => REG_QWORD,
            _ => anyhow::bail!("Тип реестра неизвестен"),
        };
        write_reg(&r.hive, &r.path, &r.name, b.clone(), kind)
    } else {
        let root = hive(&r.hive)?;
        if let Ok(k) = root.open_subkey_with_flags(&r.path, KEY_SET_VALUE) {
            match k.delete_value(&r.name) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        if !r.existed {
            let _ = root.delete_subkey(&r.path);
        }
        Ok(())
    }
}
pub fn tweak_values(key: &str, state: &str) -> Result<Vec<(String, String, u32)>> {
    let root = "Software\\Microsoft\\Windows\\CurrentVersion";
    let val = if state == "enabled" { 1 } else { 0 };
    let app = match key {
        "notify_snip" => Some("Microsoft.ScreenSketch_8wekyb3d8bbwe!App"),
        "notify_discord" => Some("com.squirrel.Discord.Discord"),
        "notify_telegram" => Some("Telegram.TelegramDesktop"),
        _ => None,
    };
    if let Some(a) = app {
        return Ok(vec![(
            format!("{}\\Notifications\\Settings\\{}", root, a),
            "Enabled".into(),
            val,
        )]);
    }
    ensure!(key == "suggestions", "Неизвестное изменение");
    let mut rows = vec![];
    for n in [
        "SoftLandingEnabled",
        "SubscribedContent-338389Enabled",
        "SubscribedContent-310093Enabled",
        "SubscribedContent-338388Enabled",
        "SubscribedContent-353694Enabled",
        "SubscribedContent-353696Enabled",
        "SystemPaneSuggestionsEnabled",
        "SilentInstalledAppsEnabled",
        "ContentDeliveryAllowed",
    ] {
        rows.push((format!("{}\\ContentDeliveryManager", root), n.into(), val));
    }
    for (p, n) in [
        ("UserProfileEngagement", "ScoobeSystemSettingEnabled"),
        ("Explorer\\Advanced", "ShowSyncProviderNotifications"),
        ("Privacy", "TailoredExperiencesWithDiagnosticDataEnabled"),
    ] {
        rows.push((format!("{}\\{}", root, p), n.into(), val));
    }
    Ok(rows)
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Mode {
    device: [u16; 32],
    spec: u16,
    driver: u16,
    size: u16,
    extra: u16,
    fields: u32,
    x: i32,
    y: i32,
    orientation: u32,
    fixed: u32,
    color: i16,
    duplex: i16,
    yres: i16,
    tt: i16,
    collate: i16,
    form: [u16; 32],
    pixels: u16,
    bits: u32,
    width: u32,
    height: u32,
    flags: u32,
    hz: u32,
    icm: u32,
    intent: u32,
    media: u32,
    dither: u32,
    r1: u32,
    r2: u32,
    panw: u32,
    panh: u32,
}
#[repr(C)]
struct Device {
    cb: u32,
    name: [u16; 32],
    description: [u16; 128],
    flags: u32,
    id: [u16; 128],
    key: [u16; 128],
}
#[link(name = "user32")]
extern "system" {
    fn EnumDisplaySettingsW(name: *const u16, index: u32, mode: *mut Mode) -> i32;
    fn EnumDisplayDevicesW(name: *const u16, index: u32, dev: *mut Device, flags: u32) -> i32;
    fn ChangeDisplaySettingsExW(
        name: *const u16,
        mode: *mut Mode,
        hwnd: *mut std::ffi::c_void,
        flags: u32,
        param: *mut std::ffi::c_void,
    ) -> i32;
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn mode(name: &str, index: u32) -> Option<Mode> {
    let mut m: Mode = unsafe { std::mem::zeroed() };
    m.size = std::mem::size_of::<Mode>() as u16;
    let w = wide(name);
    if unsafe { EnumDisplaySettingsW(w.as_ptr(), index, &mut m) } != 0 {
        Some(m)
    } else {
        None
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Display {
    pub device: String,
    pub width: u32,
    pub height: u32,
    pub bits: u32,
    pub current: u32,
    pub maximum: u32,
    pub available: Vec<u32>,
}
#[derive(Debug, PartialEq)]
pub enum RefreshDecision {
    Skip(u32),
    Apply(u32),
}
impl RefreshDecision {
    pub fn message(&self) -> String {
        match self {
            Self::Skip(hz) => format!("Уже установлена максимальная частота {hz} Гц"),
            Self::Apply(hz) => format!("Установить максимальную частоту {hz} Гц"),
        }
    }
}
pub fn refresh_decision(d: &Display) -> Result<RefreshDecision> {
    ensure!(d.width > 0 && d.height > 0 && d.bits > 0 && d.current > 1,
        "Не удалось определить текущий режим дисплея");
    ensure!(d.maximum >= d.current && (d.maximum == d.current || d.available.contains(&d.maximum)),
        "Максимальный режим больше не доступен: перечитайте список режимов");
    // current и available относятся к одним разрешению, глубине цвета и флагам.
    Ok(if d.current == d.maximum { RefreshDecision::Skip(d.current) }
       else { RefreshDecision::Apply(d.maximum) })
}
pub fn displays() -> Vec<Display> {
    let mut out = vec![];
    for i in 0..32 {
        let mut d: Device = unsafe { std::mem::zeroed() };
        d.cb = std::mem::size_of::<Device>() as u32;
        if unsafe { EnumDisplayDevicesW(std::ptr::null(), i, &mut d, 0) } == 0 {
            break;
        }
        if d.flags & 1 == 0 {
            continue;
        }
        let name =
            String::from_utf16_lossy(&d.name[..d.name.iter().position(|x| *x == 0).unwrap_or(32)]);
        if let Some(cur) = mode(&name, u32::MAX) {
            let mut hz = vec![];
            for j in 0..10000 {
                if let Some(m) = mode(&name, j) {
                    if m.width == cur.width
                        && m.height == cur.height
                        && m.bits == cur.bits
                        && m.flags == cur.flags
                        && m.hz > 1
                    {
                        hz.push(m.hz)
                    }
                } else {
                    break;
                }
            }
            if cur.hz > 1 { hz.push(cur.hz); }
            hz.sort();
            hz.dedup();
            out.push(Display {
                device: name,
                width: cur.width,
                height: cur.height,
                bits: cur.bits,
                current: cur.hz,
                maximum: *hz.last().unwrap_or(&cur.hz),
                available: hz,
            });
        }
    }
    out
}
pub fn set_display(d: &Display, hz: u32) -> Result<()> {
    let n = wide(&d.device);
    for attempt in 0..2 {
        let cur = mode(&d.device, u32::MAX).context("Монитор недоступен")?;
        ensure!(cur.width == d.width && cur.height == d.height && cur.bits == d.bits,
            "Разрешение или глубина цвета изменились: пересоздайте план");
        if cur.hz == hz { return Ok(()); }
        let mut chosen = None;
        // Индекс 0 заново запрашивает список режимов, в том числе при повторной попытке.
        for j in 0..10000 {
            if let Some(m) = mode(&d.device, j) {
                if m.width == d.width && m.height == d.height && m.bits == d.bits
                    && m.flags == cur.flags && m.hz == hz {
                    chosen = Some(m);
                    break;
                }
            } else { break; }
        }
        let mut m = match chosen {
            Some(m) => m,
            None if attempt == 0 => continue,
            None => anyhow::bail!("Режим больше не доступен после повторного чтения списка"),
        };
        m.fields |= 0x400000;
        let tested = unsafe { ChangeDisplaySettingsExW(n.as_ptr(), &mut m,
            std::ptr::null_mut(), 2, std::ptr::null_mut()) };
        if tested != 0 && attempt == 0 { continue; }
        ensure!(tested == 0, "CDS_TEST: режим не поддерживается после повторного чтения (код {tested})");
        let applied = unsafe { ChangeDisplaySettingsExW(n.as_ptr(), &mut m,
            std::ptr::null_mut(), 1, std::ptr::null_mut()) };
        if applied == -2 && attempt == 0 { continue; } // DISP_CHANGE_BADMODE
        ensure!(applied == 0, "Не удалось применить частоту (код {applied})");
        let actual = mode(&d.device, u32::MAX).context("Монитор недоступен при постпроверке")?;
        ensure!(actual.hz == hz && actual.width == d.width && actual.height == d.height && actual.bits == d.bits,
            "Постпроверка режима дисплея не прошла");
        return Ok(());
    }
    anyhow::bail!("Режим больше не доступен после повторного чтения списка")
}
pub fn internet() -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    ("www.microsoft.com", 443)
        .to_socket_addrs()
        .ok()
        .map(|a| {
            a.take(2)
                .any(|s| TcpStream::connect_timeout(&s, Duration::from_secs(3)).is_ok())
        })
        .unwrap_or(false)
}
#[cfg(test)]
mod restore_point_tests {
    use super::*;
    use chrono::{Duration, Local, TimeZone};
    fn wmi(t: chrono::DateTime<Local>, offset_label: Option<&str>) -> String {
        let minutes = t.offset().local_minus_utc() / 60;
        let label = offset_label.map(str::to_string).unwrap_or_else(|| {
            format!("{}{:03}", if minutes < 0 { '-' } else { '+' }, minutes.abs())
        });
        format!("{}.000000{}", t.format("%Y%m%d%H%M%S"), label)
    }
    #[test]
    fn parses_wmi_string() {
        let (n, o) = wmi_parts("20261012143000.000000-000").unwrap();
        assert_eq!(n.format("%Y-%m-%d %H:%M:%S").to_string(), "2026-10-12 14:30:00");
        assert_eq!(o.local_minus_utc(), 0);
        let (n, o) = wmi_parts("20261012143000.250000+180").unwrap();
        assert_eq!(o.local_minus_utc(), 3 * 3600);
        assert_eq!(chrono::Timelike::nanosecond(&n), 250_000_000);
        assert_eq!(wmi_parts("20261012143000.000000-300").unwrap().1.local_minus_utc(), -5 * 3600);
        let utc = o.from_local_datetime(&n).single().unwrap();
        assert_eq!(utc.with_timezone(&chrono::Utc).format("%H:%M:%S").to_string(), "11:30:00");
        assert!(wmi_parts("мусор").is_none());
        assert!(wmi_parts("20261012143000.000000*000").is_none());
        assert!(wmi_parts("20261312143000.000000+000").is_none());
    }
    #[test]
    fn window_uses_timezone() {
        let now = Local::now();
        let start = now - Duration::seconds(30);
        assert!(created_in_window(&wmi(now - Duration::seconds(10), None), start, now));
        assert!(created_in_window(&wmi(now - Duration::seconds(10), Some("-000")), start, now));
        assert!(!created_in_window(&wmi(now - Duration::hours(2), None), start, now));
        assert!(!created_in_window(&wmi(now + Duration::hours(1), None), start, now));
        assert!(!created_in_window("не дата", start, now));
    }
    #[test]
    fn fresh_needs_new_sequence() {
        let now = Local::now();
        let start = now - Duration::seconds(30);
        let fresh = wmi(now - Duration::seconds(5), None);
        let points = json!([{"seq": 7, "created": fresh.clone()}]);
        assert_eq!(fresh_sequence(points.clone(), 6, start, now), Some(7));
        assert_eq!(fresh_sequence(points, 7, start, now), None);
        let single = json!({"seq": 9, "created": fresh});
        assert_eq!(fresh_sequence(single, 8, start, now), Some(9));
        let stale = json!([{"seq": 9, "created": wmi(now - Duration::hours(30), None)}]);
        assert_eq!(fresh_sequence(stale, 8, start, now), None);
    }
}
#[cfg(test)]
mod reliability_tests {
    use super::*;
    #[test]
    fn maximum_refresh_decides_skip_apply_or_error_without_system_calls() {
        let mut d=Display{device:"test".into(),width:1920,height:1080,bits:32,
            current:144,maximum:144,available:vec![60,144]};
        assert_eq!(refresh_decision(&d).unwrap(),RefreshDecision::Skip(144));
        assert_eq!(refresh_decision(&d).unwrap().message(),"Уже установлена максимальная частота 144 Гц");
        d.current=60;
        assert_eq!(refresh_decision(&d).unwrap(),RefreshDecision::Apply(144));
        d.available=vec![60];
        assert!(refresh_decision(&d).is_err());
        d.current=64;d.maximum=64;d.available.clear();
        assert_eq!(refresh_decision(&d).unwrap(),RefreshDecision::Skip(64));
        d.bits=0;
        assert!(refresh_decision(&d).is_err());
    }
    fn program(id:&str)->crate::model::Program {crate::model::defaults().programs.into_iter().find(|p|p.id==id).unwrap()}
    #[test]
    fn registry_requires_exact_application_publisher_and_version() {
        let mut p=program("Discord.Discord");
        let app=json!({"name":"Discord","publisher":"Discord Inc.","version":"1.0.9262"});
        assert!(registry_matches(&p,&app));
        assert!(!registry_matches(&p,&json!({"name":"Discord Updater","publisher":"Discord Inc.","version":"1.0.9262"})));
        assert!(!registry_matches(&p,&json!({"name":"Discord","publisher":"Unrelated company","version":"1.0.9262"})));
        p.version="1.0.9262".into();assert!(registry_matches(&p,&app));
        p.version="2.0".into();assert!(!registry_matches(&p,&app));
        let armoury=program("Asus.ArmouryCrate");
        assert!(!registry_matches(&armoury,&json!({"name":"ARMOURY CRATE Lite Service","publisher":"ASUSTeK COMPUTER INC."})));
        assert!(registry_matches(&armoury,&json!({"name":"ARMOURY CRATE","publisher":"ASUSTeK COMPUTER INC."})));
    }
    #[test]
    fn profile_registry_names_and_publishers_are_exact() {
        for (id,name,publisher) in [
            ("Valve.Steam","Steam","Valve Corporation"),
            ("Mozilla.Firefox","Mozilla Firefox (x64 ru)","Mozilla"),
            ("Mozilla.Firefox","Mozilla Firefox (x64 en-US)","Mozilla"),
            ("Telegram.TelegramDesktop","Telegram Desktop","Telegram FZ-LLC"),
            ("Git.Git","Git","The Git Development Community"),
            ("Anthropic.Claude","Claude","Anthropic PBC"),
        ] {
            let mut p=program(id);
            let app=json!({"name":name,"publisher":publisher,"version":"1.2.3"});
            assert!(registry_matches(&p,&app),"{id}");
            assert!(!registry_matches(&p,&json!({"name":format!("{name} Helper"),"publisher":publisher})),"{id}");
            assert!(!registry_matches(&p,&json!({"name":name,"publisher":format!("{publisher} Other")})),"{id}");
            p.version="1.2.3".into();assert!(registry_matches(&p,&app));
            p.version="1.2".into();assert!(!registry_matches(&p,&app));
        }
        let firefox=program("Mozilla.Firefox");
        for name in ["Firefox","Mozilla Firefox","Mozilla Firefox ESR (x64 ru)","Mozilla Firefox (x64 ru) Updater"] {
            assert!(!registry_matches(&firefox,&json!({"name":name,"publisher":"Mozilla"})));
        }
        assert!(registry_identity(&program("Vendicated.Vencord")).is_none());
        assert!(registry_identity(&program("XP8CLZL93F5Z4P")).is_none());
    }
    #[test]
    fn read_timeout_retries_once_and_cancellation_prevents_retry() {
        let mut calls=0;
        let result:Result<()>=retry_read(||{calls+=1;Err(ReadTimeout("fixture".into()).into())},None);
        assert_eq!(calls,2);assert!(result.unwrap_err().is::<ReadTimeout>());
        calls=0;
        let result=retry_read(||{calls+=1;if calls==1 {Err(ReadTimeout("fixture".into()).into())} else {Ok(42)}},None);
        assert_eq!(result.unwrap(),42);assert_eq!(calls,2);
        calls=0;
        let result:Result<()>=retry_read(||{calls+=1;anyhow::bail!("отказ доступа")},None);
        assert!(result.is_err());assert_eq!(calls,1);
        let cancel=AtomicBool::new(false);calls=0;
        let result:Result<()>=retry_read(||{calls+=1;cancel.store(true,Ordering::SeqCst);Err(ReadTimeout("fixture".into()).into())},Some(&cancel));
        assert!(result.unwrap_err().is::<ReadCancelled>());assert_eq!(calls,1);
        let result:Result<()>=retry_read(||panic!("Чтение после отмены"),Some(&cancel));
        assert!(result.unwrap_err().is::<ReadCancelled>());
    }
    #[test]
    fn winget_identity_and_version_are_not_substring_matches() {
        let mut p=program("Discord.Discord");
        let winget_list_matches=|row:&str,p:&crate::model::Program|
            super::winget_list_matches(&format!("Name Id Version Source\n----------------------------------------\n{row}"),p);
        assert!(winget_list_matches("Discord  Discord.Discord  1.0.9262  winget",&p));
        assert!(!winget_list_matches("Discord Canary  Discord.Discord.Canary  1.0.9262 winget",&p));
        assert!(!winget_list_matches("Name Id Version Source\n-------------------",&p));
        p.version="1.0.9262".into();
        assert!(winget_list_matches("Discord  Discord.Discord  1.0.9262 winget",&p));
        assert!(!winget_list_matches("Discord  Discord.Discord  1.0.92620 winget",&p));
        let git=program("Git.Git");
        assert!(winget_list_matches("Git Git.Git 2.47.1 winget",&git));
        assert!(winget_list_matches("Git Git.Git 2.47.1 2.48.0 winget",&git));
        assert!(!winget_list_matches("Git GUI Git.Git.GUI 2.47.1 winget",&git));
        assert!(!winget_list_matches("GitHub Desktop GitHub.GitHubDesktop 3.0 winget",&git));
        assert!(!winget_list_matches("Git.Git Unrelated.Package 1.0 winget",&git));
        assert!(!winget_list_matches("Git Git.Git 2.47.1 msstore",&git));
        assert!(!super::winget_list_matches("Диагностика: Git.Git найдено",&git));
        assert!(!super::winget_list_matches("Git Git.Git 2.47.1 winget",&git));
        let evidence=winget_list_evidence("Name Id Version Source\n----------------------------------------\nGit Git.Git 2.47.1 winget",&git).unwrap();
        assert!(evidence.contains("winget list --id Git.Git --exact --source winget: найдено"));
        assert!(evidence.contains("версия: 2.47.1"));
    }
    #[test]
    fn compact_log_preserves_unicode_and_final_installer_error() {
        let original=format!("Found NVIDIA App\n{}\nInstaller failed with exit code: 3858759680","Лицензионный текст ".repeat(2000));
        let result=compact_output(&original);
        assert!(result.starts_with("Found NVIDIA App"));
        assert!(result.ends_with("Installer failed with exit code: 3858759680"));
        assert!(result.chars().count()<6000);
        assert_eq!(compact_output("\u{1b}[31mОшибка\u{1b}[0m"),"Ошибка");
    }
    #[test]
    fn powershell_errors_are_readable_and_success_json_is_unchanged() {
        let err=ps_readonly("throw 'Проверка: служба отключена'",&Value::Null).unwrap_err().to_string();
        assert!(err.contains("Проверка: служба отключена"),"{err}");
        assert!(!err.contains("CLIXML") && !err.contains("_x000D_"),"{err}");
        assert_eq!(ps_readonly("@{ok=$true;message='Готово'}|ConvertTo-Json",&Value::Null).unwrap(),json!({"ok":true,"message":"Готово"}));
    }
    #[test]
    fn readonly_powershell_timeout_stops_only_its_probe() {
        let start=std::time::Instant::now();
        let error=ps_with_timeout("Start-Sleep -Seconds 10",&Value::Null,Some(Duration::from_millis(200))).unwrap_err().to_string();
        assert!(error.contains("тайм-аут"),"{error}");
        assert!(start.elapsed()<Duration::from_secs(6));
    }
    #[test]
    fn vencord_requires_patch_in_latest_discord_and_existing_runtime() {
        let dir=tempfile::tempdir().unwrap();
        let discord=dir.path().join("Discord");let data=dir.path().join("Vencord");
        let old=discord.join("app-1.0.9");let latest=discord.join("app-1.0.10");
        for app in [&old,&latest] {
            std::fs::create_dir_all(app.join("resources")).unwrap();
            std::fs::write(app.join("Discord.exe"),"fixture").unwrap();
            std::fs::write(app.join("resources/_app.asar"),"original fixture").unwrap();
        }
        std::fs::create_dir_all(data.join("dist")).unwrap();
        let patcher=data.join("dist/patcher.js");std::fs::write(&patcher,"fixture only; never executed").unwrap();
        let require=format!("require({})",serde_json::to_string(&patcher.to_string_lossy()).unwrap());
        std::fs::write(old.join("resources/app.asar"),&require).unwrap();
        std::fs::write(latest.join("resources/app.asar"),"unpatched").unwrap();
        assert!(!vencord_at(&discord,&data).unwrap(),"An old patch must not hide a new unpatched installation");
        std::fs::write(latest.join("resources/app.asar"),&require).unwrap();
        assert!(vencord_at(&discord,&data).unwrap());
        std::fs::remove_file(&patcher).unwrap();
        assert!(!vencord_at(&discord,&data).unwrap());
    }
}
