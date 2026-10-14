//! Подготовка среды: проверки без скачивания; починка только после подтверждения.
use crate::{model, storage};
use anyhow::{bail, ensure, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs, io::{Read, Write}, path::{Path, PathBuf}, process::{Command, Stdio}, sync::{Mutex, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};
use std::os::windows::process::CommandExt;

pub const STORE_HELP: &str = "Откройте Microsoft Store, Библиотека, Получить обновления, дождитесь обновления Установщика приложений, затем нажмите Проверить снова";
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum Status {
    #[serde(rename="ОК")] Ok,
    #[serde(rename="можно починить")] Repairable,
    #[serde(rename="нельзя починить")] Manual,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Check { pub id:String, pub item:String, pub status:Status, pub message:String, pub action:Option<String> }
#[derive(Clone, Serialize, Deserialize)]
pub struct Report { pub checks:Vec<Check>, pub config_created:bool, pub winget_ready:bool, pub winget_help:Option<String> }
#[derive(Default)]
pub struct Runtime { created:AtomicBool, failure:Mutex<Option<String>> }
impl Runtime {
    pub fn config_created(&self)->bool {self.created.load(Ordering::SeqCst)}
    pub fn initialize(&self,root:&Path) {
        if let Ok(created)=ensure_config(root) {self.created.store(created,Ordering::SeqCst);}
    }
    pub fn create_config(&self,root:&Path)->Result<String> {
        let created=ensure_config(root)?;
        self.created.store(created,Ordering::SeqCst);
        Ok(if created {"Создан winsetup.toml из встроенных профилей"} else {"Конфиг уже существует и не изменён"}.into())
    }
}
fn drive(value:&str)->Option<String> {
    let b=value.as_bytes();
    (b.len()==2 && b[0].is_ascii_alphabetic() && b[1]==b':').then(||value.to_ascii_uppercase())
}
fn default_drive()->String {
    if Path::new("D:\\").is_dir() {"D:".into()} else {drive(&std::env::var("SystemDrive").unwrap_or_default()).unwrap_or_else(||"C:".into())}
}
pub fn ensure_config(root:&Path)->Result<bool> {ensure_config_on_drive(root,&default_drive())}
fn ensure_config_on_drive(root:&Path,selected:&str)->Result<bool> {
    let path=root.join("winsetup.toml");model::no_links(&path)?;
    if path.try_exists()? {ensure!(path.is_file(),"На месте winsetup.toml находится папка");return Ok(false);}
    let mut config=model::defaults();config.application.data_drive=drive(selected).context("Неверный системный диск")?;
    let content=model::render(&config)?;
    let mut temp=tempfile::NamedTempFile::new_in(root).context("Нельзя создать конфиг рядом с EXE; перенесите приложение в доступную для записи папку")?;
    temp.write_all(content.as_bytes())?;temp.as_file().sync_all()?;
    // В отличие от обычного сохранения настроек, существующий файл не заменяется даже при гонке.
    match temp.persist_noclobber(&path) {
        Ok(_)=>Ok(true),
        Err(e) if e.error.kind()==std::io::ErrorKind::AlreadyExists=>Ok(false),
        Err(e)=>Err(e.error.into()),
    }
}
fn item(id:&str,name:&str,status:Status,message:impl Into<String>,action:Option<&str>)->Check {
    Check {id:id.into(),item:name.into(),status,message:message.into(),action:action.map(str::to_owned)}
}
pub fn config_check(root:&Path)->Check {
    let path=root.join("winsetup.toml");
    match path.try_exists() {
        Ok(false)=>item("config","Конфиг",Status::Repairable,"winsetup.toml отсутствует; можно создать встроенные профили",Some("create_config")),
        Ok(true)=>match model::no_links(&path).and_then(|_|storage::load(root)) {
            Ok(_)=>item("config","Конфиг",Status::Ok,"winsetup.toml прочитан; существующий файл не изменён",None),
            Err(e)=>item("config","Конфиг",Status::Manual,format!("Конфиг не прочитан: {}. Автоматическая перезапись запрещена",storage::redact(&e.to_string())),None),
        },
        Err(_)=>item("config","Конфиг",Status::Manual,"Не удалось проверить доступ к winsetup.toml",None),
    }
}
// Чтение вывода ограничено 64 КиБ; процесс завершается и ожидается по тайм-ауту.
fn capture(program:&Path,args:&[String],timeout:Duration)->Result<String> {
    fn drain(mut stream:impl Read)->std::io::Result<Vec<u8>> {
        let mut saved=Vec::new();let mut block=[0;4096];
        loop {let n=stream.read(&mut block)?;if n==0 {break;}let keep=n.min(65536usize.saturating_sub(saved.len()));saved.extend_from_slice(&block[..keep]);}
        Ok(saved)
    }
    let mut child=Command::new(program).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).creation_flags(0x08000000).spawn()?;
    let stdout=child.stdout.take().unwrap();let stderr=child.stderr.take().unwrap();
    let out=std::thread::spawn(move ||drain(stdout));let err=std::thread::spawn(move ||drain(stderr));
    let started=Instant::now();
    let result=loop {
        match child.try_wait() {
            Ok(Some(status))=>break Ok(status),
            Ok(None) if started.elapsed()<timeout=>std::thread::sleep(Duration::from_millis(50)),
            Ok(None)=>{let _=child.kill();let _=child.wait();break Err(anyhow::anyhow!("Истёк тайм-аут подготовки среды"));},
            Err(e)=>{let _=child.kill();let _=child.wait();break Err(e.into());},
        }
    };
    let stdout=out.join().map_err(|_|anyhow::anyhow!("Ошибка чтения вывода"))??;
    let stderr=err.join().map_err(|_|anyhow::anyhow!("Ошибка чтения вывода"))??;
    let status=result?;
    ensure!(status.success(),"{}",storage::redact(&String::from_utf8_lossy(&stderr)));
    Ok(String::from_utf8_lossy(&stdout).trim_start_matches('\u{feff}').trim().to_string())
}
fn ps(script:&str,input:Value,timeout:Duration)->Result<Value> {
    let data=base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&input)?);
    let script=format!("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new();$i=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{data}'))|ConvertFrom-Json);{script}");
    let encoded=base64::engine::general_purpose::STANDARD.encode(script.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
    let exe=PathBuf::from(std::env::var_os("WINDIR").context("Не найден каталог Windows")?).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let output=capture(&exe,&["-NoProfile".into(),"-NonInteractive".into(),"-EncodedCommand".into(),encoded],timeout)?;
    Ok(if output.is_empty() {Value::Null}else{serde_json::from_str(&output).context("Некорректный ответ проверки среды")?})
}
#[derive(Clone)]
pub struct Winget { pub path:PathBuf, pub version:String }
pub fn winget()->Option<Winget> {
    let mut candidates=Vec::new();
    if let Some(paths)=std::env::var_os("PATH") {for dir in std::env::split_paths(&paths) {if dir.is_absolute() {candidates.push(dir.join("winget.exe"));}}}
    if let Some(local)=std::env::var_os("LOCALAPPDATA") {candidates.push(PathBuf::from(local).join("Microsoft/WindowsApps/winget.exe"));}
    let deadline=Instant::now();let mut seen=std::collections::HashSet::new();
    for path in candidates {
        if !seen.insert(path.to_string_lossy().to_lowercase()) || fs::symlink_metadata(&path).is_err() {continue;}
        let remaining=Duration::from_secs(12).saturating_sub(deadline.elapsed());if remaining.is_zero() {break;}
        if let Ok(version)=capture(&path,&["--version".into()],remaining.min(Duration::from_secs(4))) {
            if version.starts_with('v') && version.len()<80 && version[1..].chars().all(|c|c.is_ascii_alphanumeric()||".-".contains(c)) {return Some(Winget{path,version});}
        }
    }
    None
}
fn winget_item(found:Option<&Winget>)->Check {
    match found {
        Some(w)=>item("winget","winget",Status::Ok,format!("Работает: {}",w.version),None),
        None=>item("winget","winget",Status::Repairable,"Не найден или winget --version не работает",Some("install_winget")),
    }
}
pub fn readonly(root:&Path)->Vec<Check> {vec![config_check(root),winget_item(winget().as_ref())]}
pub fn internet()->bool {
    ps(r#"[bool](@(Get-NetConnectionProfile -ErrorAction SilentlyContinue|Where-Object { [int]$_.IPv4Connectivity -eq 4 -or [int]$_.IPv6Connectivity -eq 4 }).Count -gt 0)|ConvertTo-Json"#,Value::Null,Duration::from_secs(8)).ok()==Some(json!(true))
}
pub fn report(root:&Path,c:Option<&model::Config>,inv:&Value,runtime:Option<&Runtime>)->Report {
    let found=winget();let mut checks=vec![config_check(root),winget_item(found.as_ref())];
    let online=internet();checks.push(item("internet","Интернет",if online {Status::Ok}else{Status::Manual},if online {"Windows сообщает о доступе к интернету"}else{"Предупреждение: Windows не подтверждает интернет; активный сетевой запрос не выполнялся"},None));
    let admin=inv["admin"]==true;checks.push(item("admin","Права администратора",if admin {Status::Ok}else{Status::Manual},if admin {"Есть права администратора"}else{"Нет прав администратора; при необходимости запустите приложение с повышенными правами"},None));
    let selected=c.map(|c|c.application.data_drive.clone()).filter(|s|!s.is_empty()).unwrap_or_else(default_drive);
    let minimum=c.map(|c|c.execution.minimum_free_gib).unwrap_or(5);
    let free=inv["disks"].as_array().into_iter().flatten().find(|d|d["DeviceID"]==selected).and_then(|d|d["FreeSpace"].as_u64());
    checks.push(item("space","Свободное место",if free.map(|b|b/1073741824>=minimum).unwrap_or(false) {Status::Ok}else{Status::Manual},match free {Some(b)=>format!("{selected}: свободно {:.1} ГиБ, требуется не менее {minimum} ГиБ",b as f64/1073741824.0),None=>format!("Не удалось проверить свободное место на {selected}")},None));
    Report {checks,config_created:runtime.map(|r|r.created.load(Ordering::SeqCst)).unwrap_or(false),winget_ready:found.is_some(),winget_help:if found.is_none() {runtime.and_then(|r|r.failure.lock().unwrap().clone()).map(|_|STORE_HELP.into())}else{None}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_is_created_from_defaults_without_overwriting_existing_file() {
        let dir=tempfile::tempdir().unwrap();
        assert_eq!(config_check(dir.path()).status,Status::Repairable);assert!(!dir.path().join("winsetup.toml").exists());
        assert!(ensure_config_on_drive(dir.path(),"C:").unwrap());
        let config=storage::load(dir.path()).unwrap();
        assert_eq!(config.application.data_drive,"C:");
        assert_eq!(config.profiles.iter().map(|p|p.name.as_str()).collect::<Vec<_>>(),vec!["Мой ПК","Безопасный минимум","Пустой"]);
        let path=dir.path().join("winsetup.toml");fs::write(&path,"пользовательский файл, даже если он невалиден").unwrap();
        let before=fs::read(&path).unwrap();let modified=fs::metadata(&path).unwrap().modified().unwrap();
        assert!(!ensure_config_on_drive(dir.path(),"D:").unwrap());
        assert_eq!(fs::read(&path).unwrap(),before);assert_eq!(fs::metadata(path).unwrap().modified().unwrap(),modified);
    }
}
// Sources pinned to Microsoft's stable release, checked 2026-10-14.
// Only these exact hosts are accepted; github.com is restricted to Microsoft's two repositories.
pub const DOWNLOAD_HOSTS:&[&str]=&["aka.ms","github.com","release-assets.githubusercontent.com","objects.githubusercontent.com","download.microsoft.com"];
const BUNDLE:&str="https://github.com/microsoft/winget-cli/releases/download/v1.29.380/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle";
const DEPENDENCIES:&str="https://github.com/microsoft/winget-cli/releases/download/v1.29.380/DesktopAppInstaller_Dependencies.zip";
const XAML:&str="https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx";
const BUNDLE_SHA:&str="65dea9c01ce08ee7b763366b27c0e651f97db857c11ca9b9c301826c10092f2e";
const DEPENDENCIES_SHA:&str="ba875afe9d190f61218985ac0292a99d1db710bf93e13c68944ca9d89f0d82d1";
const XAML_SHA:&str="249d2afb41cc009494841372bd6dd2df46f87386d535ddf8d9f32c97226d2e46";
fn allowed_url(url:&url::Url)->bool {
    if url.scheme()!="https" || !url.username().is_empty() || url.password().is_some() || url.port_or_known_default()!=Some(443) || url.fragment().is_some() {return false;}
    let host=url.host_str().unwrap_or("");
    DOWNLOAD_HOSTS.contains(&host) && match host {
        "github.com"=>url.path().starts_with("/microsoft/winget-cli/releases/") || url.path().starts_with("/microsoft/microsoft-ui-xaml/releases/"),
        "aka.ms"=>["/getwinget","/Microsoft.VCLibs.x64.14.00.Desktop.appx"].contains(&url.path()),
        _=>true,
    }
}
fn download(source:&str,target:&Path,limit:u64,expected:&str)->Result<()> {
    let client=reqwest::blocking::Client::builder().https_only(true).connect_timeout(Duration::from_secs(15)).timeout(Duration::from_secs(300)).redirect(reqwest::redirect::Policy::none()).build()?;
    let mut url=url::Url::parse(source)?;let mut redirects=0;
    loop {
        ensure!(allowed_url(&url),"Источник или адрес перенаправления не разрешён");
        let response=client.get(url.clone()).header(reqwest::header::USER_AGENT,"WinSetup-bootstrap/1.0").send().context("Не удалось скачать официальный пакет")?;
        if response.status().is_redirection() {
            ensure!(redirects<3,"Превышен лимит трёх перенаправлений");
            let location=response.headers().get(reqwest::header::LOCATION).context("Не указан адрес перенаправления")?.to_str()?;
            url=url.join(location)?;redirects+=1;continue;
        }
        let response=response.error_for_status()?;
        ensure!(response.content_length().map(|n|n<=limit).unwrap_or(true),"Пакет превышает разрешённый размер");
        model::no_links(target)?;
        let mut file=fs::OpenOptions::new().write(true).create_new(true).open(target)?;
        let count=std::io::copy(&mut response.take(limit+1),&mut file)?;file.sync_all()?;drop(file);
        ensure!(count>0 && count<=limit,"Пакет пуст или превышает разрешённый размер");
        ensure!(storage::file_hash(target)?.eq_ignore_ascii_case(expected),"Контрольная сумма официального пакета не совпала");
        return Ok(());
    }
}
const EXTRACT_DEPENDENCIES:&str=r#"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive=[IO.Compression.ZipFile]::OpenRead($i.archive)
$paths=@();$desktop=$false;$total=0L
try {
 if($archive.Entries.Count -gt 256){throw 'Слишком много файлов зависимостей'}
 foreach($entry in $archive.Entries){
  if($entry.FullName -cmatch '^(?:x64/)?Microsoft\.VCLibs\.140\.00(?:\.UWPDesktop)?_[0-9.]+_x64__8wekyb3d8bbwe\.(?:appx|msix)$'){
   if($entry.Length -le 0 -or $entry.Length -gt 67108864 -or $paths.Count -ge 8){throw 'Размер зависимости недопустим'}
   $total+=$entry.Length;if($total -gt 134217728){throw 'Слишком большой объём зависимостей'}
   $target=Join-Path $i.folder ('dependency-'+$paths.Count+'.appx')
   $inputStream=$entry.Open();$outputStream=[IO.File]::Open($target,[IO.FileMode]::CreateNew)
   try {$buffer=New-Object byte[] 65536;$written=0L;while(($n=$inputStream.Read($buffer,0,$buffer.Length)) -gt 0){$written+=$n;if($written -gt $entry.Length){throw 'Превышен размер распаковки'};$outputStream.Write($buffer,0,$n)}}
   finally {$outputStream.Dispose();$inputStream.Dispose()}
   if($entry.FullName.Contains('Microsoft.VCLibs.140.00.UWPDesktop_')){$desktop=$true};$paths+=$target
  }
 }
 if(-not $desktop){throw 'Не найдена x64 Microsoft.VCLibs.140.00.UWPDesktop'}
 ConvertTo-Json -InputObject @($paths)
} finally {$archive.Dispose()}
"#;
const VERIFY_AND_INSTALL:&str=r#"
foreach($file in @($i.dependencies)+@($i.bundle)){
 $signature=Get-AuthenticodeSignature -LiteralPath $file
 if($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -cne 'Microsoft Corporation'){
  Remove-Item -LiteralPath $file -Force
  throw 'Подпись пакета недействительна или издатель не Microsoft Corporation. Файл удалён; установка запрещена.'
 }
}
Add-AppxPackage -Path $i.bundle -DependencyPath ([string[]]$i.dependencies) -ErrorAction Stop
@{installed=$true}|ConvertTo-Json
"#;
fn expose_to_process(found:&Winget)->Result<()> {
    // Только PATH текущего процесса для существующего engine::install; системный PATH не меняется.
    let parent=found.path.parent().context("Нет каталога winget")?;
    let mut paths=vec![parent.to_path_buf()];
    if let Some(old)=std::env::var_os("PATH") {paths.extend(std::env::split_paths(&old));}
    std::env::set_var("PATH",std::env::join_paths(paths)?);Ok(())
}
fn install_packages()->Result<Winget> {
    ensure!(cfg!(target_arch="x86_64"),"Автоматическая установка поддерживается только для Windows x64");
    let base=std::env::temp_dir().join("winsetup-winget");model::no_links(&base)?;
    let own_base=match fs::create_dir(&base) {Ok(())=>true,Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists=>false,Err(e)=>return Err(e.into())};
    model::no_links(&base)?;
    let temp=match tempfile::Builder::new().prefix("run-").tempdir_in(&base) {
        Ok(t)=>t,Err(e)=>{if own_base {let _=fs::remove_dir(&base);}return Err(e.into());},
    };
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Winget> {
        let root=temp.path().to_path_buf();
        ensure!(root.canonicalize()?.parent()==Some(base.canonicalize()?.as_path()),"Временная папка за пределами winsetup-winget");
        let bundle=root.join("Microsoft.DesktopAppInstaller.msixbundle");
        let archive=root.join("DesktopAppInstaller_Dependencies.zip");let xaml=root.join("Microsoft.UI.Xaml.2.8.x64.appx");
        download(BUNDLE,&bundle,320*1024*1024,BUNDLE_SHA)?;
        download(DEPENDENCIES,&archive,128*1024*1024,DEPENDENCIES_SHA)?;
        download(XAML,&xaml,32*1024*1024,XAML_SHA)?;
        let paths=ps(EXTRACT_DEPENDENCIES,json!({"archive":archive,"folder":root}),Duration::from_secs(60))?;
        let mut dependencies=Vec::new();
        for path in paths.as_array().context("Неверный список зависимостей")? {
            let path=PathBuf::from(path.as_str().context("Неверный путь зависимости")?);model::no_links(&path)?;
            ensure!(path.parent()==Some(root.as_path()),"Зависимость за пределами временной папки");dependencies.push(path);
        }
        dependencies.push(xaml);
        ps(VERIFY_AND_INSTALL,json!({"bundle":bundle,"dependencies":dependencies}),Duration::from_secs(300))?;
        // Регистрация alias может завершиться чуть позже Add-AppxPackage.
        for _ in 0..5 {if let Some(found)=winget() {return Ok(found);}std::thread::sleep(Duration::from_millis(500));}
        bail!("Установка завершилась, но winget --version не работает")
    })).unwrap_or_else(|_|Err(anyhow::anyhow!("Внутренняя ошибка подготовки winget")));
    // close выполняется и после ошибок/паники, включая ошибки подписи и скачивания.
    let cleanup=temp.close();
    if own_base {let _=fs::remove_dir(&base);}
    cleanup.context("Не удалось удалить временные файлы winsetup-winget")?;
    result
}
impl Runtime {
    pub fn install_winget(&self,confirmed:bool)->Result<String> {
        ensure!(confirmed,"Установка winget не подтверждена");
        let result=(|| {
            let found=match winget() {Some(w)=>w,None=>install_packages()?};
            expose_to_process(&found)?;Ok::<_,anyhow::Error>(format!("winget {} работает",found.version))
        })();
        match result {
            Ok(message)=>{*self.failure.lock().unwrap()=None;Ok(message)},
            Err(e)=>{let message=storage::redact(&format!("{e:#}"));*self.failure.lock().unwrap()=Some(message.clone());bail!("{message}");},
        }
    }
    pub fn prepare(&self,needed:bool,confirmed:bool)->(bool,String) {
        if let Some(found)=winget() {
            return match expose_to_process(&found) {Ok(())=>(true,format!("Подготовка среды: winget {} работает",found.version)),Err(e)=>(false,format!("Пропущено: {e}"))};
        }
        if !needed {return (false,"Подготовка среды: выбранному профилю winget не нужен".into());}
        if !confirmed {return (false,"Пропущено: установка winget не подтверждена; зависимые задачи ожидают winget".into());}
        match self.install_winget(true) {
            Ok(message)=>(true,message),
            Err(e)=>(false,format!("Пропущено: winget недоступен: {e}. Зависимые задачи ожидают winget")),
        }
    }
}
#[cfg(test)]
mod download_tests {
    use super::*;
    #[test]
    fn installation_requires_confirmation_before_any_system_probe() {
        let runtime=Runtime::default();
        assert!(runtime.install_winget(false).unwrap_err().to_string().contains("не подтверждена"));
        assert!(runtime.failure.lock().unwrap().is_none());
    }
    #[test]
    fn download_domains_and_repository_boundaries_are_enforced() {
        for value in [BUNDLE,DEPENDENCIES,XAML,"https://aka.ms/getwinget","https://release-assets.githubusercontent.com/github-production-release-asset/test?token=test","https://download.microsoft.com/example.appx"] {assert!(allowed_url(&url::Url::parse(value).unwrap()),"{value}");}
        for value in ["http://aka.ms/getwinget","https://github.com/other/winget-cli/releases/a","https://github.com/microsoft-evil/winget-cli/releases/a","https://github.com.evil.com/microsoft/winget-cli/releases/a","https://example.com/a","https://user:password@github.com/microsoft/winget-cli/releases/a","https://github.com:444/microsoft/winget-cli/releases/a","https://aka.ms/other","https://release-assets.githubusercontent.com.evil.org/a"] {assert!(!allowed_url(&url::Url::parse(value).unwrap()),"{value}");}
    }
}
