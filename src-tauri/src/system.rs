use anyhow::{ensure, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    io::Read,
    os::windows::process::CommandExt,
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};
fn raw_command(exe: &str, args: &[String]) -> Result<(bool, String, String)> {
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
                    out.extend_from_slice(&b[..n]);
                }
            }
            String::from_utf8_lossy(&out).to_string()
        })
    };
    let stdout = drain(Box::new(child.stdout.take().unwrap()));
    let stderr = drain(Box::new(child.stderr.take().unwrap()));
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    Ok((
        status.success(),
        stdout.join().unwrap_or_default(),
        stderr.join().unwrap_or_default(),
    ))
}
pub fn command(exe: &str, args: &[String]) -> Result<(bool, String)> {
    let (ok, out, err) = raw_command(exe, args)?;
    Ok((ok, format!("{}\n{}", out, err)))
}
pub fn ps(script: &str, input: &Value) -> Result<Value> {
    let data = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(input)?);
    let script=format!("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new();$i=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}'))|ConvertFrom-Json);{}",data,script);
    let bytes = script
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let (ok, out, err) = raw_command(
        &format!(
            "{}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            std::env::var("WINDIR")?
        ),
        &vec![
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-EncodedCommand".into(),
            encoded,
        ],
    )?;
    ensure!(ok, "{}\n{}", out, err);
    if out.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(out.trim()).with_context(|| format!("Ответ PowerShell: {}", out))
}
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
pub fn installed(p: &crate::model::Program) -> Result<bool> {
    if p.source == "git" {
        return Ok(false);
    }
    if p.source == "direct" {
        return Ok(ps(r#"$found=@(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName -eq $i.name});[bool]($found.Count -gt 0)|ConvertTo-Json"#,&json!({"name":p.detect_name}))?.as_bool().unwrap_or(false));
    }
    let args = vec![
        "list".into(),
        "--id".into(),
        p.id.clone(),
        "--exact".into(),
        "--source".into(),
        p.source.clone(),
        "--disable-interactivity".into(),
    ];
    let (ok, out) = command("winget.exe", &args)?;
    Ok(ok
        && out.lines().any(|line| {
            line.contains(&p.id)
                && (p.version.is_empty() || line.split_whitespace().any(|v| v == p.version))
        }))
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
        r#"$before=0;try{$b=@(Get-ComputerRestorePoint|Sort-Object SequenceNumber|Select-Object -Last 1);if($b.Count -gt 0 -and $b[0]){$before=[int]$b[0].SequenceNumber}}catch{};$cw=$null;Checkpoint-Computer -Description $i.desc -RestorePointType MODIFY_SETTINGS -WarningVariable cw -WarningAction SilentlyContinue;$w=@();foreach($m in @($cw)){if($m){$w+=[string]$m}};$points=@();$err='';try{$points=@(Get-ComputerRestorePoint|Where-Object{$_.Description -eq $i.desc}|ForEach-Object{@{seq=[int]$_.SequenceNumber;created=[string]$_.CreationTime}})}catch{$err=[string]$_.Exception.Message};@{before=$before;points=@($points);warnings=@($w);error=$err}|ConvertTo-Json -Depth 4"#,
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
    let mut chosen = None;
    for j in 0..10000 {
        if let Some(m) = mode(&d.device, j) {
            if m.width == d.width && m.height == d.height && m.bits == d.bits && m.hz == hz {
                chosen = Some(m);
                break;
            }
        } else {
            break;
        }
    }
    let mut m = chosen.context("Режим больше не доступен")?;
    let cur = mode(&d.device, u32::MAX).context("Монитор недоступен")?;
    ensure!(
        cur.width == d.width && cur.height == d.height && cur.bits == d.bits,
        "Разрешение изменилось: пересоздайте план"
    );
    m.fields |= 0x400000;
    let n = wide(&d.device);
    ensure!(
        unsafe {
            ChangeDisplaySettingsExW(
                n.as_ptr(),
                &mut m,
                std::ptr::null_mut(),
                2,
                std::ptr::null_mut(),
            )
        } == 0,
        "CDS_TEST: режим не поддерживается"
    );
    ensure!(
        unsafe {
            ChangeDisplaySettingsExW(
                n.as_ptr(),
                &mut m,
                std::ptr::null_mut(),
                1,
                std::ptr::null_mut(),
            )
        } == 0,
        "Не удалось применить частоту"
    );
    ensure!(
        mode(&d.device, u32::MAX).map(|m| m.hz) == Some(hz),
        "Постпроверка частоты не прошла"
    );
    Ok(())
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