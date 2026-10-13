use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub meta: Meta,
    pub application: Application,
    pub profiles: Vec<Profile>,
    pub programs: Vec<Program>,
    pub paths: Vec<Folder>,
    pub windows_tweaks: Vec<Tweak>,
    pub appx_removal: Vec<String>,
    pub autostart: Vec<StartupChoice>,
    pub backup: Backup,
    pub repositories: Vec<Repository>,
    pub execution: Execution,
    pub safety: Safety,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    pub schema_version: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Application {
    #[serde(default)]
    pub dev_mode: bool,
    pub mode: String,
    pub theme: String,
    pub selected_profile: String,
    pub data_drive: String,
    #[serde(default = "default_ui_accent")]
    pub ui_accent: String,
    #[serde(default = "default_ui_scale")]
    pub ui_scale: u16,
    #[serde(default = "default_ui_density")]
    pub ui_density: String,
    #[serde(default = "default_ui_animations")]
    pub ui_animations: bool,
    #[serde(default = "default_ui_anim_speed")]
    pub ui_anim_speed: String,
    #[serde(default)]
    pub ui_reduce_motion: bool,
    #[serde(default = "default_ui_start_mode")]
    pub ui_start_mode: String,
    #[serde(default = "default_ui_confirm_close")]
    pub ui_confirm_close: bool,
    #[serde(default = "default_ui_notify_done")]
    pub ui_notify_done: bool,
}
fn default_ui_accent() -> String { "blue".into() }
fn default_ui_scale() -> u16 { 100 }
fn default_ui_density() -> String { "normal".into() }
fn default_ui_animations() -> bool { true }
fn default_ui_anim_speed() -> String { "normal".into() }
fn default_ui_start_mode() -> String { "choose".into() }
fn default_ui_confirm_close() -> bool { true }
fn default_ui_notify_done() -> bool { true }

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub programs: Vec<String>,
    pub paths: Vec<String>,
    pub windows_tweaks: BTreeMap<String, String>,
    pub appx_removal: Vec<String>,
    pub autostart: Vec<String>,
    pub repositories: Vec<String>,
    pub restore_backup: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    pub key: String,
    pub name: String,
    pub source: String,
    pub id: String,
    pub version: String,
    pub location: String,
    pub url: String,
    pub sha256: String,
    pub detect_name: String,
    pub order: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Folder {
    pub key: String,
    pub path: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tweak {
    pub key: String,
    pub name: String,
    pub description: String,
    pub risk: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartupChoice {
    pub key: String,
    pub hive: String,
    pub category: String,
    pub name: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    pub firefox: bool,
    pub sources: Vec<BackupSource>,
    pub vault_path: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSource {
    pub key: String,
    pub path: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub key: String,
    pub url: String,
    pub target: String,
    pub branch: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    pub retries: u32,
    pub minimum_free_gib: u64,
    /// Устаревшее поле `downloads` из старых конфигов: при чтении игнорируется,
    /// при записи не выводится (установщики всегда идут по одному).
    #[serde(default, rename = "downloads", skip_serializing)]
    #[allow(dead_code)]
    legacy_downloads: Option<toml::Value>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Safety {
    pub restore_point: bool,
    pub require_removal_confirmation: bool,
}
/// Встроенный пакет Appx, который разрешено удалять.
/// `default_remove` — входит ли пакет в список удаления профиля "Мой ПК" по умолчанию.
/// Пакеты `Microsoft.LanguageExperiencePack*` разрешены к удалению по префиксу
/// (см. `removable`) и никогда не входят в список по умолчанию.
pub struct RemovablePackage {
    pub name: &'static str,
    pub default_remove: bool,
}
pub const REMOVABLE: &[RemovablePackage] = &[
    RemovablePackage {
        name: "Microsoft.549981C3F5F10",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.SkypeApp",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.Wallet",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.MixedReality.Portal",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.Microsoft3DViewer",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.MSPaint",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.People",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.GetHelp",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.Getstarted",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.WindowsFeedbackHub",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.WindowsMaps",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.MicrosoftSolitaireCollection",
        default_remove: true,
    },
    RemovablePackage {
        name: "Clipchamp.Clipchamp",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.BingWeather",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.BingSearch",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.MicrosoftOfficeHub",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.Office.OneNote",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.YourPhone",
        default_remove: true,
    },
    RemovablePackage {
        name: "MicrosoftWindows.CrossDevice",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.ZuneVideo",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.Windows.DevHome",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.XboxApp",
        default_remove: true,
    },
    RemovablePackage {
        name: "Microsoft.OutlookForWindows",
        default_remove: false,
    },
    RemovablePackage {
        name: "microsoft.windowscommunicationsapps",
        default_remove: false,
    },
    RemovablePackage {
        name: "Microsoft.MicrosoftStickyNotes",
        default_remove: false,
    },
    RemovablePackage {
        name: "Microsoft.XboxGamingOverlay",
        default_remove: false,
    },
    RemovablePackage {
        name: "Microsoft.Windows.Photos",
        default_remove: false,
    },
    RemovablePackage {
        name: "Microsoft.WindowsSoundRecorder",
        default_remove: false,
    },
    RemovablePackage {
        name: "Microsoft.WindowsCamera",
        default_remove: false,
    },
    RemovablePackage {
        name: "Microsoft.WindowsAlarms",
        default_remove: false,
    },
    RemovablePackage {
        name: "Microsoft.ZuneMusic",
        default_remove: false,
    },
];
pub const TWEAKS: &[&str] = &[
    "max_refresh",
    "notify_snip",
    "notify_discord",
    "notify_telegram",
    "suggestions",
];
pub fn removable(s: &str) -> bool {
    REMOVABLE.iter().any(|p| p.name == s) || s.starts_with("Microsoft.LanguageExperiencePack")
}
pub fn default_removal() -> Vec<String> {
    REMOVABLE
        .iter()
        .filter(|p| p.default_remove)
        .map(|p| p.name.to_string())
        .collect()
}
pub fn key(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 150
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}
pub fn https(s: &str) -> Result<url::Url> {
    let u = url::Url::parse(s)?;
    ensure!(
        u.scheme() == "https"
            && u.username().is_empty()
            && u.password().is_none()
            && u.host_str().is_some()
            && u.query().is_none()
            && u.fragment().is_none(),
        "Нужен HTTPS URL без секретов, query и fragment"
    );
    Ok(u)
}
pub fn path_value(s: &str) -> Result<()> {
    ensure!(
        !s.is_empty() && !s.contains(['\0', '\r', '\n', '"', '*', '?', '|', '<', '>']),
        "Недопустимый путь"
    );
    let t = s
        .replace("{data}", "X:")
        .replace("{appdata}", "X:\\AppData");
    ensure!(
        t.len() > 3
            && t.as_bytes()[0].is_ascii_alphabetic()
            && t.as_bytes()[1] == b':'
            && matches!(t.as_bytes()[2], b'\\' | b'/'),
        "Нужен абсолютный путь или {{data}}\\папка"
    );
    for part in t[3..].split(['\\', '/']) {
        ensure!(
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.contains(':')
                && !part.ends_with(['.', ' ']),
            "Недопустимый сегмент пути"
        );
        let name = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        ensure!(
            ![
                "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
                "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
                "LPT9"
            ]
            .contains(&name.as_str()),
            "Зарезервированное имя Windows"
        );
    }
    Ok(())
}
pub fn resolve(s: &str, c: &Config) -> Result<PathBuf> {
    path_value(s)?;
    if s.contains("{data}") {
        ensure!(!c.application.data_drive.is_empty(), "Выберите диск данных");
    }
    let a = std::env::var("APPDATA")?;
    Ok(PathBuf::from(
        s.replace("{data}", &c.application.data_drive)
            .replace("{appdata}", &a),
    ))
}
pub fn no_links(p: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    for q in p.ancestors() {
        match std::fs::symlink_metadata(q) {
            Ok(m) => {
                ensure!(
                    m.file_attributes() & 0x400 == 0,
                    "Ссылки и junction запрещены: {}",
                    q.display()
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
pub fn validate(c: &Config) -> Result<()> {
    ensure!(
        c.meta.schema_version == 1,
        "meta.schema_version: поддерживается только 1"
    );
    ensure!(
        ["choose", "full", "auto"].contains(&c.application.mode.as_str()),
        "application.mode"
    );
    ensure!(
        ["dark", "light", "system"].contains(&c.application.theme.as_str()),
        "application.theme"
    );
    ensure!(["blue", "teal", "violet", "green", "orange", "rose"].contains(&c.application.ui_accent.as_str()), "application.ui_accent");
    ensure!([90, 100, 110, 125].contains(&c.application.ui_scale), "application.ui_scale");
    ensure!(["normal", "compact"].contains(&c.application.ui_density.as_str()), "application.ui_density");
    ensure!(["fast", "normal", "smooth"].contains(&c.application.ui_anim_speed.as_str()), "application.ui_anim_speed");
    ensure!(["choose", "full", "auto"].contains(&c.application.ui_start_mode.as_str()), "application.ui_start_mode");
    let drive = &c.application.data_drive;
    ensure!(
        drive.is_empty()
            || (drive.len() == 2
                && drive.as_bytes()[0].is_ascii_alphabetic()
                && drive.ends_with(':')),
        "application.data_drive: ожидается буква диска, например D:"
    );
    ensure!(c.execution.retries <= 5, "execution: retries 0..5");
    ensure!(
        c.safety.restore_point && c.safety.require_removal_confirmation,
        "safety: отключение защиты запрещено"
    );
    ensure!(
        !c.profiles.is_empty() && c.profiles.len() <= 50,
        "profiles: требуется 1..50 профилей"
    );
    let mut ids = HashSet::new();
    for p in &c.programs {
        ensure!(
            key(&p.key) && ids.insert(p.key.clone()),
            "programs: повтор/неверный key {}",
            p.key
        );
        ensure!(!p.name.trim().is_empty(), "programs: пустое имя");
        ensure!(
            ["winget", "msstore", "direct", "git"].contains(&p.source.as_str()),
            "programs: неизвестный источник"
        );
        if !p.location.is_empty() {
            path_value(&p.location)?;
        }
        if !p.version.is_empty() {
            ensure!(key(&p.version), "programs: недопустимая версия");
        }
        match p.source.as_str() {
            "winget" | "msstore" => ensure!(key(&p.id), "programs: недопустимый id"),
            "direct" => {
                https(&p.url)?;
                ensure!(
                    p.sha256.len() == 64 && p.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                    "programs: direct требует SHA-256"
                );
                ensure!(
                    !p.detect_name.is_empty(),
                    "programs: direct требует detect_name"
                );
                ensure!(
                    p.url.to_ascii_lowercase().ends_with(".msi"),
                    "programs: для direct разрешён только MSI; EXE — вручную"
                );
            }
            "git" => {
                https(&p.url)?;
                ensure!(!p.location.is_empty(), "programs: git требует location");
            }
            _ => unreachable!(),
        }
    }
    let unique = |items: Vec<&str>, section: &str| -> Result<()> {
        let mut seen = HashSet::new();
        for x in items {
            ensure!(
                key(x) && seen.insert(x),
                "{}: неверный/повторный key {}",
                section,
                x
            );
        }
        Ok(())
    };
    unique(c.paths.iter().map(|x| x.key.as_str()).collect(), "paths")?;
    for p in &c.paths {
        path_value(&p.path)?;
    }
    unique(
        c.repositories.iter().map(|x| x.key.as_str()).collect(),
        "repositories",
    )?;
    for r in &c.repositories {
        https(&r.url)?;
        path_value(&r.target)?;
        ensure!(
            r.branch.is_empty()
                || (!r.branch.starts_with('-')
                    && !r.branch.contains(['\0', '\r', '\n'])
                    && r.branch.len() < 200),
            "repositories: неверная ветка"
        );
    }
    unique(
        c.windows_tweaks.iter().map(|x| x.key.as_str()).collect(),
        "windows_tweaks",
    )?;
    for t in &c.windows_tweaks {
        ensure!(TWEAKS.contains(&t.key.as_str()),"windows_tweaks: действие {} запрещено; Defender/UAC/Firewall/Update/SmartScreen и другие системные изменения не поддерживаются",t.key);
    }
    for a in &c.appx_removal {
        ensure!(
            removable(a),
            "appx_removal: защищённый/неразрешённый пакет {}",
            a
        );
    }
    unique(
        c.autostart.iter().map(|x| x.key.as_str()).collect(),
        "autostart",
    )?;
    for a in &c.autostart {
        ensure!(
            ["HKCU", "HKLM"].contains(&a.hive.as_str())
                && ["Run", "Run32", "StartupFolder"].contains(&a.category.as_str())
                && !a.name.contains(['\\', '/', '\0'])
                && !a.name.is_empty(),
            "autostart: недопустимая запись"
        );
    }
    let mut names = HashSet::new();
    for p in &c.profiles {
        ensure!(
            !p.name.trim().is_empty() && p.name.len() < 120 && names.insert(&p.name),
            "profiles: имя пустое или повторяется"
        );
        for id in &p.programs {
            ensure!(ids.contains(id), "profiles: неизвестная программа {}", id);
        }
        for id in &p.paths {
            ensure!(
                c.paths.iter().any(|x| &x.key == id),
                "profiles: неизвестная папка {}",
                id
            );
        }
        for (k, v) in &p.windows_tweaks {
            ensure!(
                TWEAKS.contains(&k.as_str())
                    && ["keep", "enabled", "disabled"].contains(&v.as_str()),
                "profiles.windows_tweaks: запрещённый параметр/состояние {}",
                k
            );
        }
        for a in &p.appx_removal {
            ensure!(
                removable(a) && c.appx_removal.contains(a),
                "profiles.appx_removal: запрещено {}",
                a
            );
        }
        for a in &p.autostart {
            ensure!(
                c.autostart.iter().any(|x| &x.key == a),
                "profiles.autostart: неизвестная запись"
            );
        }
        for a in &p.repositories {
            ensure!(
                c.repositories.iter().any(|x| &x.key == a),
                "profiles.repositories: неизвестный репозиторий"
            );
        }
    }
    ensure!(
        names.contains(&c.application.selected_profile),
        "application.selected_profile: профиль не найден"
    );
    unique(
        c.backup.sources.iter().map(|x| x.key.as_str()).collect(),
        "backup.sources",
    )?;
    for b in &c.backup.sources {
        ensure!(
            b.key != "firefox",
            "backup: firefox — зарезервированное имя"
        );
        path_value(&b.path)?;
    }
    if !c.backup.vault_path.is_empty() {
        path_value(&c.backup.vault_path)?;
    }
    let serialized = serde_json::to_string(c)?;
    for needle in [
        "ghp_",
        "github_pat_",
        "sk-proj-",
        "password=",
        "token=",
        "-----BEGIN PRIVATE KEY",
    ] {
        ensure!(
            !serialized.contains(needle),
            "Конфиг содержит похожее на секрет значение"
        );
    }
    Ok(())
}
pub fn parse(s: &str) -> Result<Config> {
    let c: Config = toml::from_str(s).map_err(|e| anyhow::anyhow!("Конфиг: {}", e))?;
    validate(&c).map_err(|e| {
        let section = e
            .to_string()
            .split(':')
            .next()
            .unwrap_or("config")
            .to_string();
        let line = s
            .lines()
            .position(|l| l.contains(section.split('.').next().unwrap_or("meta")))
            .map(|x| x + 1)
            .unwrap_or(1);
        anyhow::anyhow!(
            "Раздел {}, строка {} (начало раздела): {}",
            section,
            line,
            e
        )
    })?;
    Ok(c)
}
pub fn render(c: &Config) -> Result<String> {
    validate(c)?;
    let mut s = toml::to_string_pretty(c)?;
    for (key, comment) in [
        ("meta", "Версия формата"),
        (
            "application",
            "Интерфейс и выбранный диск данных; секреты запрещены",
        ),
        ("profiles", "Независимые профили: списки выбранных действий"),
        (
            "programs",
            "Только поддерживаемые источники; произвольные команды запрещены",
        ),
        ("paths", "{data} заменяется выбранным диском"),
        (
            "windows_tweaks",
            "Разрешённые изменения Windows; keep означает не менять",
        ),
        ("backup", "Пароль вводится только в интерфейсе"),
        ("execution", "Установщики выполняются последовательно"),
        ("safety", "Защитные подтверждения обязательны"),
    ] {
        let marker = if s.contains(&format!("[[{}]]", key)) {
            format!("[[{}]]", key)
        } else {
            format!("[{}]", key)
        };
        s = s.replacen(&marker, &format!("# {}\n{}", comment, marker), 1);
    }
    Ok(format!("# WinSetup — перенос окружения Windows 10\n# Не помещайте сюда пароли, токены и ключи.\n{}",s))
}
pub fn defaults() -> Config {
    let specs = [
        ("steam", "Steam", "winget", "Valve.Steam", true),
        ("discord", "Discord", "winget", "Discord.Discord", true),
        ("vencord", "Vencord", "winget", "Vendicated.Vencord", true),
        ("firefox", "Firefox", "winget", "Mozilla.Firefox", true),
        ("nvidia", "NVIDIA App", "msstore", "XP8CLZL93F5Z4P", true),
        ("claude", "Claude", "winget", "Anthropic.Claude", true),
        (
            "telegram",
            "Telegram",
            "winget",
            "Telegram.TelegramDesktop",
            true,
        ),
        ("git", "Git", "winget", "Git.Git", true),
        (
            "armoury",
            "Armoury Crate",
            "winget",
            "Asus.ArmouryCrate",
            true,
        ),
        ("chrome", "Google Chrome", "winget", "Google.Chrome", false),
        (
            "idea",
            "IntelliJ IDEA",
            "winget",
            "JetBrains.IntelliJIDEA",
            false,
        ),
        (
            "translucent",
            "TranslucentTB",
            "winget",
            "CharlesMilette.TranslucentTB",
            false,
        ),
        (
            "eartrumpet",
            "EarTrumpet",
            "winget",
            "File-New-Project.EarTrumpet",
            false,
        ),
        ("ngrok", "ngrok", "msstore", "9MVS1J51GMK6", false),
    ];
    let programs = specs
        .iter()
        .enumerate()
        .map(|(i, (k, n, s, id, _))| Program {
            key: k.to_string(),
            name: n.to_string(),
            source: s.to_string(),
            id: id.to_string(),
            version: String::new(),
            location: if *k == "steam" {
                "{data}\\Steam".into()
            } else {
                String::new()
            },
            url: if *s == "msstore" {
                format!("https://apps.microsoft.com/detail/{}", id)
            } else {
                format!(
                    "https://winget.run/pkg/{}/{}",
                    id.split('.').next().unwrap(),
                    id.split('.').skip(1).collect::<Vec<_>>().join(".")
                )
            },
            sha256: String::new(),
            detect_name: String::new(),
            order: i as u32,
        })
        .collect();
    let paths = ["Steam", "Main", "Secondary"]
        .iter()
        .map(|s| Folder {
            key: s.to_ascii_lowercase(),
            path: format!("{{data}}\\{}", s),
        })
        .collect();
    let tweaks = [
        (
            "max_refresh",
            "Максимальная частота",
            "Только частота, без изменения разрешения, HDR и масштаба",
            "Осторожно",
        ),
        (
            "notify_snip",
            "Уведомления снимков экрана",
            "Разрешить или отключить уведомления приложения",
            "Безопасно",
        ),
        (
            "notify_discord",
            "Уведомления Discord",
            "Только Windows-уведомления",
            "Безопасно",
        ),
        (
            "notify_telegram",
            "Уведомления Telegram",
            "Только Windows-уведомления",
            "Безопасно",
        ),
        (
            "suggestions",
            "Советы и предложения",
            "Советы, реклама и персонализированные предложения Windows",
            "Безопасно",
        ),
    ]
    .iter()
    .map(|(k, n, d, r)| Tweak {
        key: k.to_string(),
        name: n.to_string(),
        description: d.to_string(),
        risk: r.to_string(),
    })
    .collect();
    let mut mine = Profile {
        name: "Мой ПК".into(),
        programs: specs
            .iter()
            .filter(|s| s.4)
            .map(|s| s.0.to_string())
            .collect(),
        paths: vec!["steam".into(), "main".into(), "secondary".into()],
        windows_tweaks: TWEAKS
            .iter()
            .map(|k| {
                (
                    k.to_string(),
                    if *k == "max_refresh" {
                        "enabled"
                    } else {
                        "disabled"
                    }
                    .into(),
                )
            })
            .collect(),
        appx_removal: default_removal(),
        autostart: vec![],
        repositories: vec![],
        restore_backup: false,
    };
    let mut minimum = mine.clone();
    minimum.name = "Безопасный минимум".into();
    minimum.programs = vec!["firefox".into(), "git".into(), "telegram".into()];
    minimum.paths.clear();
    minimum.windows_tweaks.clear();
    minimum.appx_removal.clear();
    mine.restore_backup = false;
    let mut empty = minimum.clone();
    empty.name = "Пустой".into();
    empty.programs.clear();
    Config {
        meta: Meta { schema_version: 1 },
        application: Application {
            dev_mode: false,
            mode: "choose".into(),
            theme: "dark".into(),
            selected_profile: "Мой ПК".into(),
            data_drive: String::new(),
            ui_accent: default_ui_accent(),
            ui_scale: default_ui_scale(),
            ui_density: default_ui_density(),
            ui_animations: default_ui_animations(),
            ui_anim_speed: default_ui_anim_speed(),
            ui_reduce_motion: false,
            ui_start_mode: default_ui_start_mode(),
            ui_confirm_close: default_ui_confirm_close(),
            ui_notify_done: default_ui_notify_done(),
        },
        profiles: vec![mine, minimum, empty],
        programs,
        paths,
        windows_tweaks: tweaks,
        appx_removal: REMOVABLE.iter().map(|p| p.name.to_string()).collect(),
        autostart: vec![],
        backup: Backup {
            firefox: true,
            sources: vec![],
            vault_path: String::new(),
        },
        repositories: vec![],
        execution: Execution {
            retries: 2,
            minimum_free_gib: 5,
            legacy_downloads: None,
        },
        safety: Safety {
            restore_point: true,
            require_removal_confirmation: true,
        },
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_validation() {
        let c = defaults();
        let text = render(&c).unwrap();
        parse(&text).unwrap();
        assert!(!text.contains("downloads"));
        let old = text.replace("minimum_free_gib", "downloads = 3\nminimum_free_gib");
        let migrated = parse(&old).unwrap();
        assert!(!render(&migrated).unwrap().contains("downloads"));
        assert!(parse(&(text.clone() + "\n[secret]\npassword='x'\n")).is_err());
        let mut bad = c.clone();
        bad.programs[0].source = "shell".into();
        assert!(validate(&bad).is_err());
        bad = c.clone();
        bad.profiles[0]
            .windows_tweaks
            .insert("defender".into(), "disabled".into());
        assert!(validate(&bad).is_err());
        bad = c.clone();
        bad.paths[0].path = "{data}\\..\\Windows".into();
        assert!(validate(&bad).is_err());
        bad = c;
        bad.programs[0].source = "direct".into();
        bad.programs[0].url = "https://example.org/a.msi".into();
        assert!(validate(&bad).is_err());
    }
    #[test]
    fn exactly_22_default_remove_packages() {
        assert_eq!(REMOVABLE.iter().filter(|p| p.default_remove).count(), 22);
        let c = defaults();
        let mine = c.profiles.iter().find(|p| p.name == "Мой ПК").unwrap();
        assert_eq!(mine.appx_removal.len(), 22);
    }
}
