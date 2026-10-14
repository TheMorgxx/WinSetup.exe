#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{atomic::Ordering, Arc, Mutex},
};
use tauri::{Manager, State};
use winsetup::{bootstrap, devtest, engine, model, storage, system, vault};
#[derive(Clone)]
struct AppState {
    dev: Arc<devtest::Runner>,
    acceptance: Arc<devtest::acceptance::Acceptance>,
    operation_gate: Arc<Mutex<()>>,
    engine: Arc<engine::Engine>,
    plan: Arc<Mutex<Option<engine::Plan>>>,
    remote: Arc<Mutex<Option<(String, String)>>>,
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("Не указано {}", k))
}
fn free(e: &engine::Engine) -> Result<()> {
    ensure!(
        !e.busy.load(Ordering::SeqCst),
        "Недоступно во время выполнения"
    );
    Ok(())
}
fn history(root: &Path) -> Vec<Value> {
    let mut list = vec![];
    if let Ok(entries) = fs::read_dir(root.join("runs")) {
        for p in entries.flatten() {
            if p.path().extension().map(|x| x == "json").unwrap_or(false)
                && !p.file_name().to_string_lossy().contains("rollback")
            {
                if let Ok(s) = fs::read(p.path()) {
                    if let Ok(mut r) = serde_json::from_slice::<engine::Run>(&s) {
                        if r.active {
                            r.active = false;
                            for t in &mut r.tasks {
                                if t.status == "running" {
                                    t.status = "interrupted".into()
                                }
                            }
                        }
                        list.push(json!(r));
                    }
                }
            }
        }
    }
    list.sort_by(|a, b| b["id"].as_str().cmp(&a["id"].as_str()));
    list
}
fn open_https(url: &str) -> Result<()> {
    model::https(url)?;
    let u = url.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let verb = "open".encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            hwnd: *mut std::ffi::c_void,
            op: *const u16,
            file: *const u16,
            params: *const u16,
            dir: *const u16,
            show: i32,
        ) -> isize;
    }
    ensure!(
        unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                u.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
            )
        } > 32,
        "Не удалось открыть браузер"
    );
    Ok(())
}
fn dispatch(
    op: &str,
    payload: Value,
    state: AppState,
    window: tauri::WebviewWindow,
) -> Result<Value> {
    let e = state.engine.clone();
    let readonly=["get","state","dev_list","dev_state","dev_real_info","acceptance_state","acceptance_stop","bootstrap_status"].contains(&op)
        && payload["action"]!="save";
    let _operation=if readonly {None}else{Some(state.operation_gate.lock().unwrap())};
    if state.acceptance.active() && !readonly {
        anyhow::bail!("Дождитесь завершения приёмки или остановите её между шагами");
    }
    if state.dev.state().active && !["get", "state", "dev_list", "dev_run", "dev_stop", "dev_state", "dev_real_info", "acceptance_state", "acceptance_stop"].contains(&op) {
        anyhow::bail!("Дождитесь завершения диагностики или остановите её");
    }
    match op {
        "bootstrap_status" => {
            let config=storage::load(&e.root).ok();
            let inv=system::inventory().unwrap_or(Value::Null);
            Ok(json!(bootstrap::report(&e.root,config.as_ref(),&inv,Some(&e.bootstrap))))
        }
        "bootstrap_repair" => {
            ensure!(payload["confirmed"]==true,"Подтвердите подготовку среды");
            ensure!(!e.busy.swap(true,Ordering::SeqCst),"Дождитесь завершения текущей операции");
            let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||match payload["action"].as_str() {
                Some("create_config")=>e.bootstrap.create_config(&e.root),
                Some("install_winget")=>e.bootstrap.install_winget(true),
                _=>anyhow::bail!("Неизвестное действие подготовки"),
            })).unwrap_or_else(|_|Err(anyhow::anyhow!("Ошибка подготовки среды")));
            e.busy.store(false,Ordering::SeqCst);
            Ok(json!(result?))
        }
        "acceptance_prepare" => {
            ensure!(!state.dev.state().active,"Дождитесь завершения диагностики");
            state.acceptance.prepare(&e,text(&payload,"profile")?)
        }
        "acceptance_start" => {
            ensure!(!state.dev.state().active,"Дождитесь завершения диагностики");
            state.acceptance.start(e.clone(),&payload)?;
            Ok(json!(state.acceptance.state()))
        }
        "acceptance_stop" => {state.acceptance.stop();Ok(json!(state.acceptance.state()))}
        "acceptance_state" => match payload["action"].as_str() {
            Some("save") => {ensure!(!state.acceptance.active(),"Дождитесь окончания приёмки");Ok(json!(state.acceptance.save(&e.root)?))}
            Some("report") => {
                let report=devtest::acceptance::report(&state.acceptance.state());
                Ok(json!(if payload["hide_user"]==true{devtest::hide_user(&report)}else{report}))
            }
            Some("open_logs") => {devtest::open_logs(&e.root)?;Ok(Value::Null)}
            _ => Ok(json!(state.acceptance.state())),
        },
        "dev_list" => Ok(json!(devtest::list(&e.root))),
        "dev_real_info" => Ok(devtest::real_info(&e.root, payload["startup"] == true)?),
        "dev_real_run" => {
            state.dev.start_real(e.clone(), payload["startup_key"].as_str().map(str::to_owned), payload["confirmed"] == true)?;
            Ok(json!(state.dev.state()))
        }
        "dev_real_recover" => {
            state.dev.recover_real(e.clone(), payload["confirmed"] == true)?;
            Ok(json!(state.dev.state()))
        }
        "dev_run" => {
            ensure!(storage::load(&e.root)?.application.dev_mode, "Включите и сохраните режим разработчика");
            let ids = serde_json::from_value::<Vec<String>>(payload["ids"].clone())?;
            state.dev.start(e.clone(), ids)?;
            Ok(json!(state.dev.state()))
        }
        "dev_stop" => { state.dev.stop(); Ok(json!(state.dev.state())) }
        "dev_state" => {
            match payload["action"].as_str() {
                Some("save") => { ensure!(!state.dev.state().active, "Дождитесь завершения тестов"); Ok(json!(state.dev.save(&e.root)?)) }
                Some("open_logs") => { devtest::open_logs(&e.root)?; Ok(Value::Null) }
                Some("report") => {
                    let report = devtest::markdown(&state.dev.state());
                    Ok(json!(if payload["hide_user"] == true {devtest::hide_user(&report)} else {report}))
                }
                _ => Ok(json!(state.dev.state())),
            }
        }
        "get" => {
            let raw = fs::read_to_string(e.root.join("winsetup.toml"))?;
            let c = model::parse(&raw)?;
            Ok(
                json!({"config":c,"text":raw,"hash":storage::hash(raw.as_bytes()),"auto":std::env::args().any(|x|x=="--auto"),"config_created":e.bootstrap.config_created(),"root":e.root,"history":history(&e.root)}),
            )
        }
        "save" => {
            free(&e)?;
            let path = e.root.join("winsetup.toml");
            ensure!(
                storage::hash(&fs::read(&path)?) == text(&payload, "expected")?,
                "Файл изменён вне приложения: перечитайте его"
            );
            let raw = if let Some(s) = payload["text"].as_str() {
                model::parse(s)?;
                s.to_string()
            } else {
                model::render(&serde_json::from_value::<model::Config>(
                    payload["config"].clone(),
                )?)?
            };
            storage::atomic(&path, raw.as_bytes(), true)?;
            *state.plan.lock().unwrap() = None;
            Ok(json!(
                "Сохранено; предыдущая рабочая версия — winsetup.toml.bak"
            ))
        }
        "inventory" => {
            let mut inv = system::inventory()?;
            inv["startup"] = system::startup()?;
            inv["displays"] = json!(system::displays());
            let config=storage::load(&e.root).ok();
            let preparation=bootstrap::report(&e.root,config.as_ref(),&inv,Some(&e.bootstrap));
            inv["winget"]=json!(preparation.winget_ready);
            inv["internet"]=json!(preparation.checks.iter().any(|x|x.id=="internet" && x.status==bootstrap::Status::Ok));
            inv["bootstrap"]=json!(preparation);
            Ok(inv)
        }
        "plan" => {
            free(&e)?;
            let c = storage::load(&e.root)?;
            let p = engine::plan(&c, text(&payload, "profile")?, true)?;
            *state.plan.lock().unwrap() = Some(p.clone());
            Ok(json!(p))
        }
        "start" => {
            let c = storage::load(&e.root)?;
            let p = state
                .plan
                .lock()
                .unwrap()
                .clone()
                .context("Сначала создайте план")?;
            Ok(json!(engine::start(
                e.clone(),
                c,
                p,
                payload["confirm_removal"].as_bool().unwrap_or(false),
                payload["password"].as_str().unwrap_or("").to_string(),
                payload["resume"].as_str().map(str::to_string),
                false,
                payload["no_point_ok"].as_bool().unwrap_or(false),
                payload["winget_consent"]==true
            )?))
        }
        "vencord" => {
            free(&e)?;
            ensure!(
                payload["confirmed"] == true,
                "Подтвердите переустановку Vencord"
            );
            let c = storage::load(&e.root)?;
            let mut p = engine::plan(&c, &c.application.selected_profile, true)?;
            p.tasks.retain(|t| {
                matches!(
                    t.action,
                    engine::Action::Bootstrap | engine::Action::Check | engine::Action::RestorePoint
                ) || matches!(&t.action,engine::Action::Program(k)if k=="vencord")
            });
            ensure!(
                p.tasks
                    .iter()
                    .any(|t| matches!(&t.action,engine::Action::Program(k)if k=="vencord")),
                "Включите Vencord в профиле"
            );
            Ok(json!(engine::start(
                e.clone(),
                c,
                p,
                false,
                String::new(),
                None,
                true,
                false,
                false
            )?))
        }
        "state" => Ok(json!(e.state())),
        "pause" => {
            let pause = payload["value"].as_bool().unwrap_or(true);
            e.pause.store(pause, Ordering::SeqCst);
            if let Some(r) = e.current.lock().unwrap().as_mut() {
                r.paused = pause;
            }
            Ok(json!("После текущей задачи"))
        }
        "cancel" => {
            e.cancel.store(true, Ordering::SeqCst);
            Ok(json!("Отмена после текущей задачи"))
        }
        "history" => Ok(json!(history(&e.root))),
        "rollback" => {
            ensure!(
                payload["confirmed"] == true,
                "Подтвердите ограниченный откат"
            );
            Ok(json!(engine::rollback(&e, text(&payload, "id")?)?))
        }
        "remote_preview" => {
            free(&e)?;
            let url = model::https(text(&payload, "url")?)?;
            ensure!(
                url.host_str() == Some("raw.githubusercontent.com"),
                "Разрешён только raw.githubusercontent.com"
            );
            use std::io::Read;
            let response = reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(30))
                .build()?
                .get(url)
                .send()?
                .error_for_status()?;
            let mut bytes = vec![];
            response.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 2 * 1024 * 1024, "Конфиг больше 2 МиБ");
            let incoming = String::from_utf8(bytes)?;
            model::parse(&incoming)?;
            let current = fs::read_to_string(e.root.join("winsetup.toml"))?;
            let token = storage::hash(incoming.as_bytes());
            *state.remote.lock().unwrap() =
                Some((incoming.clone(), storage::hash(current.as_bytes())));
            Ok(json!({"before":current,"after":incoming,"token":token}))
        }
        "remote_apply" => {
            free(&e)?;
            ensure!(payload["confirmed"] == true, "Требуется подтверждение");
            let (incoming, expected) = state
                .remote
                .lock()
                .unwrap()
                .take()
                .context("Нет предложенного конфига")?;
            ensure!(
                storage::hash(incoming.as_bytes()) == text(&payload, "token")?,
                "Предложение изменилось"
            );
            let path = e.root.join("winsetup.toml");
            ensure!(
                storage::hash(&fs::read(&path)?) == expected,
                "Локальный конфиг изменился"
            );
            storage::atomic(&path, incoming.as_bytes(), true)?;
            Ok(json!("Конфиг применён"))
        }
        "browse" => {
            let kind = text(&payload, "kind")?;
            ensure!(
                ["folder", "open", "save"].contains(&kind),
                "Неверный диалог"
            );
            system::ps(
                r#"Add-Type -AssemblyName System.Windows.Forms;$d=if($i.kind -eq 'folder'){New-Object System.Windows.Forms.FolderBrowserDialog}elseif($i.kind -eq 'save'){New-Object System.Windows.Forms.SaveFileDialog}else{New-Object System.Windows.Forms.OpenFileDialog};if($i.kind -ne 'folder'){$d.Filter='Все файлы (*.*)|*.*'};if($d.ShowDialog() -eq 'OK'){if($i.kind -eq 'folder'){$d.SelectedPath|ConvertTo-Json}else{$d.FileName|ConvertTo-Json}}else{''|ConvertTo-Json};$d.Dispose()"#,
                &json!({"kind":kind}),
            )
        }
        "vault" => {
            ensure!(!e.busy.swap(true, Ordering::SeqCst), "Занято");
            let result = (|| -> Result<Value> {
                let c = storage::load(&e.root)?;
                let path = PathBuf::from(text(&payload, "path")?);
                let pass = zeroize::Zeroizing::new(text(&payload, "password")?.to_string());
                let mode = text(&payload, "mode")?;
                ensure!(
                    ["create", "restore", "prepare"].contains(&mode),
                    "Неверное действие"
                );
                if mode == "restore" {
                    ensure!(payload["confirmed"] == true, "Подтвердите восстановление");
                    return Ok(json!(vault::restore(&c, &path, &pass)?));
                }
                if mode == "create" {
                    return Ok(json!(vault::create(&c, &path, &pass)?));
                }
                model::no_links(&path)?;
                ensure!(path.is_dir(), "Выберите существующую папку на флешке");
                let dest = path.join(
                    chrono::Local::now()
                        .format("WinSetup-%Y%m%d-%H%M%S")
                        .to_string(),
                );
                ensure!(!dest.exists(), "Каталог уже существует");
                fs::create_dir(&dest)?;
                let result = (|| -> Result<Value> {
                    let msg = vault::create(&c, &dest.join("backup.wsvault"), &pass)?;
                    fs::copy(std::env::current_exe()?, dest.join("WinSetup.exe"))?;
                    fs::copy(e.root.join("winsetup.toml"), dest.join("winsetup.toml"))?;
                    Ok(json!(format!("{}; комплект: {}", msg, dest.display())))
                })();
                if result.is_err() {
                    let _ = fs::remove_dir_all(&dest);
                }
                result
            })();
            e.busy.store(false, Ordering::SeqCst);
            result
        }
        "export_profile" => {
            free(&e)?;
            let c = storage::load(&e.root)?;
            let name = text(&payload, "profile")?;
            let mut one = c.clone();
            one.profiles = vec![c
                .profiles
                .iter()
                .find(|p| p.name == name)
                .context("Нет профиля")?
                .clone()];
            one.application.selected_profile = name.into();
            let dest = PathBuf::from(text(&payload, "path")?);
            ensure!(!dest.exists(), "Файл уже существует");
            storage::atomic(&dest, model::render(&one)?.as_bytes(), false)?;
            Ok(json!("Экспортирован профиль и определения действий"))
        }
        "import_profile" => {
            free(&e)?;
            let incoming = model::parse(&fs::read_to_string(text(&payload, "path")?)?)?;
            ensure!(
                incoming.profiles.len() == 1,
                "В файле должен быть один профиль"
            );
            let current = storage::load(&e.root)?;
            ensure!(
                !current
                    .profiles
                    .iter()
                    .any(|p| p.name == incoming.profiles[0].name),
                "Профиль с таким именем уже есть"
            );
            Ok(json!(incoming))
        }
        "export_report" => {
            let id = text(&payload, "id")?;
            ensure!(model::key(id), "Неверный id");
            let r: engine::Run = serde_json::from_slice(&fs::read(
                e.root.join("runs").join(format!("{}.json", id)),
            )?)?;
            let dest = PathBuf::from(text(&payload, "path")?);
            ensure!(!dest.exists(), "Файл уже существует");
            let report=format!("# WinSetup: {}\n\nПрофиль: {}\n\n{}\n\n## Журнал\n{}\n\n## Технический журнал\n{}\n",r.id,r.plan.profile,r.tasks.iter().map(|t|format!("- {} — {}: {}",t.name,t.status,t.detail)).collect::<Vec<_>>().join("\n"),r.log.join("\n"),r.technical.join("\n"));
            storage::atomic(&dest, storage::redact(&report).as_bytes(), false)?;
            Ok(json!("Отчёт экспортирован с маскированием секретов"))
        }
        "open_driver" => {
            open_https(
                "https://www.amd.com/en/support/downloads/drivers.html/chipsets/am4/b550.html",
            )?;
            Ok(Value::Null)
        }
        "open_manual" => {
            let c = storage::load(&e.root)?;
            let p = c
                .programs
                .iter()
                .find(|p| p.key == payload["key"].as_str().unwrap_or(""))
                .context("Нет программы")?;
            open_https(&p.url)?;
            Ok(Value::Null)
        }
        "resize" => {
            let auto = payload["auto"].as_bool().unwrap_or(false);
            window.set_size(tauri::LogicalSize::new(
                if auto { 600.0 } else { 1180.0 },
                if auto { 660.0 } else { 820.0 },
            ))?;
            Ok(Value::Null)
        }
        _ => anyhow::bail!("Неизвестная операция"),
    }
}
#[tauri::command]
async fn api(
    op: String,
    payload: Value,
    state: State<'_, AppState>,
    window: tauri::WebviewWindow,
) -> Result<Value, String> {
    let s = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        dispatch(&op, payload, s, window).map_err(|e| storage::redact(&e.to_string()))
    })
    .await
    .map_err(|e| e.to_string())?
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--devtest-worker") {
        std::process::exit(devtest::worker(&args));
    }
    if args.iter().any(|arg| arg == "--selftest") {
        std::process::exit(devtest::selftest());
    }
    tauri::Builder::default()
        .setup(|app| {
            let root = storage::root()?;
            let engine=Arc::new(engine::Engine::new(root));
            engine.bootstrap.initialize(&engine.root);
            app.manage(AppState {
                dev: Arc::new(devtest::Runner::default()),
                acceptance: Arc::new(devtest::acceptance::Acceptance::default()),
                operation_gate: Arc::new(Mutex::new(())),
                engine,
                plan: Arc::new(Mutex::new(None)),
                remote: Arc::new(Mutex::new(None)),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![api])
        .run(tauri::generate_context!())
        .expect("Не удалось открыть WinSetup");
}