fn main() {
    println!("cargo:rerun-if-changed=app.manifest");
    let attrs = tauri_build::Attributes::new().windows_attributes(
        tauri_build::WindowsAttributes::new().app_manifest(include_str!("app.manifest")),
    );
    tauri_build::try_build(attrs).expect("tauri-build failed");
}
