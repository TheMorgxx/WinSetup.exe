fn main() -> anyhow::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).map(|s| s.as_str()) == Some("--generate") {
        println!("{}", winsetup::model::render(&winsetup::model::defaults())?);
        return Ok(());
    }
    let mut c = if let Some(p) = args.get(1) {
        winsetup::model::parse(&std::fs::read_to_string(p)?)?
    } else {
        winsetup::model::defaults()
    };
    if let Some(d) = args.get(2) {
        c.application.data_drive = d.clone();
    }
    let p = winsetup::engine::plan(&c, "Мой ПК", false)?;
    println!("{}", serde_json::to_string_pretty(&p)?);
    Ok(())
}
