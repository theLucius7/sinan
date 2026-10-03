#![forbid(unsafe_code)]

fn main() {
    println!("cargo:rerun-if-changed=migrations");
    println!("cargo:rerun-if-changed=../../Cargo.lock");
    let lock: toml::Value = std::fs::read_to_string("../../Cargo.lock")
        .expect("read workspace dependency lock")
        .parse()
        .expect("parse workspace dependency lock");
    let packages: Vec<_> = lock["package"]
        .as_array()
        .expect("locked packages")
        .iter()
        .map(|package| {
            let source = package.get("source").and_then(toml::Value::as_str);
            serde_json::json!({
                "name":package["name"].as_str().expect("package name"),
                "version":package["version"].as_str().expect("package version"),
                "ecosystem":if source.is_some_and(|value|matches!(value,"registry+https://github.com/rust-lang/crates.io-index"|"registry+https://index.crates.io/")){"crates.io"}else{"workspace-or-git"}
            })
        })
        .collect();
    std::fs::write(
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("build output"))
            .join("dependency-inventory.json"),
        serde_json::to_vec(&packages).expect("serialize dependency inventory"),
    )
    .expect("write dependency inventory");
}
