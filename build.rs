use std::{env, fs, path::Path};

fn hash_file(path: &Path, hash: &mut u64) {
    println!("cargo:rerun-if-changed={}", path.display());
    for byte in path
        .to_string_lossy()
        .replace('\\', "/")
        .bytes()
        .chain(fs::read(path).expect("read build input"))
    {
        *hash = (*hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
}
fn hash_dir(path: &Path, hash: &mut u64) {
    println!("cargo:rerun-if-changed={}", path.display());
    let mut paths: Vec<_> = fs::read_dir(path)
        .expect("read source directory")
        .map(|entry| entry.expect("source entry").path())
        .collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            hash_dir(&path, hash);
        } else {
            hash_file(&path, hash);
        }
    }
}
fn main() {
    let mut hash = 0xcbf2_9ce4_8422_2325;
    for name in ["Cargo.toml", "Cargo.lock", "build.rs"] {
        hash_file(Path::new(name), &mut hash);
    }
    for name in ["src", "templates", "static", "migrations"] {
        hash_dir(Path::new(name), &mut hash);
    }
    println!("cargo:rustc-env=CONFIGDECK_BUILD_ID={hash:016x}");
    println!("cargo:rerun-if-env-changed=CONFIGDECK_BUILD_REVISION");
    let revision = env::var("CONFIGDECK_BUILD_REVISION").unwrap_or_default();
    let revision =
        if (7..=40).contains(&revision.len()) && revision.bytes().all(|b| b.is_ascii_hexdigit()) {
            &revision
        } else {
            "local"
        };
    println!("cargo:rustc-env=CONFIGDECK_BUILD_REVISION={revision}");
}
