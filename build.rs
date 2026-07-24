//! Copy the architecture-appropriate `wintun.dll` next to whatever cargo just
//! built.
//!
//! `wintun` loads its DLL at runtime rather than linking against it, so the
//! library has to sit somewhere the loader will find it. Putting it beside the
//! executable is the only placement that works for `cargo run`, `cargo test`,
//! and a shipped binary alike, so we do it here instead of asking every
//! consumer to remember.

use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=thirdparty/wintun");

    // Only Windows has a WinTun driver; elsewhere this crate does not build
    // anyway, but a no-op keeps `cargo metadata` and doc builds quiet.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "amd64",
        Ok("x86") => "x86",
        Ok("aarch64") => "arm64",
        Ok("arm") => "arm",
        Ok(other) => {
            println!("cargo:warning=no bundled wintun.dll for architecture {other}");
            return;
        }
        Err(_) => return,
    };

    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let source = manifest
        .join("thirdparty/wintun/bin")
        .join(arch)
        .join("wintun.dll");
    if !source.exists() {
        println!(
            "cargo:warning=wintun.dll not found at {}; the crate will fall back to the system \
             search path at runtime",
            source.display()
        );
        return;
    }

    // OUT_DIR is <target>/<profile>/build/<pkg>-<hash>/out; the profile
    // directory that holds our binaries is four levels up.
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("set by cargo"));
    let Some(profile_dir) = out_dir.ancestors().nth(3) else {
        return;
    };

    // Binaries land directly in the profile directory; test and example
    // executables land in these subdirectories.
    for dir in [
        profile_dir.to_path_buf(),
        profile_dir.join("deps"),
        profile_dir.join("examples"),
    ] {
        copy_into(&source, &dir);
    }
}

/// Copy `source` into `dir`, creating it if needed. Failures are warnings, not
/// errors: a missing DLL degrades to a clear runtime error, whereas failing the
/// build here would block work that does not need the driver at all.
fn copy_into(source: &Path, dir: &Path) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        println!("cargo:warning=could not create {}: {e}", dir.display());
        return;
    }
    let dest = dir.join("wintun.dll");
    if let Err(e) = std::fs::copy(source, &dest) {
        println!(
            "cargo:warning=could not copy wintun.dll to {}: {e}",
            dest.display()
        );
    }
}
