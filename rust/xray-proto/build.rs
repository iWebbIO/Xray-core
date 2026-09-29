use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn collect(dir: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    println!("cargo:rerun-if-changed={}", dir.display());
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            collect(&entry.path(), files)?;
        } else if entry.path().extension().is_some_and(|ext| ext == "proto") {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The schemas live beside the crate: the wire-format source of truth,
    // relocated from the retired Go reference tree (paths preserved so the
    // cross-file imports keep resolving against this root).
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join("proto");
    let mut files = Vec::new();
    for dir in ["app", "common", "core", "proxy", "transport"] {
        collect(&root.join(dir), &mut files)?;
    }
    files.sort();
    let out = PathBuf::from(env::var("OUT_DIR")?);
    prost_build::Config::new()
        .service_generator(tonic_prost_build::configure().service_generator())
        .protoc_executable(protoc_bin_vendored::protoc_bin_path()?)
        .include_file("xray.rs")
        .enable_type_names()
        .file_descriptor_set_path(out.join("xray_descriptor.bin"))
        .compile_protos(&files, &[root, protoc_bin_vendored::include_path()?])?;
    Ok(())
}
