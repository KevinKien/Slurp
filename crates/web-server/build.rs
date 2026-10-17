use std::{
    env, fs,
    path::{Path, PathBuf},
};
fn collect(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) {
    for item in fs::read_dir(dir).expect("read UI directory") {
        let path = item.unwrap().path();
        assert!(!path.is_symlink(), "UI assets must not be symlinks");
        if path.is_dir() {
            collect(root, &path, files);
        } else {
            files.push(path.strip_prefix(root).unwrap().to_path_buf());
        }
    }
}
fn main() {
    println!("cargo:rerun-if-env-changed=SLURP_UI_DIR");
    let mut source = String::from("static ASSETS: &[(&str, &[u8])] = &[\n");
    if env::var_os("CARGO_FEATURE_EMBEDDED_UI").is_some() {
        let root = PathBuf::from(
            env::var_os("SLURP_UI_DIR")
                .expect("Build frontend first and set SLURP_UI_DIR (see scripts/build.mjs)"),
        );
        let root = fs::canonicalize(root).expect("UI directory missing");
        assert!(root.join("index.html").is_file(), "UI index.html missing");
        println!("cargo:rerun-if-changed={}", root.display());
        let mut files = Vec::new();
        collect(&root, &root, &mut files);
        files.sort();
        for path in files {
            let name = path.to_str().expect("UTF-8 UI path").replace('\\', "/");
            source.push_str(&format!(
                "({:?}, include_bytes!({:?})),\n",
                name,
                root.join(&path).to_str().unwrap()
            ));
        }
    }
    source.push_str("];\n");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("ui_assets.rs"),
        source,
    )
    .unwrap();
}
