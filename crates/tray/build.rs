fn main() {
    #[cfg(windows)]
    {
        let material_path = std::path::Path::new(&std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
            .join("material");

        let config = slint_build::CompilerConfiguration::new()
            .with_style("material".into())
            .with_library_paths(std::collections::HashMap::from([(
                "material".to_string(),
                material_path,
            )]));

        slint_build::compile_with_config("ui/app.slint", config)
            .expect("compile ui/app.slint");

        println!("cargo:rerun-if-changed=../../assets/stayline.ico");
        embed_resource::compile("stayline.rc", embed_resource::NONE)
            .manifest_optional()
            .expect("compile stayline.rc");
    }
}
