fn main() {
    #[cfg(windows)]
    slint_build::compile_with_config(
        "ui/app.slint",
        slint_build::CompilerConfiguration::new().with_style("fluent".into()),
    )
    .expect("compile ui/app.slint");
}
