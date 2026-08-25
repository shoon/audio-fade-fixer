fn main() {
    #[cfg(target_os = "windows")]
    embed_resource::compile_for("app.rc", ["audio-fade-fixer"], embed_resource::NONE)
        .manifest_required()
        .unwrap();
}
