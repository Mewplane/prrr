// FRD: specs/frds/FRD-M008-android-project-setup.md
// Temporary binding generator for UniFFI 0.28

fn main() {
    let udl_file = std::path::Path::new("src/mobile.udl");

    // Generate Kotlin bindings
    let out_dir_kotlin = std::path::Path::new("bindings/kotlin");
    std::fs::create_dir_all(out_dir_kotlin).unwrap();

    uniffi::generate_bindings(udl_file, None, vec!["kotlin".to_string()], Some(out_dir_kotlin), None, false).unwrap();

    println!("✓ Kotlin bindings generated in bindings/kotlin/");
}
