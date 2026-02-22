// FRD: specs/frds/FRD-M002-uniffi-interface.md

fn main() {
    uniffi::generate_scaffolding("src/mobile.udl").unwrap();
}
