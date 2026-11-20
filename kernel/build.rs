//! Link args for the kernel ELF. Uses absolute paths so the build works
//! from any working directory.
fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    println!("cargo:rustc-link-arg=-T{manifest}/linker.ld");
    // Keep file offsets small: without this, page alignment (2 MiB) pushes
    // the multiboot2 header past GRUB's 32768-byte search window and GRUB
    // refuses to boot ("multiboot2 header not found").
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=max-page-size=0x1000");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=src/entry.S");
}
