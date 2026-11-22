//! Link args for the first userland ELF. Absolute paths so the build works
//! from any working directory (same pattern as `kernel/build.rs`).

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    println!("cargo:rustc-link-arg=-T{manifest}/user.ld");
    // 4 KiB is the x86-64 base page size and matches the kernel's own
    // linker build arg. Every PT_LOAD then has p_vaddr % 4096 == p_offset
    // % 4096, so the ELF loader can map with a flat file→frame copy plus a
    // zero-fill of p_filesz..p_memsz.
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=max-page-size=0x1000");
    println!("cargo:rerun-if-changed=user.ld");
    println!("cargo:rerun-if-changed=start.S");
}
