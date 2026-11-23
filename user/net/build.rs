//! Link args for the hito-4 user editor ELF (same contract as `user/shell`).

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    // Code model is scoped to the xtask cargo invocation (`-C code-model=large`),
    // never to the kernel's build.
    println!("cargo:rustc-link-arg=-T{manifest}/user.ld");
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=max-page-size=0x1000");
    println!("cargo:rerun-if-changed=user.ld");
    println!("cargo:rerun-if-changed=start.S");
}
