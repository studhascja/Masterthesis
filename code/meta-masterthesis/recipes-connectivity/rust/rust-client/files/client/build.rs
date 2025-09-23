use std::env;
use libbpf_cargo::SkeletonBuilder;

fn main() {
    let kernel_headers = env::var("KERNEL_HEADERS").unwrap_or("/usr/src/kernel".to_string());
    SkeletonBuilder::new()
        .source("src/bpf/monitore.bpf.c")
        .clang_args(&format!("-I{}/arch/arm64/include/generated/uapi -I{}/include -I{}/include/uapi -I{}/include/generated", kernel_headers, kernel_headers, kernel_headers, kernel_headers))
        .build_and_generate("src/bpf/monitore.skel.rs")
        .unwrap();
}
