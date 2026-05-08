// Generates Rust bindings from the protobuf source of truth.
// Re-runs whenever any .proto file changes.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use the vendored protoc binary so contributors don't need it on PATH.
    if std::env::var_os("PROTOC").is_none() {
        if let Ok(p) = protoc_bin_vendored::protoc_bin_path() {
            // Safety: we are pre-main, no other thread can be reading env.
            unsafe {
                std::env::set_var("PROTOC", p);
            }
        }
    }

    let proto_root = "../proto";
    let protos = &[
        "../proto/edr/v1/common.proto",
        "../proto/edr/v1/events.proto",
        "../proto/edr/v1/control.proto",
    ];

    for p in protos {
        println!("cargo:rerun-if-changed={p}");
    }

    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(protos, &[proto_root])?;
    Ok(())
}
