// Generates Rust bindings from the protobuf source of truth.
// Re-runs whenever any .proto file changes.
fn main() -> Result<(), Box<dyn std::error::Error>> {
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
