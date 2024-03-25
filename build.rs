fn main() {
    ::capnpc::CompilerCommand::new()
        .file("capnp/schema_v1.capnp")
        .run()
        .expect("schema should compile");
}
