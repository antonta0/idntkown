#![warn(clippy::pedantic)]
#![allow(clippy::inline_always)]

pub mod schema;
pub mod utcstamp;

#[allow(dead_code)]
#[allow(clippy::pedantic)]
pub(crate) mod schema_v1_capnp {
    include!(concat!(env!("OUT_DIR"), "/capnp/schema_v1_capnp.rs"));
}
