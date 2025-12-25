//! NOMAD Echo Example
//!
//! A simple echo state implementation for conformance testing.
//! See CONFORMANCE.md for the expected interface.
//!
//! Environment variables:
//! - NOMAD_MODE: "server" or "client"
//! - NOMAD_SERVER_PRIVATE_KEY: Base64-encoded server private key (server only)
//! - NOMAD_SERVER_PUBLIC_KEY: Base64-encoded server public key (both)
//! - NOMAD_SERVER_HOST: Server hostname (client only)
//! - NOMAD_SERVER_PORT: Server port (client only)
//! - NOMAD_BIND_ADDR: Bind address (server only, default 0.0.0.0:19999)
//! - NOMAD_LOG_LEVEL: debug|info|warn|error

mod client;
mod health;
mod server;
mod state;

fn main() {
    // TODO: Parse environment and run server or client
    println!("nomad-echo: Not yet implemented");
}
