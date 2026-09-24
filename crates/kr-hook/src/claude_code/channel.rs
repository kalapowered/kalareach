//! Claude Code's Channels server.
//!
//! Claude Code starts `kr-hook claude-code channel` as an MCP server over this process's standard
//! input and output. The forwarder terminates MCP here: the handshake, the version negotiation and
//! the capability declaration are this module's.
//!
//! The protocol revision is held below `2026-07-28`, because the Channels documentation says Claude
//! Code does not register a channel server that negotiates that revision on its v2 MCP client
//! runtime.

use std::borrow::Cow;

use rmcp::model::{Implementation, ProtocolVersion, ServerCapabilities, ServerConfig};
use rmcp::{ServerHandler, ServiceExt as _};

/// The name this server introduces itself by.
pub const SERVER_NAME: &str = "kalareach";

/// The newest MCP protocol revision this server negotiates.
///
/// Claude Code registers no channel server that negotiates `2026-07-28` on its v2 MCP client
/// runtime, so the newest revision this server offers is the one before it.
pub const NEWEST_REVISION: ProtocolVersion = ProtocolVersion::V_2025_11_25;

/// Runs the server until Claude Code closes its end.
#[must_use]
pub fn run() -> std::process::ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            crate::report(&format!("the channel could not start: {error}"));
            return std::process::ExitCode::from(crate::cli::EXIT_FAILURE);
        }
    };
    match runtime.block_on(serve()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(failure) => {
            crate::report(&failure);
            std::process::ExitCode::from(crate::cli::EXIT_FAILURE)
        }
    }
}

async fn serve() -> Result<(), String> {
    let transport = rmcp::transport::async_rw::AsyncRwTransport::new_server(
        tokio::io::stdin(),
        tokio::io::stdout(),
    );
    let service = Channel
        .serve(transport)
        .await
        .map_err(|error| format!("the MCP session could not start: {error}"))?;
    service
        .waiting()
        .await
        .map_err(|error| format!("the MCP session ended badly: {error}"))?;
    Ok(())
}

/// The MCP side of the channel.
#[derive(Clone, Copy, Debug)]
struct Channel;

impl ServerHandler for Channel {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::default())
            .with_server_info(Implementation::new(SERVER_NAME, env!("CARGO_PKG_VERSION")))
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(ProtocolVersion::known_up_to(&NEWEST_REVISION))
    }
}
