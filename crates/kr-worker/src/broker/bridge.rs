//! The native bridge an application starts beside its unchanged terminal.
//!
//! Section 11 lets a package install "a minimal bridge in an application's documented native
//! plugin or hook location", and prefers "a small registration file plus the core `kr-hook`
//! forwarder". The application then starts the forwarder itself, as often as its own
//! configuration says: once for a channel server that lives as long as the session, and once for
//! every hook it runs. None of those processes is the process this host launched. Each is a process
//! the launched application started, and that is what this module admits.
//!
//! A bridge connection is admitted only when all of these hold, and each is checked by the host
//! rather than believed:
//!
//! * **The local peer.** On a private socket the kernel names the connecting process and its user,
//!   and the process the hello presents must be the one the kernel named.
//! * **The launch binding.** The connecting process is the launched application or one it started,
//!   found by the kernel's parent chain with every link checked by its start identity.
//! * **The private exchange.** The hello carries the credential this host generated for the launch
//!   and wrote to an owner-only file.
//! * **The installation.** The hello declares which bridge it is, and the declaration must name the
//!   application and a surface the installation recorded for this launch; the connecting process
//!   must be running the forwarder the installation put in place, where the platform can say what a
//!   process is running.
//!
//! A session identifier in the environment is carried in the hello and decides none of them.
//! Section 5: "An environment variable can identify a candidate session to an integration. It is
//! not a credential. The host validates the integration's local peer, installation and session
//! binding before accepting events or actions."

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::PluginId;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::broker::error::{BrokerError, Result};
use crate::broker::framing::Framing;

/// How long an admitted bridge has to send a frame the host is waiting for.
///
/// A hook sends its one observation straight after its hello, so anything slower than this is a
/// bridge that is not going to send it.
pub const BRIDGE_FRAME_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

/// One of the registrations an installed bridge put into the application's configuration.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BridgeSurface {
    /// A lifecycle or tool hook: one short-lived process per event, which observes.
    Hook,
    /// A channel server: one process for as long as the application's session lasts.
    Channel,
}

impl BridgeSurface {
    /// Returns the stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hook => "hook",
            Self::Channel => "channel",
        }
    }
}

/// What a connecting bridge says it is.
///
/// It is a claim. [`InstalledBridge::validate`] is what decides whether the installation this host
/// recorded for the launch includes it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeDeclaration {
    /// The application whose registration started the bridge.
    pub application: String,
    /// Which of its registrations it was.
    pub surface: BridgeSurface,
}

/// The native bridge an installation put in place for one launch's application.
///
/// It is what the host recorded when the connector package's bridge was installed: the package it
/// came from, the application name its registration invokes the forwarder for, the surfaces the
/// recipe registered, and the forwarder executable it points the application at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledBridge {
    /// The connector package whose native bridge this is.
    pub plugin_id: PluginId,
    /// The application name the installed registration invokes the forwarder for.
    pub application: String,
    /// The surfaces the installed recipe registered.
    pub surfaces: BTreeSet<BridgeSurface>,
    /// The forwarder executable the installed registration starts.
    pub forwarder: PathBuf,
}

impl InstalledBridge {
    /// Checks one bridge's declaration, and the executable its process runs, against this
    /// installation.
    ///
    /// `running` is the executable the operating system says the connecting process is running,
    /// where the platform can name one. A process whose executable cannot be named is refused: the
    /// installation cannot be validated for a process nobody can identify.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] naming what did not match.
    pub fn validate(&self, declared: &BridgeDeclaration, running: Option<&Path>) -> Result<()> {
        if declared.application != self.application {
            return Err(BrokerError::denied(format!(
                "this connection declares a bridge for {:?}, and the bridge installed for this \
                 launch is {:?}'s",
                declared.application, self.application
            )));
        }
        if !self.surfaces.contains(&declared.surface) {
            return Err(BrokerError::denied(format!(
                "this connection declares the {} registration, which the installed bridge does not \
                 have",
                declared.surface.as_str()
            )));
        }
        let Some(running) = running else {
            return Err(BrokerError::denied(
                "the operating system did not name the executable this connection runs, so it \
                 cannot be the installed forwarder",
            ));
        };
        let installed = std::fs::canonicalize(&self.forwarder).map_err(|error| {
            BrokerError::denied(format!(
                "the installed forwarder {} cannot be read: {error}",
                self.forwarder.display()
            ))
        })?;
        let running = std::fs::canonicalize(running).map_err(|error| {
            BrokerError::denied(format!(
                "the executable this connection runs, {}, cannot be read: {error}",
                running.display()
            ))
        })?;
        if running != installed {
            return Err(BrokerError::denied(format!(
                "this connection runs {}, and the installed forwarder is {}",
                running.display(),
                installed.display()
            )));
        }
        Ok(())
    }
}

/// A bridge this host admitted.
#[derive(Debug)]
pub struct AdmittedBridge {
    /// Which registration it is.
    pub surface: BridgeSurface,
    /// The process, as the kernel named it where it could.
    pub process: ProcessStartIdentity,
    /// The connection it speaks on.
    pub stream: BridgeStream,
}

/// The connection one admitted bridge speaks on.
///
/// Frames are read and written in the connector's own framing, and each is bounded by the gateway's
/// native frame bound. Whatever was read past the hello before the bridge was admitted is held
/// here and read first, so nothing a bridge pipelined behind its hello is lost or read twice.
pub struct BridgeStream {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    held: Vec<u8>,
    framing: Framing,
}

impl std::fmt::Debug for BridgeStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BridgeStream")
            .field("held", &self.held.len())
            .field("framing", &self.framing)
            .finish_non_exhaustive()
    }
}

impl BridgeStream {
    /// Wraps the two halves of an admitted connection.
    #[must_use]
    pub fn new(
        reader: Box<dyn AsyncRead + Unpin + Send>,
        writer: Box<dyn AsyncWrite + Unpin + Send>,
        held: Vec<u8>,
        framing: Framing,
    ) -> Self {
        Self {
            reader,
            writer,
            held,
            framing,
        }
    }

    /// Reads one whole frame, or `None` when the bridge has closed the connection between frames.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] for a frame past the bound or a connection that
    /// ends in the middle of one, and [`BrokerError::UpstreamUnavailable`] when reading fails.
    pub async fn read_frame(&mut self) -> Result<Option<Vec<u8>>> {
        let mut chunk = [0_u8; 8192];
        loop {
            if let Some(body) = self.framing.decode(&mut self.held)? {
                return Ok(Some(body));
            }
            let read = self.reader.read(&mut chunk).await.map_err(|error| {
                BrokerError::UpstreamUnavailable {
                    detail: format!("the bridge's connection could not be read: {error}"),
                }
            })?;
            if read == 0 {
                if self.held.is_empty() {
                    return Ok(None);
                }
                return Err(BrokerError::invalid(
                    "the bridge closed its connection in the middle of a frame",
                ));
            }
            self.held.extend_from_slice(&chunk[..read]);
        }
    }

    /// Writes one frame.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] for a frame past the bound, and
    /// [`BrokerError::UpstreamUnavailable`] when the write fails.
    pub async fn write_frame(&mut self, body: &[u8]) -> Result<()> {
        if body.len() > crate::broker::gateway::MAX_NATIVE_FRAME_BYTES {
            return Err(BrokerError::invalid(format!(
                "a frame for a bridge is at most {} bytes and this one is {}",
                crate::broker::gateway::MAX_NATIVE_FRAME_BYTES,
                body.len()
            )));
        }
        let framed = self.framing.encode(body);
        self.writer
            .write_all(&framed)
            .await
            .and(self.writer.flush().await)
            .map_err(|error| BrokerError::UpstreamUnavailable {
                detail: format!("the bridge's connection could not be written: {error}"),
            })
    }

    /// Closes the host's direction, so the bridge reads the end of what this host sends.
    pub async fn close(&mut self) {
        let _ = self.writer.shutdown().await;
    }
}

/// The frame an admitted bridge is answered with, before anything else this host writes to it.
#[must_use]
pub fn admission_frame(surface: BridgeSurface) -> Vec<u8> {
    serde_json::json!({ "kr_bridge": { "admitted": surface.as_str() } })
        .to_string()
        .into_bytes()
}

impl crate::broker::Broker {
    /// Checks the private exchange a bridge presents against the launch it claims.
    ///
    /// The launch's record holds the credential, so this is where it is compared, and the
    /// credential never leaves it. The comparison is the host's own constant-time one.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such instance, and
    /// [`BrokerError::PermissionDenied`] when this host launched nothing for it or the credential
    /// is not the launch's.
    pub fn admit_bridge_exchange(
        &self,
        application_instance_id: kr_protocol::ids::ApplicationInstanceId,
        presented: &[u8],
    ) -> Result<()> {
        let state = self.state();
        let instance = state
            .instances
            .get(&application_instance_id)
            .ok_or_else(|| crate::broker::unknown_instance(application_instance_id))?;
        let launched = instance.process.as_ref().ok_or_else(|| {
            BrokerError::denied(
                "this host did not launch this application, so no bridge it started can be \
                 authenticated against it",
            )
        })?;
        if !launched.authenticates_exchange(presented) {
            return Err(BrokerError::denied(
                "this connection did not present the private exchange of the launch it claims",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::gateway::NativeFraming;

    fn installed(forwarder: PathBuf) -> InstalledBridge {
        InstalledBridge {
            plugin_id: PluginId::new("kalareach/claude-code").expect("valid"),
            application: "claude-code".to_owned(),
            surfaces: [BridgeSurface::Hook, BridgeSurface::Channel]
                .into_iter()
                .collect(),
            forwarder,
        }
    }

    fn declared(application: &str, surface: BridgeSurface) -> BridgeDeclaration {
        BridgeDeclaration {
            application: application.to_owned(),
            surface,
        }
    }

    /// KR-REQ-05.09: the declaration and the executable are checked against the installation the
    /// host recorded, and each part that does not match refuses the connection.
    #[test]
    fn kr_req_05_09_a_bridge_is_the_installation_or_it_is_refused() {
        let this = std::env::current_exe().expect("this test's executable");
        let bridge = installed(this.clone());
        for surface in [BridgeSurface::Hook, BridgeSurface::Channel] {
            bridge
                .validate(&declared("claude-code", surface), Some(&this))
                .expect("the installation's own forwarder, for a surface it registered");
        }

        let refusals = [
            bridge.validate(&declared("codex", BridgeSurface::Hook), Some(&this)),
            bridge.validate(&declared("claude-code", BridgeSurface::Hook), None),
            bridge.validate(
                &declared("claude-code", BridgeSurface::Hook),
                Some(Path::new("/nonexistent/kalareach/kr-hook")),
            ),
        ];
        for refused in refusals {
            let refused = refused.expect_err("refused");
            assert_eq!(
                refused.code(),
                kr_protocol::error::ErrorCode::PermissionDenied,
                "{refused}"
            );
        }

        // A surface the recipe did not register is not one this installation has.
        let hooks_only = InstalledBridge {
            surfaces: std::iter::once(BridgeSurface::Hook).collect(),
            ..bridge
        };
        assert!(
            hooks_only
                .validate(
                    &declared("claude-code", BridgeSurface::Channel),
                    Some(&this)
                )
                .is_err()
        );
        // And another executable is not the installed forwarder, wherever it lives.
        let elsewhere = installed(PathBuf::from("/nonexistent/kalareach/kr-hook"));
        assert!(
            elsewhere
                .validate(&declared("claude-code", BridgeSurface::Hook), Some(&this))
                .is_err()
        );
    }

    #[test]
    fn a_declaration_names_exactly_an_application_and_a_surface() {
        let parsed: BridgeDeclaration =
            serde_json::from_str(r#"{"application":"claude-code","surface":"hook"}"#)
                .expect("a declaration");
        assert_eq!(parsed, declared("claude-code", BridgeSurface::Hook));
        for refused in [
            r#"{"application":"claude-code","surface":"tool"}"#,
            r#"{"application":"claude-code"}"#,
            r#"{"application":"claude-code","surface":"hook","grant":"all"}"#,
        ] {
            assert!(
                serde_json::from_str::<BridgeDeclaration>(refused).is_err(),
                "{refused}"
            );
        }
    }

    #[tokio::test]
    async fn a_stream_reads_what_was_held_first_and_refuses_a_cut_frame() {
        let (here, mut there) = tokio::io::duplex(1 << 16);
        let (reader, writer) = tokio::io::split(here);
        let mut stream = BridgeStream::new(
            Box::new(reader),
            Box::new(writer),
            b"{\"held\":1}\n{\"hel".to_vec(),
            Framing::new(NativeFraming::JsonLines),
        );
        there.write_all(b"d\":2}\n").await.expect("written");
        assert_eq!(
            stream.read_frame().await.expect("read"),
            Some(b"{\"held\":1}".to_vec())
        );
        assert_eq!(
            stream.read_frame().await.expect("read"),
            Some(b"{\"held\":2}".to_vec())
        );
        there.write_all(b"{\"cut\"").await.expect("written");
        drop(there);
        assert!(stream.read_frame().await.is_err(), "a cut frame is refused");
    }

    #[tokio::test]
    async fn a_frame_past_the_bound_is_not_written() {
        let (here, _there) = tokio::io::duplex(1 << 16);
        let (reader, writer) = tokio::io::split(here);
        let mut stream = BridgeStream::new(
            Box::new(reader),
            Box::new(writer),
            Vec::new(),
            Framing::new(NativeFraming::JsonLines),
        );
        let oversized = vec![b'x'; crate::broker::gateway::MAX_NATIVE_FRAME_BYTES + 1];
        assert!(stream.write_frame(&oversized).await.is_err());
        assert_eq!(
            admission_frame(BridgeSurface::Channel),
            br#"{"kr_bridge":{"admitted":"channel"}}"#.to_vec()
        );
    }
}
