//! The control daemon's three local endpoints, bound together, and the one line it writes when it
//! cannot.
//!
//! The daemon binds the rendezvous, control and transfer endpoints, in that order, after it holds
//! its environment. A bind that is refused is told by the evidence the bind itself gave
//! ([`kr_ipc::listen::ListenRefusal`]) and written as one line of a fixed grammar
//! ([`kr_ipc::listen::ListenLine`]), which the command line that started the daemon reads back to
//! say why the daemon ended. Any other failure is written as the bare error, which the command
//! line does not repeat.

use kr_ipc::IpcError;
use kr_ipc::endpoint::Listener;
use kr_ipc::listen::{ListenLine, ListenRole};
use kr_ipc::paths::{Endpoint, EnvironmentPaths};

/// The endpoints the daemon serves on, bound and held.
#[derive(Debug)]
pub struct LocalEndpoints {
    /// Where workers and plugin hosts report in.
    pub rendezvous: Listener,
    /// Where clients send commands.
    pub control: Listener,
    /// Where attachment chunks are sent.
    pub chunks: Listener,
}

/// Why one endpoint could not be bound, and which.
#[derive(Debug)]
pub struct BindFailure {
    role: ListenRole,
    cause: Cause,
}

#[derive(Debug)]
enum Cause {
    /// The endpoint has no address in this environment.
    Address(String),
    /// The bind was refused.
    Bind(IpcError),
}

impl BindFailure {
    /// The endpoint that could not be bound.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    pub const fn role(&self) -> ListenRole {
        self.role
    }

    /// The one line the daemon writes for this failure, as process `daemon`: the listen line when
    /// the bind's refusal is typed, and the bare error otherwise.
    #[must_use]
    pub fn line(&self, daemon: u32) -> String {
        if let Cause::Bind(IpcError::Listen { endpoint, refusal }) = &self.cause {
            let line = ListenLine {
                role: self.role,
                refusal: refusal.clone(),
                path: endpoint.clone(),
                daemon,
            };
            if let Some(written) = line.written(&refusal.said(endpoint)) {
                return written;
            }
        }
        format!("kr-controller: {self}")
    }
}

impl std::fmt::Display for BindFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let role = self.role.word();
        match &self.cause {
            Cause::Address(error) => write!(
                formatter,
                "the {role} endpoint cannot be addressed: {error}"
            ),
            Cause::Bind(error) => write!(formatter, "the {role} endpoint cannot be bound: {error}"),
        }
    }
}

impl std::error::Error for BindFailure {}

/// Binds the rendezvous, control and transfer endpoints of `environment`, in that order.
///
/// # Errors
///
/// Returns the first endpoint that has no address or whose bind was refused. The ones bound before
/// it are let go with the error.
pub fn bind_local_endpoints(environment: &EnvironmentPaths) -> Result<LocalEndpoints, BindFailure> {
    fn bind<E: std::fmt::Display>(
        role: ListenRole,
        endpoint: Result<Endpoint, E>,
    ) -> Result<Listener, BindFailure> {
        let endpoint = endpoint.map_err(|error| BindFailure {
            role,
            cause: Cause::Address(error.to_string()),
        })?;
        Listener::bind(&endpoint).map_err(|error| BindFailure {
            role,
            cause: Cause::Bind(error),
        })
    }
    let rendezvous = bind(ListenRole::Rendezvous, environment.rendezvous_endpoint())?;
    let control = bind(ListenRole::Control, environment.controller_endpoint())?;
    // A 1 MiB attachment chunk does not fit a control frame, so transfer chunks have their own
    // endpoint, framed at the attachment bound and served by the same admission path.
    let chunks = bind(
        ListenRole::Transfer,
        kr_transfer::chunks::chunk_endpoint(environment),
    )?;
    Ok(LocalEndpoints {
        rendezvous,
        control,
        chunks,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use kr_ipc::listen::{ListenRefusal, ObjectKind};

    use super::*;

    /// A file at each of the three endpoints in turn is named for its role and for what it is, and
    /// the line written for it reads back as the same record. No daemon starts and nothing reaches
    /// a service manager.
    #[tokio::test]
    async fn the_daemons_three_binds_name_their_role() {
        for role in ListenRole::ALL {
            let host = kr_ipc::testing::TempHost::create();
            let environment = host.environment();
            let endpoint = match role {
                ListenRole::Rendezvous => environment.rendezvous_endpoint().expect("an endpoint"),
                ListenRole::Control => environment.controller_endpoint().expect("an endpoint"),
                ListenRole::Transfer => {
                    kr_transfer::chunks::chunk_endpoint(&environment).expect("an endpoint")
                }
            };
            std::fs::write(endpoint.as_path(), b"mine").expect("a file at the endpoint");
            let failure = bind_local_endpoints(&environment)
                .expect_err("a file at the endpoint refuses the bind");
            assert_eq!(failure.role(), role);
            let line = failure.line(77);
            assert_eq!(
                ListenLine::parse(&line),
                Some(ListenLine {
                    role,
                    refusal: ListenRefusal::NotASocket {
                        object: ObjectKind::File
                    },
                    path: endpoint.as_text(),
                    daemon: 77,
                }),
                "{line}"
            );
            assert_eq!(
                std::fs::read(endpoint.as_path()).expect("the file"),
                b"mine"
            );
        }
    }

    /// A failure that is not a typed refusal is written as the bare error, which no reader repeats.
    #[test]
    fn a_failure_without_a_refusal_is_written_bare() {
        let failure = BindFailure {
            role: ListenRole::Transfer,
            cause: Cause::Address("no runtime directory".to_owned()),
        };
        let line = failure.line(1);
        assert_eq!(
            line,
            "kr-controller: the transfer endpoint cannot be addressed: no runtime directory"
        );
        assert_eq!(ListenLine::parse(&line), None);
    }
}
