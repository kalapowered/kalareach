//! Looking at a plugin host of a retained protocol.
//!
//! A control daemon serves the workers of a retained level, and those workers speak the plugin host
//! protocol their level recorded. When one of them asks for a plugin runtime, the daemon adopts a
//! host of that protocol that is running, and what it needs to know of one is the two things the
//! handshake settles: that the process behind the descriptor's endpoint speaks the protocol, and
//! that it is the process the descriptor names. This is that look, over raw frames and nothing
//! else. It opens no [`crate::client::PluginClient`], which speaks this build's protocol only, so
//! a request of this build's protocol is never written to a host of a retained one.
//!
//! The 0.78 cut, which stops retaining the level whose workers speak the first protocol, removes
//! this module with the protocol's route.

use kr_ipc::endpoint::Connection;
use kr_ipc::framed::split;
use kr_ipc::paths::{Endpoint, EnvironmentPaths};
use kr_protocol::frame::StreamKind;

use crate::error::{ServiceError, ServiceResult};
use crate::launcher;
use crate::protocol::{Frame, HostDescriptor, HostProtocol, Request, RequestBody, ResponseBody};

/// Connects to the host of `protocol` the environment's descriptor of that protocol names, asks it
/// to name its protocol and to prove which process it is, and returns the descriptor it proved.
///
/// The caller bounds the look in time. Nothing is sent but `Hello` and `Verify`.
///
/// # Errors
///
/// Returns [`ServiceError::Unavailable`] when there is no descriptor or the endpoint cannot be
/// reached, and [`ServiceError::Protocol`] when the host answers with something else or its proof
/// does not verify.
pub async fn probe(
    environment: &EnvironmentPaths,
    protocol: &HostProtocol,
) -> ServiceResult<HostDescriptor> {
    let descriptor = launcher::read_descriptor(environment, protocol)
        .map_err(unavailable)?
        .ok_or_else(|| ServiceError::Unavailable {
            detail: "this environment has no plugin host of that protocol".to_owned(),
        })?;
    let endpoint =
        Endpoint::from_path(&descriptor.endpoint).map_err(|error| ServiceError::Unavailable {
            detail: error.to_string(),
        })?;
    let connection =
        Connection::connect(&endpoint)
            .await
            .map_err(|error| ServiceError::Unavailable {
                detail: error.to_string(),
            })?;
    let (mut reader, mut writer) = split(connection, StreamKind::Control);

    let hello = ask(
        &mut reader,
        &mut writer,
        1,
        RequestBody::Hello {
            protocol: protocol.name.to_owned(),
        },
    )
    .await?;
    let ResponseBody::Hello {
        protocol: spoken, ..
    } = hello
    else {
        return Err(wrong_kind(&hello));
    };
    if spoken != protocol.name {
        return Err(ServiceError::Protocol {
            detail: format!("the host speaks {spoken}"),
        });
    }

    let nonce = launcher::fresh_challenge().map_err(unavailable)?;
    let verified = ask(&mut reader, &mut writer, 2, RequestBody::Verify { nonce }).await?;
    let ResponseBody::Verified(proof) = verified else {
        return Err(wrong_kind(&verified));
    };
    launcher::check_proof(&descriptor, &nonce, &proof).map_err(|error| ServiceError::Protocol {
        detail: error.to_string(),
    })?;
    Ok(descriptor)
}

/// Writes one request and reads frames until its answer, which a host that has no bindings sends
/// first.
async fn ask(
    reader: &mut kr_ipc::framed::FrameReader,
    writer: &mut kr_ipc::framed::FrameWriter,
    request_id: u64,
    body: RequestBody,
) -> ServiceResult<ResponseBody> {
    writer
        .write_message(&Request { request_id, body })
        .await
        .map_err(|error| ServiceError::Unavailable {
            detail: error.to_string(),
        })?;
    loop {
        let frame: Frame = reader
            .read_message_without_schema()
            .await
            .map_err(|error| ServiceError::Unavailable {
                detail: error.to_string(),
            })?;
        match frame {
            Frame::Response { reply_to, body } if reply_to == request_id => return Ok(body),
            Frame::Response { .. } | Frame::Notice(_) => {}
        }
    }
}

fn unavailable(error: launcher::LaunchError) -> ServiceError {
    ServiceError::Unavailable {
        detail: error.to_string(),
    }
}

fn wrong_kind(body: &ResponseBody) -> ServiceError {
    ServiceError::Protocol {
        detail: format!("an answer of the wrong kind: {body:?}"),
    }
}
