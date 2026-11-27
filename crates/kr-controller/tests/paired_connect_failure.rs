//! What the test helper's connect of a paired device says when it fails for good: the layer that
//! failed, the error's chain, how long the host and the dial had been up, every attempt with what
//! the dial offered and what the device's endpoint knew of the host, and the lines the process
//! logged.

mod net_support;

use base64::Engine as _;
use kr_client::ClientError;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::error::ErrorCode;
use kr_protocol::invitation::InviteEntry;
use kr_protocol::rights::ActionRight;
use kr_transport::TransportError;
use net_support::connect_report::{chain_of, layer_of};
use net_support::{Device, Host, pair_keeping_the_invitation, paired_dial, proposal};

/// The text a panic carries.
fn said(panic: Box<dyn std::any::Any + Send>) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .expect("a panic with a message")
}

/// The forms a secret of 32 bytes can take in a line.
fn forms(name: &str, bytes: &[u8; 32]) -> Vec<(String, String)> {
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    vec![
        (format!("{name} in lower case hex"), hex.clone()),
        (format!("{name} in upper case hex"), hex.to_uppercase()),
        (
            format!("{name} in base64"),
            base64::engine::general_purpose::STANDARD.encode(bytes),
        ),
        (
            format!("{name} in URL-safe base64"),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
        ),
        (
            format!("{name} as a list of numbers"),
            format!("{:?}", &bytes[..8])
                .trim_matches(['[', ']'])
                .to_owned(),
        ),
    ]
}

/// A device whose endpoint is shut cannot make a connection, so the helper gives up at its first
/// attempt, and the panic says what it knows and holds nothing a person keeps secret.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connect_that_fails_for_good_names_its_layer_its_chain_and_its_attempts() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = Device::create().await;
    let (record, invited, verification_value) = pair_keeping_the_invitation(
        &host,
        &device,
        &owner,
        proposal(&[ActionRight::SessionView]),
    )
    .await;
    let dial = paired_dial(&host, &device, &record);
    tracing::debug!(target: "kr_transport::listener", "a planted line of the host");
    device.endpoint().close().await;

    let failed = tokio::spawn(async move { dial.dial().await }).await;
    let message = match failed {
        Err(error) if error.is_panic() => said(error.into_panic()),
        _ => panic!("the connect of a device whose endpoint is shut fails for good"),
    };

    let offered = format!("the dial offered: {:?}", host.network().bound_sockets());
    for (part, wanted) in [
        ("the helper's own words", "the paired device connects"),
        ("the layer", "layer: the dial"),
        (
            "the error's chain",
            "the connection could not be established: ",
        ),
        ("the time since the host started", "since the host started"),
        ("the time since the first dial", "since the first dial"),
        ("the number of attempts", "attempts: 1"),
        ("the attempt's own line", "attempt 1 at +"),
        ("what the dial offered", offered.as_str()),
        (
            "what the device's endpoint knew of the host",
            "the device's endpoint is closed",
        ),
        ("a line of the process", "a planted line of the host"),
        (
            "that the lines are the process's",
            "the lines below are the process's",
        ),
    ] {
        assert!(message.contains(wanted), "no {part} in: {message}");
    }

    // What a person keeps secret is in no input of the message. Each form of it is looked for, and
    // so are the invitation, the pairing text and the value both devices showed, and the keys'
    // own rendering.
    let InviteEntry::Direct { qr_text } = &invited.entry else {
        panic!("a direct invitation is offered as a direct QR");
    };
    let payload = net_support::pairing::direct_payload(&invited);
    let mut secrets = forms(
        "the device's endpoint seed",
        device.keys().transport.export_endpoint_seed().expose(),
    );
    secrets.extend(forms(
        "the owner's endpoint seed",
        owner.transport.export_endpoint_seed().expose(),
    ));
    secrets.extend(forms("the pairing secret", payload.secret.expose()));
    secrets.push(("the pairing text".to_owned(), qr_text.as_str().to_owned()));
    secrets.push((
        "the invitation".to_owned(),
        invited.invitation_id.to_string(),
    ));
    // A short value can be a run of digits that a port or a time also holds.
    if verification_value.len() >= 12 {
        secrets.push(("the verification value".to_owned(), verification_value));
    }
    secrets.push((
        "the device's keys as they print".to_owned(),
        format!("{:?}", device.keys()),
    ));
    for (what, needle) in secrets {
        assert!(
            !message.contains(&needle),
            "the message holds {what}: {message}"
        );
    }
}

/// Each failure of the transport is named by the layer it is, and the chain keeps its text.
#[test]
fn each_failure_of_the_transport_is_named_by_its_layer() {
    let transport = |error: TransportError| ClientError::Transport(error);
    for (error, layer) in [
        (
            transport(TransportError::Connect("planted text".to_owned())),
            "the dial",
        ),
        (
            transport(TransportError::Stream("planted text".to_owned())),
            "the handshake's control stream",
        ),
        (
            transport(TransportError::Closed("planted text".to_owned())),
            "the host closed the connection",
        ),
        (
            transport(TransportError::handshake(
                ErrorCode::ResourceUnavailable,
                "planted text",
            )),
            "the handshake",
        ),
        (
            ClientError::ConnectionEnded,
            "the client, which is not a failure of the transport",
        ),
    ] {
        assert!(
            layer_of(&error).starts_with(layer),
            "{error}: {}",
            layer_of(&error)
        );
    }
    assert!(
        chain_of(&transport(TransportError::Connect(
            "planted text".to_owned()
        )))
        .ends_with("the connection could not be established: planted text")
    );
}
