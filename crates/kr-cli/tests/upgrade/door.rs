//! A device at the door of an installed host: it pairs with the host's control daemon over the
//! network, as a phone does, and then connects to it with what the pairing gave it.
//!
//! The owner's half runs over the daemon's own local socket, as the command line does at a
//! terminal, with a key made for the ceremony. The device's half is a candidate on an endpoint of
//! its own, on the loopback interface, so nothing leaves this machine.

use std::sync::Arc;

use iroh::Endpoint;
use kr_client::session::Session;
use kr_crypto::connect::PairedPeer;
use kr_crypto::keys::DeviceKeys;
use kr_ipc::client::LocalClient;
use kr_ipc::paths::Endpoint as LocalEndpoint;
use kr_pairing::direct::{CandidateIdentity, redeem_proof};
use kr_protocol::ids::{DeviceId, DeviceKeyRevision, EnvironmentId};
use kr_protocol::invitation::InviteGrantKind;
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::pairing::{DeviceName, DevicePlatform};
use kr_protocol::preauth::{PairRedeemParams, PairRedeemResult};
use kr_transport::config::EndpointConfig;
use kr_transport::handshake::{self, LocalIdentity};

use super::pairing::{self, Signer};

/// An endpoint bound to the loopback interface.
fn loopback() -> EndpointConfig {
    EndpointConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
        ..EndpointConfig::default()
    }
}

/// A device that is paired with a host as its first owner and connected to it.
pub struct Door {
    /// The identity the host gave the device.
    pub device_id: DeviceId,
    /// The device's session with the host.
    pub session: Session,
    /// The endpoint the device dials from, kept for as long as the session is.
    _endpoint: Endpoint,
}

impl Door {
    /// Pairs a new device with the host whose control daemon answers on `controller`, as the
    /// host's first owner, and connects it.
    pub async fn pair_the_first_owner(
        controller: &LocalEndpoint,
        environment_id: EnvironmentId,
    ) -> Self {
        let build = super::build();
        let keys = DeviceKeys::generate().expect("device keys");
        let endpoint = kr_transport::endpoint::bind_dialer(&loopback(), &keys.transport)
            .await
            .expect("a dialling endpoint");
        let own_endpoint = *keys.transport.public();
        let revision = DeviceKeyRevision::new(1);
        // Before it is paired a device presents the identifier it expects to be given; the host
        // gives it its own at the commit.
        let unpaired = LocalIdentity::new(
            DeviceId::new(kr_ipc::new_uuid()),
            revision,
            own_endpoint,
            keys.authorisation.clone(),
            build.clone(),
        );
        let declared = CandidateIdentity {
            keys: keys.public_keys(),
            device_key_revision: revision,
            device_name: DeviceName::new("A test phone").expect("a name"),
            platform: DevicePlatform::Android,
            endpoint_id: own_endpoint,
        };

        // The owner's half, over the daemon's own socket. The first owner is confirmed by a key
        // made for the ceremony, which is what the command line does at an interactive terminal.
        let ceremony = DeviceKeys::generate().expect("a ceremony key");
        let signer = Signer::Bootstrap(&ceremony.authorisation);
        let mut client = LocalClient::connect(controller, LocalClientKind::Cli, build.clone())
            .await
            .expect("reaches the daemon");
        let invited = pairing::invite_direct(
            environment_id,
            &mut client,
            InviteGrantKind::PersonalOwner,
            &kr_pairing::grants::personal_owner_grant(),
            &signer,
        )
        .await
        .expect("the host issues its first owner's invitation");

        // The device's half: dial the host the invitation pins, prove the invitation's secret, and
        // keep what the host said of itself, which is what a later connection is checked against.
        let payload = pairing::direct_payload(&invited);
        let connection =
            pairing::dial_until_connected(&endpoint, pairing::host_addr(&payload)).await;
        let mut candidate = handshake::connect_unpaired(&connection, &unpaired)
            .await
            .expect("an unpaired connection");
        let PairRedeemResult::Challenge(challenge) = candidate
            .call(
                Method::PairRedeem,
                &PairRedeemParams::Challenge {
                    invitation_id: payload.invitation_id,
                },
            )
            .await
            .expect("the host issues a challenge")
        else {
            panic!("the first redemption step answers with a challenge");
        };
        let live_host = pairing::HostPeer(*challenge.endpoint_id.as_bytes());
        let (proof, _transcript) = redeem_proof(
            &payload,
            &challenge,
            &keys.authorisation,
            &declared,
            &live_host,
        )
        .expect("a redemption proof");
        let locked: PairRedeemResult = candidate
            .call(
                Method::PairRedeem,
                &PairRedeemParams::Direct(Box::new(proof)),
            )
            .await
            .expect("the host accepts the redemption");
        assert!(
            matches!(locked, PairRedeemResult::Locked { .. }),
            "a redemption locks the invitation"
        );
        let host = PairedPeer {
            device_id: candidate.selection.device_id,
            device_key_revision: challenge.device_key_revision,
            authorisation: challenge.host_keys.authorisation,
            endpoint_id: payload.endpoint_id,
        };

        let confirmed =
            pairing::confirm_candidate(environment_id, &mut client, invited.invitation_id, &signer)
                .await
                .expect("the first owner is confirmed");
        assert!(
            confirmed.event.first_owner,
            "the bootstrap establishes the first owner"
        );
        connection.close(0u32.into(), b"paired");

        // And the paired device connects, as itself.
        let paired = LocalIdentity::new(
            confirmed.device_id,
            revision,
            own_endpoint,
            keys.authorisation.clone(),
            build,
        );
        let transport = pairing::connect_until_answered(
            &endpoint,
            pairing::host_addr(&payload),
            &paired,
            &host,
        )
        .await
        .expect("the paired device connects");
        Self {
            device_id: confirmed.device_id,
            session: Session::start(Arc::new(transport)).expect("a session"),
            _endpoint: endpoint,
        }
    }
}
