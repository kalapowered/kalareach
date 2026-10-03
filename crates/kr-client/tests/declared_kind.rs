//! What a local client says it is, in the first frame it sends.
//!
//! The host starts a session with the environment of whoever created it, and a client's declared
//! kind is how it tells the command line, which sends its own environment, from the companion app,
//! which has none to send. The companion that declared itself the command line would be read as
//! sending an environment of its own and get none of the host's.

use kr_client::ipc::IpcTransport;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::BuildId;
use kr_protocol::local::LocalClientKind;

/// Connects as the command line or as the app, and reads the kind off the hello the host receives.
async fn declared(app: bool) -> LocalClientKind {
    let tree = kr_ipc::testing::TempHost::create();
    let endpoint = tree
        .paths()
        .environment(tree.environment_id())
        .controller_endpoint()
        .expect("a controller endpoint");
    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("a local endpoint");
    let heard = tokio::spawn(async move {
        let (connection, _) = listener.accept().await.expect("a client connects");
        let (mut reader, _writer) = kr_ipc::framed::split(connection, StreamKind::Control);
        match reader.read_message::<ControlFrame>().await {
            Ok(ControlFrame::Hello(hello)) => hello.client,
            other => panic!("the first frame is a hello: {other:?}"),
        }
    });
    let build = BuildId::new("kr/0.1.0+test").expect("a build identity");
    // The host never answers, so the connection never completes: the hello is what is read, and
    // what the connection comes to is of no interest.
    let connecting = tokio::spawn(async move {
        let _ = if app {
            IpcTransport::connect_app(&endpoint, build).await
        } else {
            IpcTransport::connect(&endpoint, build).await
        };
    });
    let kind = heard.await.expect("the hello is read");
    connecting.abort();
    kind
}

/// The command line declares itself the command line, and the companion declares itself the app.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_command_line_and_the_app_each_declare_their_own_kind() {
    assert_eq!(declared(false).await, LocalClientKind::Cli);
    assert_eq!(declared(true).await, LocalClientKind::App);
}
