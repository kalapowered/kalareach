//! A paired device's page of a live session's retained output, over a real paired connection.
//!
//! The daemon forwards a device's `history.page` to the session's worker with the history scope of
//! the grant it decided the read under. The worker narrows the page to the output its record of
//! when each part was produced proves was written at or after the first moment the scope reaches,
//! and serves nothing before that. These cases run the product's own worker over a real terminal
//! behind a real daemon, pair real devices under real grants, and read the pages the phone's
//! terminal view is built from.
//!
//! The application in the session follows a file, so the output is written when the case writes the
//! file, and two bursts of output, with the clock moving on between them, are two intervals of the
//! worker's record. A case reads that record back from its file before it asks, so a premise that
//! did not hold fails by saying so rather than by passing on a page that proved nothing.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-13.15 | the cases here |
//! | KR-REQ-10.49 | the cases here |

#![cfg(unix)]

mod net_support;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kr_client::error::ClientError;
use kr_client::session::Session;
use kr_controller::service::net::devices::DeviceRecord;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, AttachmentViewportParams, SessionAttachParams,
    SessionAttachResult, ViewportPosition,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::grant::SessionSelector;
use kr_protocol::ids::{ActionId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::pairing::ProposedGrant;
use kr_protocol::privacy::{
    PrivacyCompletion, PrivacyReport, PrivacySetParams, PrivacyStatusParams,
};
use kr_protocol::recovery::{HistoryPageParams, HistoryPageResult};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, TimestampMs, U64};
use kr_protocol::session::Dimensions;
use kr_protocol::sharing::{GrantRedeemParams, RoleSelection, SessionRole};
use net_support::worker::Worker;
use net_support::{
    Device, Host, RawDevice, an_open_session, connect, on_the_host, pair_with, proposal, share_with,
};

/// How long a case waits for something the worker or the daemon has to do.
const PATIENCE: Duration = Duration::from_secs(60);

/// The most a page is asked to carry, far beyond what these cases write.
const WHOLE: u64 = 1024 * 1024;

/// A burst of output: more than the bytes an interval holds before the next output may close it.
fn burst(byte: u8) -> Vec<u8> {
    vec![byte; 300]
}

/// `count` lines that begin with `label`, enough of them to scroll the first off a screen of 24 rows.
fn lines(label: &str, count: usize) -> Vec<u8> {
    (0..count)
        .flat_map(|number| format!("{label} {number}\n").into_bytes())
        .collect()
}

/// Waits until `holds` says it does.
async fn until<F, Fut>(what: &str, mut holds: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while !holds().await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not happen"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Waits until the clock the worker times output by has moved on by `by`: long enough for the
/// interval the last output opened to be one the next output closes.
async fn until_the_clock_has_moved(by: Duration) {
    let until_then = kr_ipc::clock::boot_elapsed_ms()
        .saturating_add(u64::try_from(by.as_millis()).unwrap_or(u64::MAX));
    until("the clock moving on", || async {
        kr_ipc::clock::boot_elapsed_ms() >= until_then
    })
    .await;
}

/// The application: it says it is ready and then prints whatever is added to a file.
fn application(output: &Path) -> String {
    format!(
        "printf 'kr-ready.'; exec tail -f -n 0 '{}'",
        output.display()
    )
}

/// A paired device's session, with the device it belongs to: the connection ends with the device.
struct Connected {
    session: Session,
    _device: Device,
}

impl std::ops::Deref for Connected {
    type Target = Session;

    fn deref(&self) -> &Session {
        &self.session
    }
}

/// A daemon, a worker over a real terminal whose time service keeps its clock, and the owner.
struct Rig {
    host: Host,
    worker: Worker,
    owner: DeviceKeys,
    output: PathBuf,
    _kept: tempfile::TempDir,
}

impl Rig {
    async fn start() -> Self {
        let kept = tempfile::tempdir().expect("a directory for what the application follows");
        let output = kept.path().join("output");
        std::fs::write(&output, b"").expect("the file the application follows");
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start(&owner).await;
        let stopped = host.shut_down().await;
        let worker =
            Worker::start_running_on_a_kept_clock(stopped.tree(), 1, &application(&output)).await;
        let settings = stopped.settings().clone();
        let host = stopped.start(settings).await;
        let rig = Self {
            host,
            worker,
            owner,
            output,
            _kept: kept,
        };
        rig.until_adopted().await;
        until("the application's first output", || async {
            rig.owner_page(0)
                .await
                .bytes
                .as_slice()
                .ends_with(b"kr-ready.")
        })
        .await;
        rig
    }

    /// Waits until the daemon serves the worker's session.
    async fn until_adopted(&self) {
        until("the daemon reaching the worker", || async {
            self.host
                .client()
                .await
                .request(
                    Method::SessionRead,
                    &kr_protocol::session::SessionReadParams {
                        session_id: self.worker.session_id,
                    },
                )
                .await
                .expect("the call reaches the daemon")
                .is_ok()
        })
        .await;
    }

    fn session_id(&self) -> SessionId {
        self.worker.session_id
    }

    /// The target of a mutation on the worker's session.
    fn target(&self) -> ActionTarget {
        self.worker.target(self.host.environment_id)
    }

    /// One page of the retained output as the local owner reads it, on the worker's own socket.
    async fn owner_page(&self, from: u64) -> HistoryPageResult {
        self.worker
            .client()
            .await
            .request(Method::HistoryPage, &page_of(self.session_id(), from))
            .await
            .expect("the call reaches the worker")
            .expect("the owner is served the page")
            .to_typed()
            .expect("decodes")
    }

    /// The cursor after the last byte the worker has retained.
    async fn end(&self) -> u64 {
        self.owner_page(0).await.next_cursor.get()
    }

    /// Adds `bytes` to what the application prints, and waits until the owner reads them as the
    /// end of the retained output.
    async fn write(&self, bytes: &[u8]) {
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&self.output)
            .and_then(|mut file| file.write_all(bytes))
            .expect("the output is added to");
        // The terminal turns each line end into a carriage return and a line feed.
        let without_returns = |text: &[u8]| {
            text.iter()
                .copied()
                .filter(|&byte| byte != b'\r')
                .collect::<Vec<u8>>()
        };
        let wanted = without_returns(bytes);
        until("the output being retained", || async {
            without_returns(self.owner_page(0).await.bytes.as_slice()).ends_with(&wanted)
        })
        .await;
    }

    /// Pairs a device under `grant`.
    async fn pair(&self, grant: ProposedGrant) -> (Device, DeviceRecord) {
        let device = Device::create().await;
        let record = pair_with(&self.host, &device, &self.owner, grant).await;
        (device, record)
    }

    /// Pairs a device that may view sessions, whose history reaches back to `bound` when it names
    /// one and to the pairing when it names none.
    async fn pair_viewing(&self, bound: Option<u64>) -> Connected {
        let mut grant = proposal(&[ActionRight::SessionView]);
        grant.history.lower_bound_ms = Nullable(bound.map(TimestampMs::new));
        let (device, record) = self.pair(grant).await;
        let session = connect(&self.host, &device, &record).await;
        Connected {
            session,
            _device: device,
        }
    }

    /// The file the worker keeps the times of its output in.
    fn times_file(&self) -> PathBuf {
        self.worker
            .runtime()
            .session()
            .output_time_index()
            .expect("the session keeps a record of when its output was produced")
            .path()
            .to_path_buf()
    }

    /// Makes the worker write its record of when output was produced, as its maintenance does, and
    /// reads the intervals of the first `end` bytes back from the file.
    fn times(&self, end: u64) -> Vec<kr_worker::output_times::TimedRange> {
        self.worker.service.maintain_now();
        kr_worker::output_times::read(&self.times_file(), 0, end, 64)
            .expect("the worker's record of the output's times")
            .marks
    }

    async fn stop(self) {
        self.host.stop().await;
    }
}

fn page_of(session_id: SessionId, from: u64) -> HistoryPageParams {
    HistoryPageParams {
        session_id,
        from_cursor: U64::new(from),
        max_bytes: U64::new(WHOLE),
    }
}

/// What a device is given of the retained output from `from`, or the host's refusal.
async fn device_page(
    session: &Session,
    session_id: SessionId,
    from: u64,
) -> Result<HistoryPageResult, kr_protocol::error::ProtocolError> {
    match session.history_page(&page_of(session_id, from)).await {
        Ok(page) => Ok(page),
        Err(ClientError::Host(refusal)) => Err(refusal),
        Err(other) => panic!("the read failed before the host answered: {other:?}"),
    }
}

/// KR-REQ-13.15, KR-REQ-10.49: a paired device is served the retained output its grant reaches and
/// none that came before.
///
/// Two bursts are written with the clock moving on between them. The grant's bound lies between
/// them, so it reaches the second and not the first, whatever way the grant came by its bound: named
/// by the pairing, or the pairing itself when it named none. A page from the very start begins at
/// the second burst and says what it left out; a page from inside the first does the same; a page
/// from inside the second is whole. A grant that reaches back to every moment is served everything
/// the owner reads, the output no interval times included; one without `session.view` is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_pages_the_output_its_grant_reaches_and_none_before_it() {
    let rig = Rig::start().await;
    let first = burst(b'a');
    let second = burst(b'b');
    let ready = rig.end().await;
    rig.write(&first).await;
    let reaches_from = rig.end().await;
    until_the_clock_has_moved(Duration::from_millis(150)).await;
    let bound = kr_ipc::now_ms().get();

    let named = rig.pair_viewing(Some(bound)).await;
    let unnamed = rig.pair_viewing(None).await;
    let everything = rig.pair_viewing(Some(0)).await;
    let (blind_device, blind_record) = rig.pair(proposal(&[ActionRight::TerminalInput])).await;
    let blind = connect(&rig.host, &blind_device, &blind_record).await;

    rig.write(&second).await;
    let end = rig.end().await;

    // The record the worker keeps, read back before anything is asked of it: the first burst's
    // interval ends where the second begins, was written before the bound, and the second's was
    // written after it, both on a clock the worker could prove.
    let times = rig.times(end);
    let before = times
        .iter()
        .find(|interval| interval.from < reaches_from && interval.to == reaches_from)
        .expect("an interval ends where the second burst begins");
    let after = times
        .iter()
        .find(|interval| interval.from == reaches_from)
        .expect("an interval begins where the second burst does");
    assert!(
        before.proven && before.at_ms < bound,
        "the first burst was written before the bound {bound}: {times:?}"
    );
    assert!(
        after.proven && after.at_ms >= bound,
        "the second burst was written at or after the bound {bound}: {times:?}"
    );

    for (what, device) in [
        ("a grant that names its bound", &named),
        ("a grant that names none", &unnamed),
    ] {
        let page = device_page(device, rig.session_id(), 0)
            .await
            .unwrap_or_else(|refusal| panic!("{what} is served the page: {refusal:?}"));
        assert_eq!(
            page.bytes.as_slice(),
            second.as_slice(),
            "{what} is served the second burst and nothing before it"
        );
        assert_eq!(page.from_cursor.get(), reaches_from, "{what}");
        assert_eq!(page.oldest_retained_cursor.get(), reaches_from, "{what}");
        let gap = page
            .gap
            .0
            .unwrap_or_else(|| panic!("{what} is told what the page leaves out"));
        assert_eq!(
            (gap.from_cursor.get(), gap.to_cursor.get(), gap.cause),
            (0, reaches_from, None),
            "{what}: nothing took the output it does not reach"
        );

        // From inside the first burst it is the same page, with a gap from where it asked.
        let inside = ready + 10;
        let page = device_page(device, rig.session_id(), inside)
            .await
            .unwrap_or_else(|refusal| panic!("{what} is served the page: {refusal:?}"));
        assert_eq!(page.bytes.as_slice(), second.as_slice(), "{what}");
        assert_eq!(page.from_cursor.get(), reaches_from, "{what}");
        let gap = page.gap.0.expect("a gap");
        assert_eq!(
            (gap.from_cursor.get(), gap.to_cursor.get()),
            (inside, reaches_from),
            "{what}"
        );

        // From inside the second it is whole.
        let page = device_page(device, rig.session_id(), reaches_from + 5)
            .await
            .unwrap_or_else(|refusal| panic!("{what} is served the page: {refusal:?}"));
        assert_eq!(page.bytes.as_slice(), &second[5..], "{what}");
        assert!(page.gap.0.is_none(), "{what}");
        assert_eq!(page.next_cursor.get(), end, "{what}");
    }

    // A grant that reaches every moment is served all the owner reads.
    let owner = rig.owner_page(0).await;
    assert!(
        owner.bytes.as_slice().starts_with(b"kr-ready."),
        "the owner reads the output before either burst"
    );
    let page = device_page(&everything, rig.session_id(), 0)
        .await
        .expect("a grant that reaches every moment is served the page");
    assert_eq!(page, owner, "and so is the device");

    // And a device without `session.view` is refused, whatever its history reaches.
    let refusal = device_page(&blind, rig.session_id(), 0)
        .await
        .expect_err("a device without session.view is not served");
    assert_eq!(refusal.code, ErrorCode::PermissionDenied, "{refusal:?}");

    named.close();
    unnamed.close();
    everything.close();
    blind.close();
    rig.stop().await;
}

/// KR-REQ-13.15: a device that holds a share of the session is served the output written after the
/// share was issued, and none before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_holding_a_share_is_served_the_output_written_after_the_share_was_issued() {
    let rig = Rig::start().await;
    rig.write(&burst(b'a')).await;
    let reaches_from = rig.end().await;
    until_the_clock_has_moved(Duration::from_millis(150)).await;

    // The device's pairing reaches another session, so the share is what reaches this one.
    let mut grant = proposal(&[ActionRight::SessionView]);
    grant.session_selector = SessionSelector::These {
        session_ids: [SessionId::new(kr_ipc::new_uuid())].into_iter().collect(),
    };
    let (device, record) = rig.pair(grant).await;
    let share = share_with(
        &rig.host,
        rig.session_id(),
        record.device_id,
        RoleSelection::plain(SessionRole::Viewer),
        None,
    )
    .await
    .expect("the session is shared");
    let redeeming = RawDevice::connect(&rig.host, &device, &record).await;
    redeeming
        .mutate(
            Method::GrantRedeem,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&rig.host),
            &GrantRedeemParams {
                invitation_id: share.preview.invitation_id,
            },
        )
        .await
        .expect("the share is redeemed");
    redeeming.close();

    let second = burst(b'b');
    rig.write(&second).await;
    let session = connect(&rig.host, &device, &record).await;
    let page = device_page(&session, rig.session_id(), 0)
        .await
        .expect("the share's holder is served the page");
    assert_eq!(page.bytes.as_slice(), second.as_slice());
    assert_eq!(page.from_cursor.get(), reaches_from);
    session.close();
    rig.stop().await;
}

/// KR-REQ-13.15, KR-REQ-10.49: under privacy mode a paired device is served nothing the owner is
/// not.
///
/// A device whose grant reaches the whole of the output reads it before privacy mode is on. Turning
/// the mode on removes what the worker retained and keeps what arrives meanwhile: the owner reads an
/// empty window, and so does the device, and the output produced under the mode is read by neither.
/// When the mode is off again, both read what is produced after it and the device only what the
/// owner reads. The device's page comes from the same retained window as the owner's and leaves
/// through the same response path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn under_privacy_mode_a_paired_device_is_served_nothing_the_owner_is_not() {
    let rig = Rig::start().await;
    rig.write(&burst(b'a')).await;
    until_the_clock_has_moved(Duration::from_millis(150)).await;
    let bound = kr_ipc::now_ms().get();
    // The bound is before everything the device is asked to read below.
    let device = rig.pair_viewing(Some(bound.saturating_sub(60_000))).await;

    // Before the mode: what the owner reads, the device reads from where its grant reaches.
    rig.write(&burst(b'b')).await;
    let owner = rig.owner_page(0).await;
    let served = device_page(&device, rig.session_id(), 0)
        .await
        .expect("the device is served the page");
    assert_no_more_than_the_owner(&owner, &served);
    assert!(
        served.bytes.as_slice().ends_with(&burst(b'b')),
        "the device reads the second burst"
    );

    rig.privacy(true).await;
    let (owner, served) = rig.both_read(&device).await;
    assert!(
        owner.bytes.as_slice().is_empty() && served.bytes.as_slice().is_empty(),
        "privacy mode emptied the window: {owner:?} {served:?}"
    );
    assert_no_more_than_the_owner(&owner, &served);

    // Output produced under the mode is retained for neither.
    let before = rig.worker.runtime().session().output_cursor();
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&rig.output)
        .and_then(|mut file| file.write_all(&burst(b'c')))
        .expect("the output is added to");
    until("the worker reading the output", || async {
        rig.worker.runtime().session().output_cursor() > before
    })
    .await;
    let (owner, served) = rig.both_read(&device).await;
    assert!(
        owner.bytes.as_slice().is_empty() && served.bytes.as_slice().is_empty(),
        "output produced under privacy mode is not retained: {owner:?} {served:?}"
    );

    // Off again: both read what is produced after it, and the device nothing more than the owner.
    rig.privacy(false).await;
    until_the_clock_has_moved(Duration::from_millis(150)).await;
    let after = burst(b'd');
    rig.write(&after).await;
    let (owner, served) = rig.both_read(&device).await;
    assert!(owner.bytes.as_slice().ends_with(&after), "{owner:?}");
    assert!(served.bytes.as_slice().ends_with(&after), "{served:?}");
    assert!(
        !owner.bytes.as_slice().windows(3).any(|run| run == b"ccc")
            && !served.bytes.as_slice().windows(3).any(|run| run == b"ccc"),
        "output produced under privacy mode stays unread"
    );
    assert_no_more_than_the_owner(&owner, &served);
    device.close();
    rig.stop().await;
}

/// Every byte of `served` is a byte `owner` is served at the same cursor, and `served` ends no later.
fn assert_no_more_than_the_owner(owner: &HistoryPageResult, served: &HistoryPageResult) {
    let from = served.from_cursor.get();
    let owner_from = owner.from_cursor.get();
    assert!(
        from >= owner_from && served.next_cursor.get() <= owner.next_cursor.get(),
        "the device is served a range the owner is not: owner {owner_from}..{}, device {from}..{}",
        owner.next_cursor.get(),
        served.next_cursor.get()
    );
    let start = usize::try_from(from - owner_from).expect("a small offset");
    assert_eq!(
        served.bytes.as_slice(),
        &owner.bytes.as_slice()[start..start + served.bytes.as_slice().len()],
        "the device is served bytes the owner is not"
    );
}

impl Rig {
    /// Turns privacy mode on or off at the daemon's local socket, and waits until the worker holds
    /// the mode: its retained output removed when it is on.
    async fn privacy(&self, enabled: bool) {
        self.host
            .client()
            .await
            .mutate(
                Method::PrivacySet,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(self.host.environment_id),
                &PrivacySetParams { enabled },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("privacy mode is set");
        until("the worker holding privacy mode", || async {
            let session = self.worker.runtime().session();
            session.privacy().is_enabled() == enabled
                && (!enabled || session.retained_output_bytes() == 0)
        })
        .await;
        // The daemon turns the mode off only once the worker has said its cleanup is complete.
        until("privacy mode's cleanup being complete", || async {
            let report: PrivacyReport = self
                .host
                .client()
                .await
                .request(Method::PrivacyStatus, &PrivacyStatusParams {})
                .await
                .expect("the call reaches the daemon")
                .expect("privacy mode's report")
                .to_typed()
                .expect("decodes");
            matches!(report.completion, PrivacyCompletion::Complete)
        })
        .await;
    }
}

impl Rig {
    /// The owner's page and `device`'s page, each from the start.
    async fn both_read(&self, device: &Connected) -> (HistoryPageResult, HistoryPageResult) {
        let owner = self.owner_page(0).await;
        let served = device_page(device, self.session_id(), 0)
            .await
            .expect("the device is served the page");
        (owner, served)
    }
}

/// The attach a terminal of 40 columns and 12 rows makes: smaller than the session, so that
/// the session's rows above the live screen are the part of it that is out of the window.
fn attach_small(session_id: SessionId) -> SessionAttachParams {
    SessionAttachParams {
        session_id,
        mode: AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(Dimensions::new(40, 12)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested: [AttachmentCapability::ObserveTerminal]
            .into_iter()
            .collect(),
    }
}

/// A report that puts the window 30 rows above the live screen.
fn pan_up(attachment_id: kr_protocol::ids::AttachmentId) -> AttachmentViewportParams {
    AttachmentViewportParams {
        attachment_id,
        dimensions: Dimensions::new(40, 12),
        position: Nullable::some(ViewportPosition::Above(U64::new(30))),
        column: U64::ZERO,
    }
}

/// KR-REQ-13.15, KR-REQ-10.49: a paired device cannot place its window above the live screen, so
/// the output from before its grant's bound is not shown to it by panning.
///
/// The session has written more lines than its screen holds, the first of them before the bound of
/// the grant. The owner, attached the same way, is answered a window in the session's rows above
/// the live screen: the rows are there. A device paired under a grant that begins after those lines
/// is refused the same report, and so is one whose grant reaches every moment: the rows above the
/// live screen are the owner's, and a grant is shown the screen that is showing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_cannot_pan_above_the_live_screen_into_output_from_before_its_grant() {
    let rig = Rig::start().await;
    rig.write(&lines("before", 60)).await;
    until_the_clock_has_moved(Duration::from_millis(150)).await;
    let bound = kr_ipc::now_ms().get();
    rig.write(&lines("after", 5)).await;

    // The rows above the live screen exist: the owner pans into them.
    let mut owner = rig.worker.client().await;
    let attached: SessionAttachResult = owner
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            rig.target(),
            &attach_small(rig.session_id()),
        )
        .await
        .expect("the call reaches the worker")
        .expect("the owner attaches")
        .to_typed()
        .expect("an attachment");
    let panned: kr_protocol::attachment::AttachmentViewportResult = owner
        .mutate(
            Method::AttachmentViewport,
            ActionId::new(kr_ipc::new_uuid()),
            rig.target(),
            &pan_up(attached.attachment.attachment_id),
        )
        .await
        .expect("the call reaches the worker")
        .expect("the owner pans above the live screen")
        .to_typed()
        .expect("a window");
    assert!(
        matches!(panned.position.0, Some(ViewportPosition::Row(_))),
        "the owner's window is in the session's rows above the live screen: {panned:?}"
    );

    for (what, from) in [
        ("a grant that begins after the lines", Some(bound)),
        ("a grant that reaches every moment", Some(0)),
    ] {
        let mut grant = proposal(&[ActionRight::SessionView]);
        grant.history.lower_bound_ms = Nullable(from.map(TimestampMs::new));
        let (device, record) = rig.pair(grant).await;
        let connection = RawDevice::connect(&rig.host, &device, &record).await;
        let attached: SessionAttachResult = connection
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                rig.target(),
                &attach_small(rig.session_id()),
            )
            .await
            .unwrap_or_else(|refusal| panic!("{what} attaches: {refusal:?}"))
            .to_typed()
            .expect("an attachment");
        let refusal = connection
            .mutate(
                Method::AttachmentViewport,
                ActionId::new(kr_ipc::new_uuid()),
                rig.target(),
                &pan_up(attached.attachment.attachment_id),
            )
            .await
            .expect_err(&format!(
                "{what} is not shown the rows above the live screen"
            ));
        assert_eq!(refusal.code, ErrorCode::UnsupportedCapability, "{what}");
        connection.close();
    }
    rig.stop().await;
}

/// KR-REQ-13.15: a paired device is refused the retained output of a session that has closed, and
/// told that is why, until a closed session's output is served to it under its grant.
///
/// The session is one the registry holds a closure of, as the daemon records one when a session
/// ends: it has no worker, so nothing can cut its output to a grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_is_refused_a_closed_sessions_retained_output_and_told_why() {
    use kr_controller::registry::Registry;
    use kr_protocol::session::{Durability, OwnershipCoverage};

    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (session_id, _) = an_open_session(&host);
    let device = Device::create().await;
    let mut grant = proposal(&[ActionRight::SessionView]);
    grant.history.lower_bound_ms = Nullable::some(TimestampMs::new(0));
    let record = pair_with(&host, &device, &owner, grant).await;
    let session = connect(&host, &device, &record).await;

    Registry::open(host.registry_database(), host.environment_id)
        .expect("the registry opens beside the daemon's own handle")
        .record_closure(&kr_protocol::session::ClosureRecord {
            session_id,
            session_epoch: kr_protocol::ids::SessionEpoch::V1,
            reason: kr_protocol::session::ClosureReason::CloseRequested,
            root_exit_code: Nullable::null(),
            root_signal: Nullable::null(),
            terminated: Vec::new(),
            surviving: Vec::new(),
            ownership_coverage: OwnershipCoverage::Incomplete,
            durability: Durability::Durable,
            closed_at_ms: kr_ipc::now_ms(),
        })
        .expect("the closure is recorded");

    let refusal = device_page(&session, session_id, 0)
        .await
        .expect_err("a closed session's output is not served to a device");
    assert_eq!(refusal.code, ErrorCode::SessionClosed, "{refusal:?}");
    assert!(
        refusal.message.contains("retained output"),
        "the refusal says what is not served: {refusal:?}"
    );
    session.close();
    host.stop().await;
}
