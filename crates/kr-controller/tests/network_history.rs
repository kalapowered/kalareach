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
        self.pair_holding(bound, &[ActionRight::SessionView]).await
    }

    /// Pairs a device that holds `rights`, whose history reaches back as [`Self::pair_viewing`]'s
    /// does.
    async fn pair_holding(&self, bound: Option<u64>, rights: &[ActionRight]) -> Connected {
        let mut grant = proposal(rights);
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
///
/// KR-REQ-10.49, the part about a share's history scope: the output the device reads through the
/// share is what was written after the share was issued, and none of what was written before it.
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
/// owner reads. The device's page comes from the same retained window as the owner's; the owner
/// reads it on the worker's own socket and the device through the daemon.
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
/// told why.
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

/// Whether `bytes` holds `marker`.
fn holds(bytes: &[u8], marker: &str) -> bool {
    bytes
        .windows(marker.len())
        .any(|window| window == marker.as_bytes())
}

/// One page of `limit` bytes at most from `from`, as a device is given it.
async fn device_page_of(
    session: &Session,
    session_id: SessionId,
    from: u64,
    limit: u64,
) -> HistoryPageResult {
    session
        .history_page(&HistoryPageParams {
            session_id,
            from_cursor: U64::new(from),
            max_bytes: U64::new(limit),
        })
        .await
        .expect("the device is served the page")
}

/// What a device is paged from `from` to the end of the output, a page of `limit` bytes at most at
/// a time. A page stops where the worker's resident window begins, so one page does not reach the
/// end of output as long as the window is.
async fn device_paged(session: &Session, session_id: SessionId, from: u64, limit: u64) -> Vec<u8> {
    let mut cursor = from;
    let mut together = Vec::new();
    loop {
        let page = device_page_of(session, session_id, cursor, limit).await;
        if page.next_cursor.get() <= cursor {
            return together;
        }
        together.extend_from_slice(page.bytes.as_slice());
        cursor = page.next_cursor.get();
    }
}

/// What the owner is paged from `from` to the end of the output.
async fn owner_paged(rig: &Rig, from: u64) -> Vec<u8> {
    let mut cursor = from;
    let mut together = Vec::new();
    loop {
        let page = rig.owner_page(cursor).await;
        if page.next_cursor.get() <= cursor {
            return together;
        }
        together.extend_from_slice(page.bytes.as_slice());
        cursor = page.next_cursor.get();
    }
}

/// Adds `bytes`, which hold no line end, to what the application prints, waits until the owner is
/// paged all of them, and returns the cursor they begin at.
async fn print(rig: &Rig, bytes: &[u8]) -> u64 {
    use std::io::Write as _;
    let start = owner_paged(rig, 0).await.len() as u64;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&rig.output)
        .and_then(|mut file| file.write_all(bytes))
        .expect("the output is added to");
    let end = start + bytes.len() as u64;
    until("the output being retained", || async {
        let page = rig.owner_page(end - 1).await;
        page.next_cursor.get() >= end
    })
    .await;
    start
}

/// One word inside each payload `printed` writes that a device is not given.
const PAYLOADS: [&str; 6] = [
    "INLINEFILEPAYLOAD",
    "SIXELPICTUREPAYLOAD",
    "KITTYPICTUREPAYLOAD",
    "ENVELOPEDFILEPAYLOAD",
    "LARGEFILEPAYLOAD",
    "AFTERRAWC1PAYLOAD",
];

/// What an application prints that a terminal takes for a file or a picture, with plain words
/// between: an inline file of the iTerm2 protocol, a sixel picture, a Kitty graphics command, an
/// inline file inside a tmux passthrough envelope, an inline file longer than the engine holds of
/// a control string, and a string of documented metadata whose payload holds a raw 8-bit string
/// terminator and the start of an inline file, which a terminal that reads raw 8-bit controls
/// takes for the end of the metadata and a file. The last is ordinary documented metadata, which
/// is the control.
///
/// The second is the same output with each sequence a device is not given replaced, byte for
/// byte, by NUL.
fn printed() -> (Vec<u8>, Vec<u8>) {
    let mut large = b"\x1b]1337;File=name=bGFyZ2U=;inline=1:".to_vec();
    large.extend(std::iter::repeat_n(b'Z', 70_000));
    large.extend_from_slice(PAYLOADS[4].as_bytes());
    large.push(0x07);
    let mut raw_c1 = b"\x1b]1337;CurrentDir=/tmp\x9c\x9d1337;File=name=eA==:".to_vec();
    raw_c1.extend_from_slice(PAYLOADS[5].as_bytes());
    raw_c1.push(0x07);
    let sequences: [(Vec<u8>, bool); 7] = [
        (
            format!("\x1b]1337;File=name=bm90ZQ==;inline=1:{}\x07", PAYLOADS[0]).into_bytes(),
            true,
        ),
        (
            format!("\x1bP0;0;0q#0;2;0;0;0{}~~@@\x1b\\", PAYLOADS[1]).into_bytes(),
            true,
        ),
        (
            format!("\x1b_Gf=24,s=1,v=1,a=T;{}\x1b\\", PAYLOADS[2]).into_bytes(),
            true,
        ),
        (
            format!(
                "\x1bPtmux;\x1b\x1b]1337;File=name=YQ==:{}\x1b\x1b\\\x1b\\",
                PAYLOADS[3]
            )
            .into_bytes(),
            true,
        ),
        (large, true),
        (raw_c1, true),
        (b"\x1b]1337;CurrentDir=/tmp\x07".to_vec(), false),
    ];
    woven(&sequences)
}

/// One word inside each payload `side_effects_printed` writes that a device is not given.
const SIDE_EFFECT_PAYLOADS: [&str; 4] = [
    "Q0xJUEJPQVJEU0VDUkVUUEFZTE9BRA==",
    "NOTIFYNINEPAYLOAD",
    "NOTIFYKITTYPAYLOAD",
    "NOTIFYRXVTPAYLOAD",
];

/// What an application prints that the live policy keeps from every attachment but the one that
/// holds the input lease, with plain words between: a write to the clipboard (the base64 of
/// `CLIPBOARDSECRETPAYLOAD`), a notification of OSC 9, one of the Kitty protocol, one of rxvt, and
/// a progress report, which holds no word to look for. A window title between them is the
/// control: a device is paged it as written.
///
/// The second is the same output with each sequence a device is not given replaced, byte for
/// byte, by NUL.
fn side_effects_printed() -> (Vec<u8>, Vec<u8>) {
    let sequences: [(Vec<u8>, bool); 6] = [
        (
            format!("\x1b]52;c;{}\x07", SIDE_EFFECT_PAYLOADS[0]).into_bytes(),
            true,
        ),
        (
            format!("\x1b]9;{}\x07", SIDE_EFFECT_PAYLOADS[1]).into_bytes(),
            true,
        ),
        (
            format!("\x1b]99;i=1:d=1:p=body;{}\x1b\\", SIDE_EFFECT_PAYLOADS[2]).into_bytes(),
            true,
        ),
        (
            format!("\x1b]777;notify;title;{}\x07", SIDE_EFFECT_PAYLOADS[3]).into_bytes(),
            true,
        ),
        (b"\x1b]9;4;1;50\x07".to_vec(), true),
        (b"\x1b]0;a title\x07".to_vec(), false),
    ];
    woven(&sequences)
}

/// `sequences` as an application prints them, with plain words before each and after the last, and
/// the same output with each one marked as withheld replaced, byte for byte, by NUL.
fn woven(sequences: &[(Vec<u8>, bool)]) -> (Vec<u8>, Vec<u8>) {
    let mut written = Vec::new();
    let mut shown = Vec::new();
    for (number, (sequence, withheld)) in sequences.iter().enumerate() {
        let words = format!("words {number} ").into_bytes();
        written.extend_from_slice(&words);
        shown.extend_from_slice(&words);
        written.extend_from_slice(sequence);
        if *withheld {
            shown.extend(std::iter::repeat_n(0_u8, sequence.len()));
        } else {
            shown.extend_from_slice(sequence);
        }
    }
    written.extend_from_slice(b"last words");
    shown.extend_from_slice(b"last words");
    (written, shown)
}

/// KR-REQ-10.50, the part about file and attachment bytes needing a file grant of their own: a
/// device that holds `session.view`, the live screen and a history that reaches every moment, and
/// not `files.read`, is not given what an application printed as a file or a picture when it pages
/// the retained output. The local owner is.
///
/// Each such sequence comes back as NUL, byte for byte, so every cursor in a page and every word
/// around a payload is where it was, whatever size a page is cut to: a page that begins or ends
/// inside a payload withholds that part of it. Not shown here: a device that holds `files.read`,
/// which the worker cannot tell from one that does not, since the scope a read carries states no
/// rights, and the terminal's live stream, which the engine withholds the same sequences from.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_50_a_device_without_files_read_is_not_paged_the_files_and_pictures_an_application_printed()
 {
    let rig = Rig::start().await;
    let device = rig.pair_holding(Some(0), &[ActionRight::SessionView]).await;
    let (written, shown) = printed();
    let start = print(&rig, &written).await;

    let owner = owner_paged(&rig, start).await;
    assert_eq!(owner, written, "the owner is paged what was written");

    // Whole pages, and pages cut small, so the cuts fall inside payloads and inside the sequences
    // around them.
    for limit in [WHOLE, 4_099] {
        let paged = device_paged(&device, rig.session_id(), start, limit).await;
        for marker in PAYLOADS {
            assert!(
                !holds(&paged, marker),
                "pages of {limit} bytes hold {marker}"
            );
        }
        assert_eq!(
            paged, shown,
            "pages of {limit} bytes are the words, and NUL where each payload lay"
        );
    }

    device.close();
    rig.stop().await;
}

/// KR-REQ-10.50, the part about file and attachment bytes needing a file grant of their own: a
/// control string the application has begun and not ended is not paged to a device without
/// `files.read`, since nothing yet says what it is. The page stops where it begins, and once it
/// ends the string is withheld if it was a file, and the words after it are paged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_string_the_application_has_not_ended_is_paged_to_a_device_without_files_read_only_when_it_ends()
 {
    let rig = Rig::start().await;
    let device = rig.pair_holding(Some(0), &[ActionRight::SessionView]).await;
    let start = rig.end().await;
    rig.write(b"words before ").await;
    let opens_at = rig.end().await;
    let opening = format!("\x1b]1337;File=name=eA==:{}", PAYLOADS[0]);
    rig.write(opening.as_bytes()).await;

    let page = device_page_of(&device, rig.session_id(), start, WHOLE).await;
    assert_eq!(
        page.bytes.as_slice(),
        b"words before ",
        "the page stops where the string begins"
    );
    assert_eq!(page.next_cursor.get(), opens_at);
    // A reader that asks where the output ends is told where it may read to, not where the
    // string has got to.
    let probe = device_page_of(&device, rig.session_id(), u64::MAX, WHOLE).await;
    assert_eq!(
        (
            probe.from_cursor.get(),
            probe.next_cursor.get(),
            probe.bytes.len()
        ),
        (opens_at, opens_at, 0)
    );

    rig.write(b"\x07 words after").await;
    let page = device_page_of(&device, rig.session_id(), opens_at, WHOLE).await;
    let mut wanted = vec![0_u8; opening.len() + 1];
    wanted.extend_from_slice(b" words after");
    assert_eq!(
        page.bytes.as_slice(),
        wanted.as_slice(),
        "once it ends the string is withheld, and the words after it are paged"
    );

    device.close();
    rig.stop().await;
}

/// A device that holds `session.view` and a history that reaches every moment is not paged what
/// the live policy keeps from every attachment but the one that holds the input lease: the text of
/// a clipboard write or of a notification, and a progress report. The local owner is.
///
/// Each such sequence comes back as NUL, byte for byte, whatever size a page is cut to, so a page
/// that begins or ends inside one withholds that part of it and every cursor is where it was. A
/// window title between them, which the live policy sends on, is paged as written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_is_not_paged_the_clipboard_text_and_the_notifications_an_application_printed() {
    let rig = Rig::start().await;
    let device = rig.pair_holding(Some(0), &[ActionRight::SessionView]).await;
    let (written, shown) = side_effects_printed();
    let start = print(&rig, &written).await;

    let owner = owner_paged(&rig, start).await;
    assert_eq!(owner, written, "the owner is paged what was written");

    for limit in [WHOLE, 7] {
        let paged = device_paged(&device, rig.session_id(), start, limit).await;
        for marker in SIDE_EFFECT_PAYLOADS {
            assert!(
                !holds(&paged, marker),
                "pages of {limit} bytes hold {marker}"
            );
        }
        assert_eq!(
            paged, shown,
            "pages of {limit} bytes are the words and the title, and NUL where each side effect lay"
        );
    }

    device.close();
    rig.stop().await;
}

/// `payload` as an inline file between plain words, enough of them that the output is an interval
/// of its own in the worker's record of when it was produced, and the same output with the file
/// replaced, byte for byte, by NUL.
fn a_file_among_words(payload: &str) -> (Vec<u8>, Vec<u8>) {
    let words = vec![b'w'; 150];
    let file = format!("\x1b]1337;File=name=eA==;inline=1:{payload}\x07").into_bytes();
    let mut written = words.clone();
    written.extend_from_slice(&file);
    written.extend_from_slice(&words);
    let mut shown = words.clone();
    shown.extend(std::iter::repeat_n(0_u8, file.len()));
    shown.extend_from_slice(&words);
    (written, shown)
}

/// A device whose history begins part way through the output is not paged a file printed from
/// there on, and a device whose history begins after all of it is paged none of the output that
/// exists and, once a file is printed, only that file's place: the reach a device's grant gives it
/// narrows what it is paged and never what is withheld from it.
///
/// The record the worker keeps of when the output was produced is read back before anything is
/// asked, so a bound that did not fall where the case says fails by saying so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_whose_history_begins_part_way_is_not_paged_the_files_printed_from_there_on() {
    let rig = Rig::start().await;
    let (earlier, _) = a_file_among_words("EARLYFILEPAYLOAD");
    let (later, later_shown) = a_file_among_words("LATERFILEPAYLOAD");
    let (last, last_shown) = a_file_among_words("LASTFILEPAYLOAD");
    let markers = ["EARLYFILEPAYLOAD", "LATERFILEPAYLOAD", "LASTFILEPAYLOAD"];

    print(&rig, &earlier).await;
    let reaches_from = rig.end().await;
    until_the_clock_has_moved(Duration::from_millis(150)).await;
    let bound = kr_ipc::now_ms().get();
    let part_way = rig
        .pair_holding(Some(bound), &[ActionRight::SessionView])
        .await;

    assert_eq!(print(&rig, &later).await, reaches_from);
    let after_later = rig.end().await;
    until_the_clock_has_moved(Duration::from_millis(150)).await;
    let past_the_end = kr_ipc::now_ms().get();
    let none_yet = rig
        .pair_holding(Some(past_the_end), &[ActionRight::SessionView])
        .await;

    let times = rig.times(after_later);
    let before = times
        .iter()
        .find(|interval| interval.from < reaches_from && interval.to == reaches_from)
        .expect("an interval ends where the later output begins");
    let after = times
        .iter()
        .find(|interval| interval.from == reaches_from)
        .expect("an interval begins where the later output does");
    assert!(
        before.proven && before.at_ms < bound,
        "the earlier output was written before the bound {bound}: {times:?}"
    );
    assert!(
        after.proven && after.at_ms >= bound && after.at_ms < past_the_end,
        "the later output was written between the bounds {bound} and {past_the_end}: {times:?}"
    );

    // Reach::From: the page begins where the grant's reach does, and the file in it is withheld.
    let page = device_page_of(&part_way, rig.session_id(), 0, WHOLE).await;
    assert_eq!(page.from_cursor.get(), reaches_from);
    assert_eq!(page.bytes.as_slice(), later_shown.as_slice());
    let gap = page.gap.0.expect("the page says what it leaves out");
    assert_eq!(
        (gap.from_cursor.get(), gap.to_cursor.get()),
        (0, reaches_from)
    );

    // Reach::Nothing: every moment of the output is before the grant's, so none of it is paged.
    let page = device_page_of(&none_yet, rig.session_id(), 0, WHOLE).await;
    assert!(page.bytes.is_empty(), "nothing is paged: {page:?}");
    assert_eq!(
        (page.from_cursor.get(), page.next_cursor.get()),
        (after_later, after_later)
    );

    // What is printed from then on reaches that device, and the file in it is withheld.
    let last_starts = print(&rig, &last).await;
    assert_eq!(last_starts, after_later);
    let times = rig.times(last_starts + last.len() as u64);
    let reached = times
        .iter()
        .find(|interval| interval.from == last_starts)
        .expect("an interval begins where the last output does");
    assert!(
        reached.proven && reached.at_ms >= past_the_end,
        "the last output was written after the bound {past_the_end}: {times:?}"
    );
    let page = device_page_of(&none_yet, rig.session_id(), 0, WHOLE).await;
    assert_eq!(page.from_cursor.get(), last_starts);
    assert_eq!(page.bytes.as_slice(), last_shown.as_slice());

    for paged in [
        device_paged(&part_way, rig.session_id(), 0, 4_099).await,
        device_paged(&none_yet, rig.session_id(), 0, 4_099).await,
    ] {
        for marker in markers {
            assert!(!holds(&paged, marker), "pages hold {marker}");
        }
    }

    part_way.close();
    none_yet.close();
    rig.stop().await;
}
