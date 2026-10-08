//! Stopping what a crashed session still owned, before its identity is released.
//!
//! Section 7: after a worker crash the controller fences its endpoints, uses the control group, the
//! job or the recorded identities for cleanup, and records any incomplete coverage. Section 24: the
//! supervisor terminates or fences any remaining owned processes before releasing the session
//! identity. [`ArchiveService::take_ownership`] has already fenced the endpoint when this runs;
//! this is the rest.
//!
//! **What is stopped, and by what.** The worker wrote down the processes its session owned, each
//! by identifier and start (`kr_worker::ownership::OwnedRecord`). A recorded identity can name only
//! the process that was recorded, and a process is stopped only through the platform's own hold on
//! it ([`kr_ipc::identity::stop_process`]), so an identifier the kernel has given to a stranger is
//! never signalled. A worker that ran as a systemd service also ran in that service's control
//! group, which holds every descendant including ones the worker never saw; the group is named
//! from the reservation, so it can name nothing else, and its emptiness is read from the kernel.
//! On Windows the worker's own job object held the whole tree and closed with the worker; this
//! waits for that, and ends by handle only what is left.
//!
//! **How.** Unix processes are asked to end (terminate, hang up, continue) and given the grace
//! period section 7 gives a closing session, then ended with no chance to refuse, and given a
//! moment more. The cleanup is bounded. A process that is still there at the end of it has been
//! fenced in the sense section 24 allows: the worker that served it is dead and its endpoint,
//! descriptor and terminal are gone, so nothing it holds lets it act as the session, and the
//! closure names it by identifier, start and where it ran, with incomplete coverage, so that
//! nobody reads it as gone. The next session's control group is named from its own reservation,
//! and the number of its endpoint only ever increases, so no later session shares an identity with
//! it.
//!
//! **Coverage** is complete only for a boundary this pass confirmed: a control group it proved the
//! worker ran in and read empty at the end, or a job that needed no help. Everywhere else it is
//! incomplete, always on macOS and on a Linux host with no service manager, because a process that
//! left the terminal's session was never recorded and is not found.

use std::time::{Duration, Instant};

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::session::{OwnershipCoverage, SurvivingResource};
use kr_worker::journal::Journal;
use kr_worker::ownership::OwnedRecord;

use super::{ArchiveService, RecoveryOwnership};

/// How long the processes are given to end after they are asked to: section 7's shutdown period.
const GRACE: Duration = kr_worker::session::GRACE_PERIOD;

/// How long what was forced is given to be gone.
const FORCED: Duration = Duration::from_secs(2);

/// How often the processes are looked at while they are waited for.
const POLL: Duration = Duration::from_millis(50);

/// A recorded process this pass saw end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ended {
    /// The process and its start.
    pub identity: ProcessStartIdentity,
    /// Whether this pass had to end it with no chance to refuse, or the platform's job had to be
    /// helped. False for one that was already gone, ended after it was asked, or ended with the
    /// worker.
    pub forced: bool,
    /// Whether it is the session's root shell.
    pub root: bool,
}

/// What fencing a crashed session's owned processes did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fenced {
    /// The session.
    pub session_id: kr_protocol::ids::SessionId,
    /// The recorded processes this pass saw end.
    pub ended: Vec<Ended>,
    /// What survived the attempt or could not be established: each process still running by
    /// identifier, start and where it ran, and each reason this pass could not account for
    /// something.
    pub surviving: Vec<SurvivingResource>,
    /// Whether every owned process was accounted for.
    pub coverage: OwnershipCoverage,
}

impl Fenced {
    /// Returns what a closure records when this host had no chance to fence anything.
    ///
    /// A closure written for a worker that was already gone with the boot it ran in carries this:
    /// nothing ended, nothing accounted for, coverage incomplete.
    #[must_use]
    pub const fn nothing(session_id: kr_protocol::ids::SessionId) -> Self {
        Self {
            session_id,
            ended: Vec::new(),
            surviving: Vec::new(),
            coverage: OwnershipCoverage::Incomplete,
        }
    }
}

/// What the worker's record came to when it was read.
enum Recorded {
    /// A record of this boot.
    Usable(Box<OwnedRecord>),
    /// No record this pass may act on, and why.
    Unusable(String),
}

/// One recorded process while it is being stopped.
struct Tracked {
    identity: ProcessStartIdentity,
    forced: bool,
    state: Standing,
}

/// Where one recorded process stands.
enum Standing {
    /// Still to be seen to end.
    Pending,
    /// Seen to end.
    Ended,
    /// Could not be stopped, for the reason given.
    Refused(String),
}

/// Asks the platform to stop a recorded process, or refuses on the test's behalf.
fn stop(identity: &ProcessStartIdentity, how: kr_ipc::identity::Stop) -> kr_ipc::identity::Stopped {
    #[cfg(any(test, feature = "testing"))]
    if crate::testing::stop_is_refused(identity) {
        return kr_ipc::identity::Stopped::Refused("Operation not permitted".to_owned());
    }
    kr_ipc::identity::stop_process(identity, how)
}

impl ArchiveService {
    /// Stops what a crashed session still owned, and reports it.
    ///
    /// `unit` is the service-manager unit the worker was started as, named from its reservation,
    /// where the platform has one. Nothing here creates a worker, and nothing is signalled that
    /// the worker did not record or that is not in the unit's control group.
    pub async fn fence_owned(&self, ownership: &RecoveryOwnership, unit: Option<&str>) -> Fenced {
        let session_id = ownership.session_id;
        let paths = self.paths().clone();
        let recorded = tokio::task::spawn_blocking(move || read_record(&paths, session_id))
            .await
            .unwrap_or_else(|_| Recorded::Unusable("reading the record did not finish".to_owned()));
        let mut surviving = Vec::new();
        let mut tracked: Vec<Tracked> = Vec::new();
        let mut record: Option<OwnedRecord> = None;
        match recorded {
            Recorded::Usable(usable) => {
                for identity in &usable.processes {
                    tracked.push(Tracked {
                        identity: identity.clone(),
                        forced: false,
                        state: Standing::Pending,
                    });
                }
                for limit in &usable.limits {
                    surviving.push(unestablished(limit.clone()));
                }
                record = Some(*usable);
            }
            Recorded::Unusable(why) => surviving.push(unestablished(why)),
        }
        let boundary = record
            .as_ref()
            .map_or_else(String::new, |record| record.boundary.clone());
        let root = record.as_ref().map(|record| record.root.clone());

        // The control group, where the worker ran in the unit this reservation named.
        let mut group = record
            .as_ref()
            .and_then(|record| record.cgroup.as_deref())
            .and_then(|path| unit.map(|unit| Group::of(path, unit)))
            .flatten();
        if record
            .as_ref()
            .is_some_and(|record| record.cgroup.is_some())
            && group.is_none()
        {
            // A worker that ran in some other group, the daemon's or a login session's, has no
            // group of its own to clean by, and the group it did run in holds other things.
            surviving.push(unestablished(
                "the worker did not run in a service of its own, so there is no control group \
                 to clean by"
                    .to_owned(),
            ));
        }

        // Ask, wait, force.
        let started = Instant::now();
        look(&mut tracked);
        #[cfg(unix)]
        for process in &mut tracked {
            if matches!(process.state, Standing::Pending) {
                match stop(&process.identity, kr_ipc::identity::Stop::Terminate) {
                    // Whether the process is gone is the kernel's word, asked at the next look:
                    // a version-bound signal that finds nothing can be a process that ran a new
                    // program in between.
                    kr_ipc::identity::Stopped::Signalled
                    | kr_ipc::identity::Stopped::Gone
                    | kr_ipc::identity::Stopped::Unsupported => {}
                    kr_ipc::identity::Stopped::Refused(why)
                    | kr_ipc::identity::Stopped::Unsafe(why) => {
                        process.state = Standing::Refused(why);
                    }
                }
            }
        }
        // The grace period is for everything this pass is to answer for: the recorded processes
        // and whatever the unit's control group still holds, which the manager has also asked to
        // end and which may need the time to do it.
        loop {
            look(&mut tracked);
            let group_empty = match group.as_mut() {
                Some(group) => group.empty().await,
                None => true,
            };
            if (!tracked.iter().any(pending) && group_empty) || started.elapsed() >= GRACE {
                break;
            }
            tokio::time::sleep(POLL).await;
        }
        let mut forced_job = false;
        for process in &mut tracked {
            if matches!(process.state, Standing::Pending) {
                match stop(&process.identity, kr_ipc::identity::Stop::Kill) {
                    kr_ipc::identity::Stopped::Signalled => {
                        process.forced = true;
                        forced_job |= cfg!(windows);
                    }
                    kr_ipc::identity::Stopped::Gone | kr_ipc::identity::Stopped::Unsupported => {}
                    kr_ipc::identity::Stopped::Refused(why)
                    | kr_ipc::identity::Stopped::Unsafe(why) => {
                        process.state = Standing::Refused(why);
                    }
                }
            }
        }
        // The unit's control group, once the grace period has gone and it still holds something.
        // What the manager then ends was forced, whether or not the worker had recorded it.
        let mut group_refused = None;
        if let Some(group) = group.as_mut() {
            match group.force().await {
                Forced::Nothing => {}
                Forced::Killed => {
                    for process in &mut tracked {
                        if matches!(process.state, Standing::Pending) {
                            process.forced = true;
                        }
                    }
                }
                Forced::Refused(why) => group_refused = Some(why),
            }
        }
        let forced_until = Instant::now() + FORCED;
        loop {
            look(&mut tracked);
            let group_empty = match group.as_mut() {
                Some(group) => group.empty().await,
                None => true,
            };
            if (!tracked.iter().any(pending) && group_empty) || Instant::now() >= forced_until {
                break;
            }
            tokio::time::sleep(POLL).await;
        }

        // What each process came to.
        let mut ended = Vec::new();
        for process in tracked {
            let is_root = root.as_ref() == Some(&process.identity);
            let refusal = match &process.state {
                Standing::Refused(why) => format!(": {why}"),
                _ => String::new(),
            };
            // A refusal can come with an end that happened anyway, so the kernel is asked last.
            match kr_ipc::identity::process_state(&process.identity) {
                kr_ipc::identity::ProcessState::Ended => ended.push(Ended {
                    root: is_root,
                    identity: process.identity,
                    forced: process.forced,
                }),
                kr_ipc::identity::ProcessState::Running => surviving.push(survivor(
                    &process.identity,
                    &boundary,
                    group.as_ref(),
                    &format!("is still running{refusal}"),
                )),
                kr_ipc::identity::ProcessState::Unknown { detail } => surviving.push(survivor(
                    &process.identity,
                    &boundary,
                    group.as_ref(),
                    &format!(
                        "may still be running: this host cannot say whether it ended ({detail})"
                    ),
                )),
            }
        }
        let mut boundary_confirmed = false;
        if let Some(group) = group.as_mut() {
            match group.holders().await {
                Holders::None => boundary_confirmed = true,
                Holders::Some(identities) => {
                    let why = group_refused
                        .as_deref()
                        .map(|why| format!("; the service manager did not end it: {why}"))
                        .unwrap_or_default();
                    for identity in identities {
                        if !surviving.iter().any(|resource| {
                            resource
                                .detail
                                .starts_with(&format!("process {} ", identity.pid.get()))
                        }) {
                            surviving.push(survivor(
                                &identity,
                                &boundary,
                                Some(&*group),
                                &format!("is still running{why}"),
                            ));
                        }
                    }
                }
                Holders::Unreadable(why) => surviving.push(unestablished(why)),
            }
        }
        // Windows: the job closed with the worker, and the claim holds only if nothing needed
        // help to end.
        let job = cfg!(windows) && record.is_some();
        // A process this pass names as still there is never inside a complete claim, whatever else
        // ended: the claim is read off the report it sits in.
        let complete = record.is_some()
            && surviving.is_empty()
            && ((job && !forced_job) || (group.is_some() && boundary_confirmed));
        if forced_job {
            surviving.push(unestablished(
                "the session's job object had not ended everything it held when the worker died, \
                 so what was left was ended by handle"
                    .to_owned(),
            ));
        }
        if !complete {
            surviving.push(unestablished(
                if group.is_some() {
                    "a process that moved itself to another service or scope is not found on this \
                     host"
                } else {
                    "a process that left the terminal's session, a process the worker started \
                     outside it and a process that began after the last record was written are \
                     not found on this host"
                }
                .to_owned(),
            ));
        }
        Fenced {
            session_id,
            ended,
            surviving,
            coverage: if complete {
                OwnershipCoverage::Complete
            } else {
                OwnershipCoverage::Incomplete
            },
        }
    }
}

/// The kind of a surviving resource that is a reason this pass could not account for something.
const UNESTABLISHED: &str = "unestablished";

fn unestablished(detail: String) -> SurvivingResource {
    SurvivingResource {
        kind: UNESTABLISHED.to_owned(),
        detail,
    }
}

fn pending(process: &Tracked) -> bool {
    matches!(process.state, Standing::Pending)
}

/// Names one process that outlasted the attempt: by identifier, start, and where it ran.
fn survivor(
    identity: &ProcessStartIdentity,
    boundary: &str,
    group: Option<&Group>,
    refusal: &str,
) -> SurvivingResource {
    let place = group.map_or_else(
        || {
            if boundary.is_empty() {
                String::new()
            } else {
                format!("; it ran in {boundary}")
            }
        },
        |group| format!("; it ran in the control group {}", group.path),
    );
    SurvivingResource {
        kind: "process".to_owned(),
        detail: format!(
            "process {} (started {}) {refusal}{place}",
            identity.pid.get(),
            identity.start_value.get(),
        ),
    }
}

/// Marks every pending process the kernel says has ended.
fn look(tracked: &mut [Tracked]) {
    for process in tracked {
        if matches!(process.state, Standing::Pending)
            && matches!(
                kr_ipc::identity::process_state(&process.identity),
                kr_ipc::identity::ProcessState::Ended
            )
        {
            process.state = Standing::Ended;
        }
    }
}

/// Reads the worker's record from its journal, which is the archive's under ownership.
fn read_record(
    paths: &kr_ipc::paths::EnvironmentPaths,
    session_id: kr_protocol::ids::SessionId,
) -> Recorded {
    let archive = ArchiveService::new(paths.clone());
    archive.bring_forward(session_id);
    let path = paths.journal_database(session_id);
    if !path.exists() {
        return Recorded::Unusable(
            "the worker's journal is not there, so no record of its processes was read".to_owned(),
        );
    }
    let journal = match Journal::open_read_only(&path) {
        Ok(journal) => journal,
        Err(error) => {
            return Recorded::Unusable(format!(
                "the worker's journal could not be read, so no record of its processes was read: {error}"
            ));
        }
    };
    let record = match journal.read_owned(session_id) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return Recorded::Unusable(
                "the worker recorded no processes of its session".to_owned(),
            );
        }
        Err(error) => {
            return Recorded::Unusable(format!(
                "the worker's record of its processes could not be read: {error}"
            ));
        }
    };
    let now = kr_ipc::identity::boot_identity().ok();
    match (&record.boot, now) {
        (Some(recorded), Some(now)) if *recorded == now => Recorded::Usable(Box::new(record)),
        (None, _) => Recorded::Unusable(format!(
            "the worker's record of its processes came from an earlier build and names no boot; its \
             root shell was {}",
            record.root.pid.get()
        )),
        _ => Recorded::Unusable(
            "the worker's record of its processes is from another boot or this boot could not be \
             read, and a process identity means nothing across boots"
                .to_owned(),
        ),
    }
}

/// The control group of the service a worker ran as.
#[cfg_attr(
    not(target_os = "linux"),
    expect(dead_code, reason = "only a Linux host has a control group to read")
)]
struct Group {
    path: String,
    unit: String,
    /// Whether the unit's kill has been asked for.
    killed: bool,
}

/// What a control group holds.
#[cfg_attr(
    not(target_os = "linux"),
    expect(dead_code, reason = "only a Linux host has a control group to read")
)]
enum Holders {
    /// Nothing, as the kernel says.
    None,
    /// These processes, still.
    Some(Vec<ProcessStartIdentity>),
    /// The kernel would not say.
    Unreadable(String),
}

/// What asking the service manager to kill a group came to.
#[cfg_attr(
    not(target_os = "linux"),
    expect(dead_code, reason = "only a Linux host has a control group to kill")
)]
enum Forced {
    /// The group held nothing, or had already been asked.
    Nothing,
    /// The manager was asked, and did not refuse.
    Killed,
    /// The manager refused, did not answer, or could not be asked.
    Refused(String),
}

impl Group {
    /// The group at `path`, if its last component is the unit this reservation was started as.
    fn of(path: &str, unit: &str) -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            let last = path.rsplit('/').next()?;
            (last == format!("{unit}.service") || last == unit).then(|| Self {
                path: path.to_owned(),
                unit: unit.to_owned(),
                killed: false,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, unit);
            None
        }
    }

    /// Asks the service manager to kill everything in the unit, if the group still holds
    /// something.
    async fn force(&mut self) -> Forced {
        if self.killed || self.empty().await {
            return Forced::Nothing;
        }
        self.killed = true;
        #[cfg(target_os = "linux")]
        {
            let unit = self.unit.clone();
            return match tokio::task::spawn_blocking(move || {
                crate::supervision::kill_unit(&unit, FORCED)
            })
            .await
            {
                Ok(Ok(())) => Forced::Killed,
                Ok(Err(why)) => Forced::Refused(why),
                Err(_) => {
                    Forced::Refused("the call to the service manager did not finish".to_owned())
                }
            };
        }
        #[cfg(not(target_os = "linux"))]
        Forced::Nothing
    }

    /// Whether the kernel says the group holds nothing.
    async fn empty(&self) -> bool {
        matches!(self.holders().await, Holders::None)
    }

    /// What the group holds, as the kernel says.
    async fn holders(&self) -> Holders {
        #[cfg(target_os = "linux")]
        {
            let path = self.path.clone();
            tokio::task::spawn_blocking(move || read_group(&path))
                .await
                .unwrap_or_else(|_| {
                    Holders::Unreadable("reading the control group did not finish".to_owned())
                })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Holders::None
        }
    }
}

/// Reads a control group from the unified hierarchy's files.
#[cfg(target_os = "linux")]
fn read_group(path: &str) -> Holders {
    let root = std::path::Path::new("/sys/fs/cgroup");
    // The files below are the unified hierarchy's only if it is what is mounted here. Elsewhere a
    // directory that is not there says nothing about the group.
    match rustix::fs::statfs(root) {
        Ok(stat) if stat.f_type == 0x6367_7270 => {}
        Ok(_) => {
            return Holders::Unreadable(
                "/sys/fs/cgroup is not the unified control group hierarchy".to_owned(),
            );
        }
        Err(error) => {
            return Holders::Unreadable(format!("/sys/fs/cgroup could not be read: {error}"));
        }
    }
    let directory = root.join(path.trim_start_matches('/'));
    match std::fs::read_to_string(directory.join("cgroup.events")) {
        Ok(events) => {
            let populated = events
                .lines()
                .find_map(|line| line.strip_prefix("populated "))
                .map(str::trim);
            match populated {
                Some("0") => Holders::None,
                Some("1") => {
                    let mut held = Vec::new();
                    if let Ok(procs) = std::fs::read_to_string(directory.join("cgroup.procs")) {
                        for pid in procs
                            .lines()
                            .filter_map(|line| line.trim().parse::<u32>().ok())
                        {
                            if let Ok(identity) = kr_ipc::identity::process_start_identity(pid) {
                                held.push(identity);
                            }
                        }
                    }
                    if held.is_empty() {
                        Holders::Unreadable(format!(
                            "the control group {path} holds processes this host could not describe"
                        ))
                    } else {
                        Holders::Some(held)
                    }
                }
                _ => Holders::Unreadable(format!("the control group {path} has no populated line")),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A group that is gone is empty, if its parent is there to be asked.
            if directory.parent().is_some_and(std::path::Path::is_dir) {
                Holders::None
            } else {
                Holders::Unreadable(format!(
                    "the control group {path} and its parent are not there"
                ))
            }
        }
        Err(error) => Holders::Unreadable(format!(
            "the control group {path} could not be read: {error}"
        )),
    }
}
