//! The model files this daemon keeps for descriptions, and the fetch that puts them there.
//!
//! The files of the selected profile live in `<state>/models/<profile>/<revision>/`, where the
//! description process looks for them. A fetch writes each one as `<file>.partial`, has the
//! description process check it against the size and digest the profile records, and renames it
//! into place only once it has passed. When every file is in place a marker is written beside
//! them, and the marker is what says this host holds the profile's files: without it nothing is
//! loaded and a session is shown its metadata title. The process checks each file again at every
//! load, and one it refuses clears the marker, so the next fetch starts from nothing.
//!
//! A fetch asks for no account. It goes to the addresses the profile names, and follows at most five
//! redirects from them, through the proxy the daemon started with; whatever answers, a file is kept
//! only once its size and digest are the profile's. It refuses a file larger than the profile
//! records, as it refuses to begin when the disk has less room than the files need. It runs as a
//! task of its own, so nothing on the host's thread or on a keystroke's path waits for it, and a
//! cancellation stops it between two chunks of the body. A fetch that is cancelled or fails removes
//! the files it wrote, and one that is kept removes the files of the profile's other revisions.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kr_describe::profile::{Asset, ModelProfile};
use kr_describe::service::DownloadProgress;
use kr_describe::supervise::Checked;
use kr_describe::wire::VerifyResult;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::watch;

use super::host::{CheckRequest, DescribeHost};
use crate::error::{ControllerError, Result};

/// The marker that says a profile's files are all here and have passed their check.
const MARKER: &str = "held.json";

/// What a file is called while it is being fetched and checked.
const PARTIAL_SUFFIX: &str = ".partial";

/// How long a connection may take to be made.
const CONNECT: Duration = Duration::from_secs(30);

/// How long the fetch waits for the server's answer, and then for each chunk of the body, before it
/// is given up. A test shortens it through the host.
pub(crate) const STALL: Duration = Duration::from_secs(60);

/// The room left on the disk beyond the files themselves.
const ROOM_BEYOND: u64 = 256 * 1024 * 1024;

/// How often the progress is told to the host while a body arrives.
const PROGRESS_EVERY: Duration = Duration::from_millis(250);

/// The HTTP client a fetch uses: this product's trust and the proxy the daemon started with, and
/// nothing of the environment's.
///
/// # Errors
///
/// Returns [`ControllerError::Refused`] when the client cannot be built.
pub(crate) fn client(proxy: Option<&kr_transport::config::ProxyUrl>) -> Result<reqwest::Client> {
    let refused = |why: String| ControllerError::Refused {
        code: kr_protocol::error::ErrorCode::ResourceUnavailable,
        detail: format!("this host cannot fetch the model's files: {why}"),
    };
    kr_client::services::http::client_builder(proxy)
        .map_err(|error| refused(error.to_string()))?
        .connect_timeout(CONNECT)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|error| refused(error.to_string()))
}

/// The directory a profile's files are kept in.
pub(crate) fn directory(models: &Path, profile: &ModelProfile) -> PathBuf {
    models
        .join(profile.profile_id())
        .join(profile.revision().get().to_string())
}

/// What the marker says when it says this host holds `profile`: the profile and each of its files
/// with the size and digest it was checked against, so a marker written for another revision or
/// another catalogue is never taken for this one's.
fn marker_text(profile: &ModelProfile) -> String {
    serde_json::json!({
        "profile_id": profile.profile_id(),
        "revision": profile.revision().get(),
        "files": profile
            .assets()
            .iter()
            .map(|asset| serde_json::json!({
                "file_name": asset.file_name,
                "bytes": asset.bytes,
                "sha256": asset.sha256,
            }))
            .collect::<Vec<_>>(),
    })
    .to_string()
}

/// Whether this host holds `profile`'s files: its marker is there and is its own, and each file is
/// there at the size the profile records. The digest is the process's to check, at each load.
pub(crate) fn held(models: &Path, profile: &ModelProfile) -> bool {
    let here = directory(models, profile);
    std::fs::read_to_string(here.join(MARKER)).is_ok_and(|text| text == marker_text(profile))
        && profile.assets().iter().all(|asset| {
            std::fs::metadata(here.join(&asset.file_name))
                .is_ok_and(|about| about.is_file() && about.len() == asset.bytes)
        })
}

/// Writes the marker, once every file is in place and has passed its check.
pub(crate) fn mark_held(models: &Path, profile: &ModelProfile) -> std::io::Result<()> {
    let here = directory(models, profile);
    let pending = here.join(format!("{MARKER}{PARTIAL_SUFFIX}"));
    std::fs::write(&pending, marker_text(profile))?;
    std::fs::rename(pending, here.join(MARKER))
}

/// Takes the marker away: the files are not to be taken for held any more.
pub(crate) fn clear_marker(models: &Path, profile: &ModelProfile) {
    let _ = std::fs::remove_file(directory(models, profile).join(MARKER));
}

/// How a fetch ended.
#[derive(Debug, PartialEq, Eq)]
enum Ended {
    /// Every file is in place and has passed its check.
    Verified,
    /// A person stopped it.
    Cancelled,
    /// It could not finish, and why.
    Failed(String),
}

/// The fetch that is running, when one is.
#[derive(Debug, Default)]
pub(crate) struct Fetches {
    running: std::sync::Mutex<Option<Running>>,
}

#[derive(Debug)]
struct Running {
    cancel: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Fetches {
    fn running(&self) -> std::sync::MutexGuard<'_, Option<Running>> {
        self.running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Starts the fetch of `profile`'s files unless one is running. It returns what completes once
    /// the host has taken the fetch's first progress and published it, which is when the setup
    /// answer shows the fetch as running; none when a fetch was already running.
    ///
    /// Nothing here waits, so a caller can start a fetch inside a registration it holds.
    pub(crate) fn start(
        &self,
        host: Arc<DescribeHost>,
        profile: ModelProfile,
        client: reqwest::Client,
    ) -> Option<tokio::sync::oneshot::Receiver<()>> {
        let mut running = self.running();
        if running
            .as_ref()
            .is_some_and(|held| !held.task.is_finished())
        {
            return None;
        }
        let (cancel, cancelled) = watch::channel(false);
        let taken = host.progress_and_wait(DownloadProgress::Running {
            fetched_bytes: 0,
            total_bytes: total_bytes(&profile),
        });
        let task = tokio::spawn(async move {
            let ended = fetch(&host, &profile, &client, cancelled).await;
            match ended {
                Ended::Verified => host.progress(DownloadProgress::Verified),
                Ended::Cancelled => host.progress(DownloadProgress::Cancelled),
                Ended::Failed(why) => host.progress(DownloadProgress::Failed { why }),
            }
        });
        *running = Some(Running { cancel, task });
        Some(taken)
    }

    /// Asks the running fetch to stop, and says whether one was running.
    pub(crate) fn cancel(&self) -> bool {
        self.running().as_ref().is_some_and(|held| {
            let alive = !held.task.is_finished();
            if alive {
                let _ = held.cancel.send(true);
            }
            alive
        })
    }
}

fn total_bytes(profile: &ModelProfile) -> u64 {
    profile.assets().iter().map(|asset| asset.bytes).sum()
}

/// Completes once the fetch is cancelled, and never when it is not.
async fn until_cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow_and_update() {
            return;
        }
        if cancel.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Fetches, checks and places every file of `profile`, and marks them held; when it ends any other
/// way, the files it had put in place are removed.
async fn fetch(
    host: &Arc<DescribeHost>,
    profile: &ModelProfile,
    client: &reqwest::Client,
    cancel: watch::Receiver<bool>,
) -> Ended {
    let mut placed = Vec::new();
    let ended = fetch_all(host, profile, client, cancel, &mut placed).await;
    if ended != Ended::Verified {
        for file in placed {
            let _ = tokio::fs::remove_file(file).await;
        }
    }
    ended
}

/// Fetches, checks and places every file of `profile`, and marks them held, recording each file it
/// puts in place.
async fn fetch_all(
    host: &Arc<DescribeHost>,
    profile: &ModelProfile,
    client: &reqwest::Client,
    mut cancel: watch::Receiver<bool>,
    placed: &mut Vec<PathBuf>,
) -> Ended {
    let models = host.models().to_path_buf();
    let here = directory(&models, profile);
    if let Err(error) = tokio::fs::create_dir_all(&here).await {
        return Ended::Failed(format!(
            "the folder for the model's files could not be made: {error}"
        ));
    }
    // A marker from before says nothing about files that are about to be replaced.
    clear_marker(&models, profile);
    host.assets_held(false);
    let total = total_bytes(profile);
    if let Some(free) = host.free_space(&here)
        && free < total.saturating_add(ROOM_BEYOND)
    {
        return Ended::Failed(format!(
            "the disk has {free} bytes free, and the model's files need {total} bytes and some \
             room beside them"
        ));
    }
    let mut fetched_before = 0_u64;
    for asset in profile.assets() {
        let partial = here.join(format!("{}{PARTIAL_SUFFIX}", asset.file_name));
        let ended = fetch_one(
            host,
            profile,
            asset,
            client,
            &partial,
            fetched_before,
            total,
            &mut cancel,
        )
        .await;
        if ended != Ended::Verified {
            return ended;
        }
        let file = here.join(&asset.file_name);
        if let Err(error) = tokio::fs::rename(&partial, &file).await {
            let _ = tokio::fs::remove_file(&partial).await;
            return Ended::Failed(format!(
                "{} could not be put in place: {error}",
                asset.file_name
            ));
        }
        placed.push(file);
        fetched_before = fetched_before.saturating_add(asset.bytes);
    }
    // The last look before the files are kept, and the one that honours a cancellation that came
    // while the process was checking a file even though the check ended as passed: the process may
    // have answered before it read the cancellation. A cancellation that comes after this finds
    // the files held.
    if *cancel.borrow() {
        return Ended::Cancelled;
    }
    if let Err(error) = mark_held(&models, profile) {
        return Ended::Failed(format!("the model's files could not be marked: {error}"));
    }
    let (kept_models, kept_profile) = (models.clone(), profile.clone());
    let _ =
        tokio::task::spawn_blocking(move || remove_other_revisions(&kept_models, &kept_profile))
            .await;
    host.assets_held(true);
    Ended::Verified
}

/// Removes the directories of the profile's other revisions, which the held files have replaced. It
/// runs when a fetch has kept its files and again when a daemon starts that finds them held, so a
/// removal that failed once (a file still mapped by a process that was going) is tried again.
pub(crate) fn remove_other_revisions(models: &Path, profile: &ModelProfile) {
    let kept = directory(models, profile);
    let Some(profile_directory) = kept.parent() else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(profile_directory) else {
        return;
    };
    for entry in entries.filter_map(std::result::Result::ok) {
        let other = entry.path();
        if other != kept && other.is_dir() {
            let _ = std::fs::remove_dir_all(other);
        }
    }
}

/// Removes what a fetch that did not end left in the selected profile's directory: a partial file.
/// Files that are kept are held by a marker, and nothing else is taken away.
pub(crate) fn remove_leftovers(models: &Path, profile: &ModelProfile) {
    let Ok(entries) = std::fs::read_dir(directory(models, profile)) else {
        return;
    };
    for entry in entries.filter_map(std::result::Result::ok) {
        let name = entry.file_name();
        if name.to_string_lossy().ends_with(PARTIAL_SUFFIX) && entry.path().is_file() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Fetches one file to its partial, has the process check it, and leaves it checked, or deletes it.
#[allow(clippy::too_many_arguments)]
async fn fetch_one(
    host: &Arc<DescribeHost>,
    profile: &ModelProfile,
    asset: &Asset,
    client: &reqwest::Client,
    partial: &Path,
    fetched_before: u64,
    total: u64,
    cancel: &mut watch::Receiver<bool>,
) -> Ended {
    let received = match receive(host, asset, client, partial, fetched_before, total, cancel).await
    {
        Ok(received) => received,
        Err(ended) => {
            // Nothing is reading the file: no check has been asked for yet.
            let _ = tokio::fs::remove_file(partial).await;
            return ended;
        }
    };
    debug_assert_eq!(received, asset.bytes);
    let ended = check(host, profile, asset, partial, cancel).await;
    if ended != Ended::Verified {
        // Deleted only now, once the process has said it has done with the file.
        let _ = tokio::fs::remove_file(partial).await;
    }
    ended
}

/// Writes the body of `asset` to `partial`, and returns how many bytes it was.
async fn receive(
    host: &Arc<DescribeHost>,
    asset: &Asset,
    client: &reqwest::Client,
    partial: &Path,
    fetched_before: u64,
    total: u64,
    cancel: &mut watch::Receiver<bool>,
) -> std::result::Result<u64, Ended> {
    let source = asset
        .url
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        .unwrap_or("the model's source")
        .to_owned();
    let stall = host.stall();
    let mut response = tokio::select! {
        sent = tokio::time::timeout(stall, client.get(&asset.url).send()) => match sent {
            Err(_) => return Err(Ended::Failed(format!(
                "{source} did not answer within {} seconds", stall.as_secs()
            ))),
            Ok(sent) => sent.map_err(|error| {
                Ended::Failed(format!("{source} could not be reached: {}", error.without_url()))
            })?,
        },
        () = until_cancelled(cancel) => return Err(Ended::Cancelled),
    };
    if !response.status().is_success() {
        return Err(Ended::Failed(format!(
            "{source} answered {} for {}",
            response.status(),
            asset.file_name
        )));
    }
    if let Some(declared) = response.content_length()
        && declared > asset.bytes
    {
        return Err(Ended::Failed(format!(
            "{source} says {} is {declared} bytes, and the profile records {} bytes",
            asset.file_name, asset.bytes
        )));
    }
    let mut file = tokio::fs::File::create(partial).await.map_err(|error| {
        Ended::Failed(format!("{} could not be written: {error}", asset.file_name))
    })?;
    let mut received = 0_u64;
    let mut told = tokio::time::Instant::now();
    loop {
        let chunk = tokio::select! {
            chunk = tokio::time::timeout(stall, response.chunk()) => match chunk {
                Err(_) => return Err(Ended::Failed(format!(
                    "{source} sent nothing for {} seconds", stall.as_secs()
                ))),
                Ok(Err(error)) => return Err(Ended::Failed(format!(
                    "{source} broke off: {}", error.without_url()
                ))),
                Ok(Ok(chunk)) => chunk,
            },
            () = until_cancelled(cancel) => return Err(Ended::Cancelled),
        };
        let Some(chunk) = chunk else { break };
        received = received.saturating_add(chunk.len() as u64);
        if received > asset.bytes {
            return Err(Ended::Failed(format!(
                "{source} sent more than the {} bytes the profile records for {}",
                asset.bytes, asset.file_name
            )));
        }
        file.write_all(&chunk).await.map_err(|error| {
            Ended::Failed(format!("{} could not be written: {error}", asset.file_name))
        })?;
        if told.elapsed() >= PROGRESS_EVERY {
            told = tokio::time::Instant::now();
            host.progress(DownloadProgress::Running {
                fetched_bytes: fetched_before.saturating_add(received),
                total_bytes: total,
            });
        }
    }
    if received != asset.bytes {
        return Err(Ended::Failed(format!(
            "{source} ended {} after {received} of {} bytes",
            asset.file_name, asset.bytes
        )));
    }
    file.sync_all().await.map_err(|error| {
        Ended::Failed(format!("{} could not be written: {error}", asset.file_name))
    })?;
    host.progress(DownloadProgress::Running {
        fetched_bytes: fetched_before.saturating_add(received),
        total_bytes: total,
    });
    Ok(received)
}

/// How long the process is given to check a file of `bytes`, in milliseconds.
fn check_deadline_ms(bytes: u64) -> u64 {
    // Reading the file whole at ten megabytes a second, which the process's lowest scheduling class
    // can come to on a busy host, and two minutes beside it: a good download is never thrown away
    // for the time a check took.
    120_000_u64.saturating_add(bytes / 10_000)
}

/// Has the description process check `partial` against `asset`, and waits for it to say so, however
/// long that takes within its own deadline: the file is not touched until it has.
async fn check(
    host: &Arc<DescribeHost>,
    profile: &ModelProfile,
    asset: &Asset,
    partial: &Path,
    cancel: &mut watch::Receiver<bool>,
) -> Ended {
    let mut answer = host.check(CheckRequest {
        profile_id: profile.profile_id().to_owned(),
        revision: profile.revision().get(),
        file_name: asset.file_name.clone(),
        path: partial.to_path_buf(),
        deadline_ms: check_deadline_ms(asset.bytes),
    });
    let mut asked = false;
    let checked = loop {
        tokio::select! {
            checked = &mut answer => break checked,
            () = until_cancelled(cancel), if !asked => {
                asked = true;
                host.cancel_check();
            }
        }
    };
    match checked {
        Err(_) => Ended::Failed("the description process could not check the file".to_owned()),
        Ok(Checked::Answered { result, detail }) => match result {
            VerifyResult::Verified => Ended::Verified,
            VerifyResult::Cancelled => Ended::Cancelled,
            VerifyResult::Mismatch => Ended::Failed(format!(
                "{} is not the file the profile records{}",
                asset.file_name,
                detail
                    .map(|detail| format!(": {detail}"))
                    .unwrap_or_default()
            )),
            VerifyResult::Unreadable | VerifyResult::DeadlineExceeded | VerifyResult::Refused => {
                Ended::Failed(format!(
                    "{} could not be checked{}",
                    asset.file_name,
                    detail
                        .map(|detail| format!(": {detail}"))
                        .unwrap_or_default()
                ))
            }
        },
        Ok(Checked::ProcessEnded { .. } | Checked::Unloaded | Checked::Refused) => {
            Ended::Failed("the description process ended while it checked the file".to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default profile this build ships, whose files are too large to write: each is made
    /// sparse, at exactly the size the profile records.
    fn profile() -> ModelProfile {
        kr_describe::Catalogue::builtin()
            .expect("the profiles this build ships")
            .default_profile()
            .clone()
    }

    /// The check is given time to read the whole file at ten megabytes a second and two minutes
    /// beside that, so a good download is not thrown away for the time a busy host took to hash it.
    #[test]
    fn a_check_is_given_the_time_to_read_the_whole_file_slowly() {
        for asset in profile().assets() {
            let allowed = check_deadline_ms(asset.bytes);
            assert!(
                allowed >= 120_000 + asset.bytes / 10_000,
                "{} bytes are given {allowed} ms",
                asset.bytes
            );
        }
        assert_eq!(
            check_deadline_ms(0),
            120_000,
            "a file of nothing keeps the margin"
        );
    }

    fn sparse(path: &Path, length: u64) {
        std::fs::File::create(path)
            .and_then(|file| file.set_len(length))
            .expect("a sparse file");
    }

    /// The files are held only with the marker written for this profile and each file there at the
    /// size it records; a marker that is another's, a file of another size and a file that is gone
    /// each say they are not, and clearing the marker says so too. The directory is the profile's
    /// and its revision's.
    #[test]
    fn files_are_held_only_with_their_marker_and_each_file_at_its_recorded_size() {
        let models = tempfile::tempdir().expect("a directory");
        let profile = profile();
        let here = directory(models.path(), &profile);
        assert_eq!(
            here,
            models
                .path()
                .join(profile.profile_id())
                .join(profile.revision().get().to_string())
        );
        std::fs::create_dir_all(&here).expect("the model directory");
        let first = &profile.assets()[0];
        for asset in profile.assets() {
            sparse(&here.join(&asset.file_name), asset.bytes);
        }
        assert!(!held(models.path(), &profile), "no marker");

        mark_held(models.path(), &profile).expect("the marker");
        assert!(held(models.path(), &profile));
        assert!(
            !here.join(format!("{MARKER}{PARTIAL_SUFFIX}")).exists(),
            "the marker is written whole and renamed"
        );

        std::fs::write(here.join(MARKER), b"{}").expect("another marker");
        assert!(
            !held(models.path(), &profile),
            "a marker that is not this profile's"
        );
        mark_held(models.path(), &profile).expect("the marker");
        assert!(held(models.path(), &profile));

        sparse(&here.join(&first.file_name), first.bytes - 1);
        assert!(!held(models.path(), &profile), "a file of another size");
        sparse(&here.join(&first.file_name), first.bytes);
        assert!(held(models.path(), &profile));
        std::fs::remove_file(here.join(&first.file_name)).expect("a file gone");
        assert!(!held(models.path(), &profile), "a file that is gone");
        sparse(&here.join(&first.file_name), first.bytes);
        assert!(held(models.path(), &profile));

        clear_marker(models.path(), &profile);
        assert!(!held(models.path(), &profile), "the marker taken away");
    }
}
