//! The databases of a run's sessions, read from memory only. The harness reads each database's main
//! file, its `-wal` and its `-journal` through the run's handles, builds the database that SQLite
//! would read from them (the log's committed frames laid over the main file's pages, by a reader
//! of the log of its own), and gives SQLite that image and no file name, read only. SQLite opens
//! no path, so nothing an agent puts in the run can make it read, make or change a file.

use rusqlite::{Connection, MAIN_DB};

/// The most bytes an image may hold, and the most bytes the harness reads of one file of a database.
/// The databases of a run are far smaller. A log that claims more is refused, so that its claim
/// cannot make the harness allocate what it names, and a longer file is refused too.
pub(crate) const IMAGE_LIMIT: usize = 256 << 20;

/// The first bytes of every database file.
const MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// The bytes of a database file's header.
const HEADER: usize = 100;

/// The bytes of a log's header.
const LOG_HEADER: usize = 32;

/// The bytes of the header of each frame of a log.
const FRAME_HEADER: usize = 24;

/// The magic number of a log, whose last bit says how the checksums read their words.
const LOG_MAGIC: u32 = 0x377f_0682;

/// The version of the log's format that SQLite reads.
const LOG_VERSION: u32 = 3_007_000;

/// The files of one database as the harness read them from the run: the main file and, where each
/// is there, the `-wal` and the `-journal`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Files {
    /// The main file.
    pub main: Vec<u8>,
    /// The `-wal`, where there is one.
    pub wal: Option<Vec<u8>>,
    /// The `-journal`, where there is one.
    pub journal: Option<Vec<u8>>,
}

/// Gives `read` a connection to the database that `files` hold: an image made in memory, read only
/// and with no file name.
///
/// # Errors
///
/// Returns why the files cannot be read whole, or why SQLite refuses the image, or what `read`
/// returns.
pub fn read<T>(
    files: &Files,
    read: impl FnOnce(&Connection) -> Result<T, String>,
) -> Result<T, String> {
    let image = image(files)?;
    let mut connection = Connection::open_in_memory().map_err(|why| why.to_string())?;
    connection
        .pragma_update(None, "temp_store", "MEMORY")
        .map_err(|why| why.to_string())?;
    connection
        .deserialize_read_exact(MAIN_DB, image.as_slice(), image.len(), true)
        .map_err(|why| format!("SQLite does not take the image of the database: {why}"))?;
    read(&connection)
}

/// The database that SQLite would read from `files`: as many pages as the log's last commit says
/// (the main file's where the log holds no commit), each taken from the latest frame of the log up
/// to that commit that holds it, and from the main file where none does. The bytes that name
/// write-ahead mode are set to rollback mode, since the log has been applied.
///
/// # Errors
///
/// Returns why the files cannot be read whole: a main file of no bytes, a `-journal` that SQLite
/// would play back first, a main file that is not whole pages, a log whose header is torn or is not
/// SQLite's, a log of another page size, an image of no pages or of more than the limit.
pub fn image(files: &Files) -> Result<Vec<u8>, String> {
    if files.main.is_empty() {
        return Err(
            "the main file is empty, and SQLite reads a database whose main file is \
             empty as having no pages whatever its -wal holds"
                .to_owned(),
        );
    }
    if let Some(journal) = files
        .journal
        .as_deref()
        .filter(|journal| !journal.is_empty())
    {
        return Err(format!(
            "the -journal holds {} bytes, which SQLite plays back before it reads the database and \
             the harness does not",
            journal.len()
        ));
    }
    let main = files.main.as_slice();
    let main_page = page_size_of_main(main)?;
    let log = match files.wal.as_deref() {
        None | Some([]) => None,
        Some(wal) => Some(Log::of(wal)?),
    };
    if let Some(log) = &log
        && main_page != log.page_size
    {
        return Err(format!(
            "the -wal's page size is {}, not the main file's {main_page}",
            log.page_size
        ));
    }
    let committed = log.as_ref().and_then(Log::committed);
    let mut image = match (&log, committed) {
        (Some(log), Some((pages, frames))) => {
            let size = log.page_size;
            let length = usize::try_from(pages)
                .ok()
                .and_then(|pages| pages.checked_mul(size))
                .filter(|length| *length <= IMAGE_LIMIT)
                .ok_or_else(|| {
                    format!(
                        "the -wal's last commit says the database has {pages} pages of {size} \
                         bytes, more than the harness reads"
                    )
                })?;
            let mut image = vec![0_u8; length];
            for (number, page) in image.chunks_exact_mut(size).enumerate() {
                let number = u32::try_from(number + 1).unwrap_or(u32::MAX);
                if let Some(at) = frames.get(&number) {
                    page.copy_from_slice(&log.bytes[*at..*at + size]);
                } else if let Some(held) = main.chunks_exact(size).nth(number as usize - 1) {
                    page.copy_from_slice(held);
                }
            }
            image
        }
        _ => main.to_vec(),
    };
    if image.len() < HEADER || image[..16] != MAGIC[..] {
        return Err("the files do not hold a database".to_owned());
    }
    for at in [18, 19] {
        if image[at] == 2 {
            image[at] = 1;
        }
    }
    Ok(image)
}

/// The page size the main file's header names.
fn page_size_of_main(main: &[u8]) -> Result<usize, String> {
    if main.len() < HEADER || main[..16] != MAGIC[..] {
        return Err("the main file does not hold a database".to_owned());
    }
    let named = usize::from(u16::from_be_bytes([main[16], main[17]]));
    let size = if named == 1 { 65_536 } else { named };
    if !valid_page_size(size) {
        return Err(format!("the main file names a page size of {size}"));
    }
    if !main.len().is_multiple_of(size) {
        return Err(format!(
            "the main file holds {} bytes, which is not a whole number of its pages of {size}",
            main.len()
        ));
    }
    Ok(size)
}

fn valid_page_size(size: usize) -> bool {
    (512..=65_536).contains(&size) && size.is_power_of_two()
}

/// A log whose header SQLite accepts.
struct Log<'a> {
    bytes: &'a [u8],
    page_size: usize,
    /// Whether the checksums read their words as the most significant byte first.
    big: bool,
    salt: [u8; 8],
    /// The checksum of the header, where the frames' checksums begin.
    first: (u32, u32),
}

impl<'a> Log<'a> {
    /// The log in `bytes`: its header must be whole, hold SQLite's magic number, version and
    /// checksum, and name a page size SQLite takes. SQLite reads a log that fails these as an empty
    /// one; the harness refuses it, because a header that was half written when the file was read
    /// fails them too.
    fn of(bytes: &'a [u8]) -> Result<Self, String> {
        let refused = |why: &str| format!("the -wal's header is not one SQLite accepts: {why}");
        if bytes.len() < LOG_HEADER {
            return Err(refused(&format!("it is {} bytes long", bytes.len())));
        }
        let magic = be(&bytes[0..4]);
        if magic & 0xffff_fffe != LOG_MAGIC {
            return Err(refused("its magic number is not SQLite's"));
        }
        let big = magic & 1 == 1;
        let page_size = be(&bytes[8..12]) as usize;
        if !valid_page_size(page_size) {
            return Err(refused(&format!("it names a page size of {page_size}")));
        }
        let first = checksum(big, &bytes[..24], (0, 0));
        if first != (be(&bytes[24..28]), be(&bytes[28..32])) {
            return Err(refused("its checksum is wrong"));
        }
        if be(&bytes[4..8]) != LOG_VERSION {
            return Err(refused("its version is not the one SQLite reads"));
        }
        let mut salt = [0_u8; 8];
        salt.copy_from_slice(&bytes[16..24]);
        Ok(Self {
            bytes,
            page_size,
            big,
            salt,
            first,
        })
    }

    /// The pages of the database after the last commit frame of the log, and the offset in the log
    /// of the latest frame that holds each page up to that commit, or none where the log holds no
    /// commit. A frame counts only while its salts are the header's, its page number is not zero and
    /// its checksum, which runs on from the frame before it, is right; the first frame that fails
    /// ends the log. Frames after the last commit frame are not applied.
    fn committed(&self) -> Option<(u32, std::collections::BTreeMap<u32, usize>)> {
        let frame = FRAME_HEADER + self.page_size;
        let mut sum = self.first;
        let mut pending: Vec<(u32, usize)> = Vec::new();
        let mut found = std::collections::BTreeMap::new();
        let mut pages = None;
        for number in 0..(self.bytes.len() - LOG_HEADER) / frame {
            let at = LOG_HEADER + number * frame;
            let header = &self.bytes[at..at + FRAME_HEADER];
            let page = &self.bytes[at + FRAME_HEADER..at + frame];
            if header[8..16] != self.salt {
                break;
            }
            let held = be(&header[0..4]);
            if held == 0 {
                break;
            }
            sum = checksum(self.big, &header[..8], sum);
            sum = checksum(self.big, page, sum);
            if sum != (be(&header[16..20]), be(&header[20..24])) {
                break;
            }
            pending.push((held, at + FRAME_HEADER));
            let size_after = be(&header[4..8]);
            if size_after != 0 {
                found.extend(pending.drain(..));
                pages = Some(size_after);
            }
        }
        pages.map(|pages| (pages, found))
    }
}

/// The four bytes at the start of `bytes` as a number, most significant byte first.
fn be(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// SQLite's checksum of `data`, a multiple of eight bytes, continued from `from`: each pair of
/// words adds to the two sums, the first of the pair to the first sum with the second sum, the
/// second to the second sum with the first.
fn checksum(big: bool, data: &[u8], from: (u32, u32)) -> (u32, u32) {
    let word = |bytes: &[u8]| {
        let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if big {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        }
    };
    let (mut first, mut second) = from;
    for pair in data.chunks_exact(8) {
        first = first.wrapping_add(word(&pair[0..4])).wrapping_add(second);
        second = second.wrapping_add(word(&pair[4..8])).wrapping_add(first);
    }
    (first, second)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    /// The files of the database at `path`, as they stand: the main file and the `-wal` where it is
    /// there.
    fn files_at(path: &Path) -> Files {
        let wal = format!("{}-wal", path.display());
        Files {
            main: std::fs::read(path).expect("the main file"),
            wal: std::fs::read(wal).ok(),
            journal: None,
        }
    }

    /// The files of a database made with pages of `page_size` bytes in write-ahead mode that
    /// `steps` wrote to, read while the connection that wrote them is open and has not checkpointed
    /// them, as a copy of the files of a database that is in use holds them.
    fn made(page_size: u32, steps: impl FnOnce(&Connection)) -> Files {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("db.sqlite");
        let connection = Connection::open(&path).expect("a database");
        connection
            .execute_batch(&format!(
                "PRAGMA page_size = {page_size};
                 PRAGMA journal_mode = WAL;
                 PRAGMA wal_autocheckpoint = 0;"
            ))
            .expect("write-ahead mode");
        steps(&connection);
        let files = files_at(&path);
        drop(connection);
        files
    }

    /// Four transactions that insert, one that changes and removes, so that the log holds many
    /// frames that commit in several places.
    fn several(connection: &Connection) {
        connection
            .execute_batch("CREATE TABLE t (n INTEGER PRIMARY KEY, b BLOB);")
            .expect("a table");
        for _ in 0..4 {
            connection
                .execute_batch(
                    "BEGIN;
                     WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 40)
                       INSERT INTO t (b) SELECT randomblob(300) FROM c;
                     COMMIT;",
                )
                .expect("an insert");
        }
        connection
            .execute_batch(
                "BEGIN;
                 UPDATE t SET b = randomblob(300) WHERE n % 3 = 0;
                 DELETE FROM t WHERE n % 7 = 0;
                 COMMIT;",
            )
            .expect("a change");
    }

    /// The files of `files` written in a private directory, and the path of the main file there.
    fn on_disk(files: &Files) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("db.sqlite");
        std::fs::write(&path, &files.main).expect("the main file");
        if let Some(wal) = &files.wal {
            std::fs::write(directory.path().join("db.sqlite-wal"), wal).expect("the log");
        }
        (directory, path)
    }

    /// How many tables SQLite itself finds in `files`, in a private directory.
    fn tables_sqlite_finds(files: &Files) -> i64 {
        let (_directory, path) = on_disk(files);
        Connection::open(&path)
            .expect("SQLite opens the files")
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
                [],
                |row| row.get(0),
            )
            .expect("SQLite's own reading")
    }

    /// How many pages the last commit of the log of `files` gives the database, and how many
    /// different pages the log holds up to that commit.
    fn pages_the_log_commits_and_holds(files: &Files) -> (u32, usize) {
        let wal = files.wal.as_deref().expect("a log");
        let (pages, frames) = Log::of(wal)
            .expect("a log header")
            .committed()
            .expect("a commit");
        (pages, frames.len())
    }

    /// The database SQLite itself reads from `files`, in a private directory: its own recovery of
    /// the log, then its own serialisation of the pages as it reads them, with the bytes that name
    /// the mode read as the image reads them.
    fn sqlite_reads(files: &Files) -> Vec<u8> {
        let (_directory, path) = on_disk(files);
        let mut connection = Connection::open(&path).expect("SQLite opens the files");
        let mut bytes = connection
            .serialize(MAIN_DB)
            .expect("SQLite's own reading")
            .to_vec();
        for at in [18, 19] {
            if bytes[at] == 2 {
                bytes[at] = 1;
            }
        }
        bytes
    }

    /// Says where two byte strings first differ.
    fn first_difference(left: &[u8], right: &[u8]) -> String {
        match left
            .iter()
            .zip(right)
            .position(|(left, right)| left != right)
        {
            Some(at) => format!("they differ at byte {at}"),
            None => format!(
                "one is a prefix of the other, {} and {} bytes",
                left.len(),
                right.len()
            ),
        }
    }

    /// The image of `files` is the database SQLite reads from them.
    fn is_what_sqlite_reads(files: &Files, what: &str) {
        let mine =
            image(files).unwrap_or_else(|why| panic!("{what}: the files are refused: {why}"));
        let sqlites = sqlite_reads(files);
        assert!(
            mine == sqlites,
            "{what}: the image is not what SQLite reads, {}",
            first_difference(&mine, &sqlites)
        );
    }

    /// The bytes of one frame with its page: the log is a header and frames of this length.
    fn frame_length(files: &Files) -> usize {
        FRAME_HEADER + page_size_of_main(&files.main).expect("a page size")
    }

    /// The offset of the frame `number` of the log.
    fn frame_at(files: &Files, number: usize) -> usize {
        LOG_HEADER + number * frame_length(files)
    }

    /// The number of frames the log holds, whole ones only.
    fn frames_in(files: &Files) -> usize {
        (files.wal.as_ref().expect("a log").len() - LOG_HEADER) / frame_length(files)
    }

    /// The database that `files` make without their log.
    fn without_the_log(files: &Files) -> Vec<u8> {
        image(&Files {
            wal: None,
            ..files.clone()
        })
        .expect("the main file alone")
    }

    /// Several transactions in the log, at several page sizes, are the database SQLite reads, and
    /// differ from the main file alone, which is the database before them.
    #[test]
    fn the_image_of_several_transactions_is_what_sqlite_reads_at_each_page_size() {
        for page_size in [512, 1024, 4096, 65_536] {
            let files = made(page_size, several);
            assert!(
                frames_in(&files) > 4,
                "page size {page_size}: a log of many frames"
            );
            is_what_sqlite_reads(
                &files,
                &format!("several transactions, pages of {page_size}"),
            );
            assert_ne!(
                image(&files).expect("an image"),
                without_the_log(&files),
                "page size {page_size}: the log's frames are applied"
            );
        }
    }

    /// A log that ends after frames that no commit frame follows, or in the middle of a frame, is
    /// read to its last commit: the frames after it are not applied.
    #[test]
    fn frames_after_the_last_commit_are_not_applied() {
        let files = made(4096, several);
        let whole = image(&files).expect("an image");
        let frame = frame_length(&files);
        let wal = files.wal.clone().expect("a log");
        let short = |length: usize| Files {
            wal: Some(wal[..length].to_vec()),
            ..files.clone()
        };
        let without_the_last_frame = short(wal.len() - frame);
        is_what_sqlite_reads(&without_the_last_frame, "the last frame cut off");
        assert_ne!(
            image(&without_the_last_frame).expect("an image"),
            whole,
            "the transaction whose commit frame is gone is not applied"
        );
        is_what_sqlite_reads(&short(wal.len() - 10), "the last frame cut in the middle");
        let header_only = short(LOG_HEADER);
        is_what_sqlite_reads(&header_only, "a log of its header only");
        assert_eq!(
            image(&header_only).expect("an image"),
            without_the_log(&files)
        );
    }

    /// A frame whose page was changed after its checksum was made ends the log: it and the frames
    /// after it are not applied.
    #[test]
    fn a_frame_with_a_bad_checksum_ends_the_log() {
        let files = made(4096, several);
        let whole = image(&files).expect("an image");
        for number in [0, frames_in(&files) / 2, frames_in(&files) - 1] {
            let mut wal = files.wal.clone().expect("a log");
            wal[frame_at(&files, number) + FRAME_HEADER + 5] ^= 0xff;
            let changed = Files {
                wal: Some(wal),
                ..files.clone()
            };
            is_what_sqlite_reads(&changed, &format!("frame {number} with a bad checksum"));
            assert_ne!(
                image(&changed).expect("an image"),
                whole,
                "frame {number}: the frames from the bad one on are not applied"
            );
        }
    }

    /// A frame whose salts are not the header's ends the log even where its checksum is right,
    /// which the salts do not enter.
    #[test]
    fn a_frame_with_other_salts_ends_the_log_though_its_checksum_is_right() {
        let files = made(4096, several);
        let whole = image(&files).expect("an image");
        for number in [0, frames_in(&files) / 2] {
            let mut wal = files.wal.clone().expect("a log");
            wal[frame_at(&files, number) + 8] ^= 0xff;
            let changed = Files {
                wal: Some(wal),
                ..files.clone()
            };
            is_what_sqlite_reads(&changed, &format!("frame {number} with other salts"));
            assert_ne!(
                image(&changed).expect("an image"),
                whole,
                "frame {number}: the frames from the one with other salts on are not applied"
            );
        }
    }

    /// After the log has been restarted by a checkpoint, the frames of the log before it are still
    /// in the file beyond the new ones, with the old salts, and are not applied.
    #[test]
    fn frames_left_from_before_a_restart_of_the_log_are_not_applied() {
        let files = made(4096, |connection| {
            several(connection);
            connection
                .execute_batch("PRAGMA wal_checkpoint(RESTART);")
                .expect("a checkpoint");
            connection
                .execute_batch("BEGIN; INSERT INTO t (b) VALUES (randomblob(100)); COMMIT;")
                .expect("a transaction after the restart");
        });
        let wal = files.wal.as_ref().expect("a log");
        assert!(
            wal.len() > LOG_HEADER + 10 * frame_length(&files),
            "the log still holds the frames from before the restart"
        );
        is_what_sqlite_reads(&files, "after a restart of the log");
        assert_ne!(
            image(&files).expect("an image"),
            without_the_log(&files),
            "the transaction after the restart is applied"
        );
    }

    /// A database that shrank is as many pages as the last commit says, fewer than the main file
    /// holds.
    #[test]
    fn a_database_that_shrank_is_as_long_as_the_last_commit_says() {
        let files = made(4096, |connection| {
            several(connection);
            connection
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .expect("a checkpoint");
            connection
                .execute_batch("DELETE FROM t; VACUUM;")
                .expect("a smaller database");
        });
        is_what_sqlite_reads(&files, "a database that shrank");
        assert!(
            image(&files).expect("an image").len() < files.main.len(),
            "the image is shorter than the main file"
        );
    }

    /// The same log with its checksums read the other way round, as a log written on a machine of
    /// the other byte order is, is applied.
    #[test]
    fn a_log_whose_checksums_read_the_other_way_round_is_applied() {
        let files = made(4096, several);
        let mut wal = files.wal.clone().expect("a log");
        wal[3] |= 1;
        let mut sum = checksum(true, &wal[..24], (0, 0));
        wal[24..28].copy_from_slice(&sum.0.to_be_bytes());
        wal[28..32].copy_from_slice(&sum.1.to_be_bytes());
        for number in 0..frames_in(&files) {
            let at = frame_at(&files, number);
            sum = checksum(true, &wal[at..at + 8], sum);
            sum = checksum(
                true,
                &wal[at + FRAME_HEADER..at + frame_length(&files)],
                sum,
            );
            wal[at + 16..at + 20].copy_from_slice(&sum.0.to_be_bytes());
            wal[at + 20..at + 24].copy_from_slice(&sum.1.to_be_bytes());
        }
        let other = Files {
            wal: Some(wal),
            ..files.clone()
        };
        is_what_sqlite_reads(&other, "checksums read the other way round");
        assert_ne!(
            image(&other).expect("an image"),
            without_the_log(&files),
            "the frames are applied"
        );
    }

    /// A main file whose log was checkpointed into it is read as SQLite reads it, with no log and
    /// with an empty one.
    #[test]
    fn a_database_with_no_log_or_an_empty_log_is_its_main_file() {
        let files = made(4096, |connection| {
            connection
                .execute_batch("CREATE TABLE t (n INTEGER PRIMARY KEY, b BLOB);")
                .expect("a table");
            connection
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .expect("a checkpoint");
        });
        for wal in [None, Some(Vec::new())] {
            is_what_sqlite_reads(
                &Files {
                    wal,
                    ..files.clone()
                },
                "no log",
            );
        }
    }

    /// A log that SQLite would take as empty, and a header that a copy took in the middle of its
    /// writing, are refused and say why.
    #[test]
    fn a_log_whose_header_is_not_whole_or_not_sqlites_is_refused() {
        let files = made(4096, several);
        let wal = files.wal.clone().expect("a log");
        let refused = |wal: Vec<u8>| {
            image(&Files {
                wal: Some(wal),
                ..files.clone()
            })
            .expect_err("a log with a bad header is refused")
        };
        for length in [1, 31] {
            let why = refused(wal[..length].to_vec());
            assert!(
                why.contains(&format!("it is {length} bytes long")),
                "{length} bytes: {why}"
            );
        }
        let mut changed = wal.clone();
        changed[1] ^= 0xff;
        assert!(refused(changed).contains("its magic number is not SQLite's"));
        let mut changed = wal.clone();
        changed[9] ^= 0x01;
        assert!(refused(changed).contains("it names a page size of"));
        let mut changed = wal.clone();
        changed[17] ^= 0x01;
        assert!(refused(changed).contains("its checksum is wrong"));
        let mut changed = wal.clone();
        changed[7] ^= 0x01;
        let sum = checksum(false, &changed[..24], (0, 0));
        changed[24..28].copy_from_slice(&sum.0.to_be_bytes());
        changed[28..32].copy_from_slice(&sum.1.to_be_bytes());
        assert!(refused(changed).contains("its version is not the one SQLite reads"));
    }

    /// A log of another page size than the main file's, a `-journal` that holds anything, a main
    /// file that is not whole pages, a main file of no bytes and files that hold no database are
    /// refused.
    #[test]
    fn files_that_cannot_be_read_whole_are_refused_and_say_why() {
        let files = made(4096, several);
        let small = made(512, several);
        let why = image(&Files {
            wal: small.wal.clone(),
            ..files.clone()
        })
        .expect_err("a log of another page size");
        assert!(
            why.contains("the -wal's page size is 512, not the main file's 4096"),
            "{why}"
        );
        let why = image(&Files {
            journal: Some(vec![0; 512]),
            ..files.clone()
        })
        .expect_err("a journal that holds bytes");
        assert!(why.contains("the -journal holds 512 bytes"), "{why}");
        assert!(
            image(&Files {
                journal: Some(Vec::new()),
                ..files.clone()
            })
            .is_ok(),
            "a journal that holds nothing is nothing"
        );
        let why = image(&Files {
            main: files.main[..files.main.len() - 1].to_vec(),
            ..files.clone()
        })
        .expect_err("a main file that is not whole pages");
        assert!(why.contains("not a whole number of its pages"), "{why}");
        let why = image(&Files {
            main: Vec::new(),
            wal: None,
            journal: None,
        })
        .expect_err("a main file of no bytes");
        assert!(why.contains("the main file is empty"), "{why}");
        let why = image(&Files {
            main: vec![7; 4096],
            wal: None,
            journal: None,
        })
        .expect_err("a main file that is not a database");
        assert!(why.contains("does not hold a database"), "{why}");
    }

    /// A log of the page size of `files` that holds one frame: the page `number` with the bytes
    /// `page`, committing a database of `size_after` pages, with its checksum right.
    fn one_frame_log(files: &Files, number: u32, size_after: u32, page: &[u8]) -> Vec<u8> {
        let wal = files.wal.as_deref().expect("a log");
        let big = wal[3] & 1 == 1;
        let mut log = wal[..LOG_HEADER].to_vec();
        let mut header = [0_u8; FRAME_HEADER];
        header[0..4].copy_from_slice(&number.to_be_bytes());
        header[4..8].copy_from_slice(&size_after.to_be_bytes());
        header[8..16].copy_from_slice(&wal[16..24]);
        let sum = checksum(big, &log[..24], (0, 0));
        let sum = checksum(big, &header[..8], sum);
        let sum = checksum(big, page, sum);
        header[16..20].copy_from_slice(&sum.0.to_be_bytes());
        header[20..24].copy_from_slice(&sum.1.to_be_bytes());
        log.extend_from_slice(&header);
        log.extend_from_slice(page);
        log
    }

    /// A main file of no bytes is refused whatever the log and the journal hold. SQLite reads a
    /// database whose main file has no pages as empty and removes its log, so an image laid from a
    /// log that holds every page would be a database that a fresh open of the same files does not
    /// read.
    #[test]
    fn a_main_file_of_no_bytes_is_refused_whatever_the_log_and_the_journal_hold() {
        let files = made(4096, several);
        let (pages, held) = pages_the_log_commits_and_holds(&files);
        assert_eq!(
            held, pages as usize,
            "the log holds every page of the database it commits"
        );
        assert!(
            tables_sqlite_finds(&files) > 0,
            "the database with its log has its table"
        );
        let emptied = Files {
            main: Vec::new(),
            ..files.clone()
        };
        assert_eq!(
            tables_sqlite_finds(&emptied),
            0,
            "SQLite reads the emptied main file with its log as an empty database"
        );
        for (what, files) in [
            ("a log that holds every page", emptied.clone()),
            (
                "no log",
                Files {
                    wal: None,
                    ..emptied.clone()
                },
            ),
            (
                "an empty log",
                Files {
                    wal: Some(Vec::new()),
                    ..emptied.clone()
                },
            ),
            (
                "a journal that holds bytes",
                Files {
                    journal: Some(vec![0; 512]),
                    ..emptied.clone()
                },
            ),
        ] {
            match image(&files) {
                Ok(image) => panic!(
                    "{what}: an image of {} bytes is made from files whose main file is empty",
                    image.len()
                ),
                Err(why) => assert!(why.contains("the main file is empty"), "{what}: {why}"),
            }
        }
    }

    /// A log whose last commit lays a first page that is no database over a main file that is one
    /// gives files that hold no database.
    #[test]
    fn an_image_whose_first_page_is_no_database_is_refused() {
        let files = made(4096, several);
        let log = one_frame_log(&files, 1, 1, &[0; 4096]);
        let why = image(&Files {
            wal: Some(log),
            ..files
        })
        .expect_err("a first page that is no database");
        assert!(why.contains("do not hold a database"), "{why}");
    }

    /// A frame whose page number is 0 ends the log as SQLite reads it, though its checksum is right
    /// and it says that it commits a larger database: the image is the main file's.
    #[test]
    fn a_frame_of_page_zero_ends_the_log_though_its_checksum_is_right() {
        let files = made(4096, several);
        let pages = u32::try_from(files.main.len() / 4096).expect("a page count");
        let log = one_frame_log(&files, 0, pages + 2, &[7; 4096]);
        let with_the_frame = Files {
            wal: Some(log),
            ..files.clone()
        };
        is_what_sqlite_reads(&with_the_frame, "a frame of page 0");
        assert_eq!(
            image(&with_the_frame).expect("an image"),
            without_the_log(&files),
            "the frame ends the log"
        );
    }

    /// A last commit that says the database has more pages than the harness reads is refused, and
    /// nothing of that size is made.
    #[test]
    fn a_commit_that_names_more_pages_than_the_limit_is_refused() {
        let files = made(4096, several);
        let mut wal = files.wal.clone().expect("a log");
        let frame = frame_length(&files);
        wal.truncate(LOG_HEADER + frame);
        let big = wal[3] & 1 == 1;
        wal[LOG_HEADER + 4..LOG_HEADER + 8].copy_from_slice(&0x00ff_ffff_u32.to_be_bytes());
        let sum = checksum(big, &wal[..24], (0, 0));
        let sum = checksum(big, &wal[LOG_HEADER..LOG_HEADER + 8], sum);
        let sum = checksum(big, &wal[LOG_HEADER + FRAME_HEADER..], sum);
        wal[LOG_HEADER + 16..LOG_HEADER + 20].copy_from_slice(&sum.0.to_be_bytes());
        wal[LOG_HEADER + 20..LOG_HEADER + 24].copy_from_slice(&sum.1.to_be_bytes());
        let why = image(&Files {
            wal: Some(wal),
            ..files
        })
        .expect_err("a commit that names too many pages");
        assert!(why.contains("more than the harness reads"), "{why}");
    }

    /// SQLite is given the image with no file name and no write: what it holds is read only, its
    /// temporary tables stay in memory, and the file it names, if it names one, is not on disk.
    #[test]
    fn sqlite_is_given_the_image_with_no_file_and_no_write() {
        let files = made(4096, several);
        let rows = read(&files, |connection| {
            let file: Option<String> = connection
                .query_row(
                    "SELECT file FROM pragma_database_list WHERE name = 'main'",
                    [],
                    |row| row.get(0),
                )
                .map_err(|why| why.to_string())?;
            assert!(
                file.as_deref()
                    .is_none_or(|file| file.is_empty() || !Path::new(file).exists()),
                "SQLite holds a file at {file:?}"
            );
            let refused = connection
                .execute("INSERT INTO t (b) VALUES (x'00')", [])
                .expect_err("a write is refused");
            assert!(
                refused.to_string().contains("readonly"),
                "the write is refused as one to a read-only database: {refused}"
            );
            let temporary: i64 = connection
                .query_row("PRAGMA temp_store", [], |row| row.get(0))
                .map_err(|why| why.to_string())?;
            assert_eq!(temporary, 2, "temporary tables are kept in memory");
            connection
                .query_row("SELECT count(*) FROM t", [], |row| row.get::<_, i64>(0))
                .map_err(|why| why.to_string())
        })
        .expect("the image is read");
        assert!(rows > 0, "the rows of the log's transactions are there");
    }
}
