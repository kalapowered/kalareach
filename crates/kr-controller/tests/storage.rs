//! Where the host keeps its metadata.
//!
//! Section 4 puts host metadata and action receipts in SQLite: local persistence without a
//! database service. The daemon's session registry is that metadata, and this reads it as what it
//! is on disk.

use kr_controller::registry::Registry;

/// KR-REQ-04.06: the daemon's session registry is an SQLite database file this process opens
/// itself, with no database service running: its bytes begin with the SQLite header, an ordinary
/// SQLite connection lists its tables, and what one open wrote a later open reads back.
#[test]
fn the_host_metadata_is_an_sqlite_file_that_needs_no_database_service() {
    let host = kr_ipc::testing::TempHost::create();
    let path = host.environment().registry_database();
    {
        let mut registry = Registry::open(&path, host.environment_id()).expect("opens");
        assert_eq!(registry.advance_generation().expect("advances").get(), 1);
    }

    let bytes = std::fs::read(&path).expect("the registry is a file");
    assert!(
        bytes.starts_with(b"SQLite format 3\0"),
        "the registry file is an SQLite database"
    );
    let connection = rusqlite::Connection::open(&path).expect("an SQLite connection opens it");
    let tables: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .expect("prepares")
        .query_map([], |row| row.get(0))
        .expect("lists")
        .collect::<Result<_, _>>()
        .expect("reads");
    assert!(
        !tables.is_empty(),
        "the registry keeps its records in tables"
    );
    drop(connection);

    let reopened = Registry::open(&path, host.environment_id()).expect("reopens");
    assert_eq!(
        reopened.generation().expect("reads").get(),
        1,
        "what one open wrote, a later open reads"
    );
}
