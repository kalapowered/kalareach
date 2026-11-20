//! The cases of the endpoint's bind that need no second process.

use crate::endpoint::Listener;
use crate::error::IpcError;
use crate::listen::ListenRefusal;
use crate::paths::Endpoint;
use crate::testing::PrivateTempDir;

/// The refusal a bind returned, which the case expects to be a listen refusal.
fn refusal_of(result: crate::Result<Listener>) -> (String, ListenRefusal) {
    match result {
        Err(IpcError::Listen { endpoint, refusal }) => (endpoint, refusal),
        Err(other) => panic!("a listen refusal, not {other:?}"),
        Ok(_) => panic!("the bind was refused"),
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use crate::listen::ObjectKind;

    /// The folder's endpoint named `name`.
    fn endpoint_in(folder: &PrivateTempDir, name: &str) -> Endpoint {
        Endpoint::from_path(folder.path().join(name)).expect("an endpoint that fits the platform")
    }

    use std::os::unix::fs::MetadataExt as _;

    /// What stands at the path, by its device and inode, read without following a link.
    fn identity(path: &std::path::Path) -> (u64, u64) {
        let metadata = std::fs::symlink_metadata(path).expect("the path exists");
        (metadata.dev(), metadata.ino())
    }

    /// A file, a directory and a link at an endpoint are each named for what they are, and none
    /// is removed or replaced.
    #[tokio::test]
    async fn a_file_a_directory_and_a_link_at_the_endpoint_are_named_and_left_alone() {
        let folder = PrivateTempDir::create();
        let target = folder.path().join("target");
        std::fs::write(&target, b"somebody's file").expect("a file");
        for (name, object) in [
            ("file.sock", ObjectKind::File),
            ("directory.sock", ObjectKind::Directory),
            ("link.sock", ObjectKind::Link),
        ] {
            let path = folder.path().join(name);
            match object {
                ObjectKind::File => std::fs::write(&path, b"mine").expect("a file"),
                ObjectKind::Directory => std::fs::create_dir(&path).expect("a directory"),
                _ => std::os::unix::fs::symlink(&target, &path).expect("a link"),
            }
            let before = identity(&path);
            let (endpoint, refusal) = refusal_of(Listener::bind(&endpoint_in(&folder, name)));
            assert_eq!(refusal, ListenRefusal::NotASocket { object }, "{name}");
            assert_eq!(endpoint, path.to_str().expect("text"), "{name}");
            assert_eq!(identity(&path), before, "{name} is left where it was");
            let said = refusal.said(&endpoint);
            assert!(
                said.contains(object.phrase())
                    && said.contains("does not remove what it did not make"),
                "{said}"
            );
        }
        assert_eq!(
            std::fs::read(&target).expect("the target"),
            b"somebody's file"
        );
    }

    /// A bind whose address a live listener holds names the process that listens, the way the
    /// kernel gives it.
    #[tokio::test]
    async fn a_second_bind_names_the_process_that_holds_the_endpoint() {
        let folder = PrivateTempDir::create();
        let endpoint = endpoint_in(&folder, "held.sock");
        let _live = Listener::bind(&endpoint).expect("a live listener");
        let (_, refusal) = refusal_of(Listener::bind(&endpoint));
        assert_eq!(
            refusal,
            ListenRefusal::Held {
                pid: Some(std::process::id())
            }
        );
        let said = refusal.said(endpoint.as_path().to_str().expect("text"));
        assert!(
            said.contains(&format!("process {} started", std::process::id())),
            "{said}"
        );
    }
}

#[cfg(windows)]
mod windows {
    use super::*;

    /// A pipe name that exists is named taken, with no process and no instruction to stop one.
    #[tokio::test]
    async fn a_pipe_name_that_exists_is_named_taken_without_a_pid() {
        let name = format!("kr-ipc-taken-{}", crate::new_uuid());
        let endpoint = Endpoint::from_name(name).expect("a pipe name");
        let _first = Listener::bind(&endpoint).expect("the first instance");
        let (_, refusal) = refusal_of(Listener::bind(&endpoint));
        assert_eq!(refusal, ListenRefusal::NameTaken);
        let said = refusal.said(&endpoint.as_text());
        assert!(
            said.contains("the pipe is already in use by another program, or another account made it first, and kr cannot name the holder"),
            "{said}"
        );
        assert!(
            !said.contains("process") && !said.contains("stop"),
            "{said}"
        );
    }
}
