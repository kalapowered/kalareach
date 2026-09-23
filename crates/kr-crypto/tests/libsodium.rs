//! The cryptography comes from the pinned libraries, through one narrow boundary.
//!
//! Section 20 puts `crypto_box_easy`, Ed25519 signatures, `crypto_secretstream_xchacha20poly1305`
//! and the pairing AEAD on libsodium's maintained C implementation, through a pinned
//! `libsodium-sys-stable` binding and a narrow safe Rust wrapper, keeps the pairing key derivation
//! on RustCrypto's HKDF, HMAC and SHA-256, puts the PAKE on a pinned library, and forbids the
//! application from implementing a cipher or PAKE primitive of its own. These tests check the pins
//! in the lock file, check that one module is the whole of the libsodium boundary, check the
//! constructions against vectors their authors published, and check that no source file in the
//! repository carries the constants a hand-written primitive would.

use std::path::{Path, PathBuf};

use kr_crypto::secret::SymmetricKey;
use kr_crypto::{CryptoError, aead, stream};
use kr_protocol::scalars::Nonce192;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The version requirement the workspace manifest gives one dependency.
fn workspace_requirement(name: &str) -> String {
    let manifest = read(&repository_root().join("Cargo.toml"));
    let line = manifest
        .lines()
        .find(|line| line.starts_with(&format!("{name} = ")))
        .unwrap_or_else(|| panic!("the workspace names {name}"));
    let start = line.find('"').expect("a quoted requirement") + 1;
    let end = start + line[start..].find('"').expect("a closing quote");
    line[start..end].to_owned()
}

/// Every `[[package]]` entry the lock file records under `name`, as its lines.
fn locked(name: &str) -> Vec<Vec<String>> {
    read(&repository_root().join("Cargo.lock"))
        .split("[[package]]")
        .filter(|entry| {
            entry
                .lines()
                .any(|line| line.trim() == format!("name = \"{name}\""))
        })
        .map(|entry| entry.lines().map(|line| line.trim().to_owned()).collect())
        .collect()
}

/// Every Rust source file under `directory`, skipping build output.
fn sources(directory: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            sources(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

/// Every product source file: each crate's `src` and the companion's native side.
fn product_sources() -> Vec<PathBuf> {
    let root = repository_root();
    let mut found = Vec::new();
    let crates = root.join("crates");
    for entry in std::fs::read_dir(&crates).expect("the crates directory") {
        sources(&entry.expect("a crate").path().join("src"), &mut found);
    }
    sources(&root.join("apps/companion/src-tauri/src"), &mut found);
    assert!(found.len() > 100, "the walk found the product's sources");
    found
}

fn relative(path: &Path) -> String {
    path.strip_prefix(repository_root())
        .unwrap_or(path)
        .display()
        .to_string()
}

/// KR-REQ-20.01: the binding is `libsodium-sys-stable` at one exact version: the workspace pins it
/// with `=`, the lock file records that release from the registry with its checksum, and the
/// cryptography crate is the only crate that depends on it.
#[test]
fn the_binding_is_the_pinned_libsodium_sys_stable_release() {
    let requirement = workspace_requirement("libsodium-sys-stable");
    let pinned = requirement
        .strip_prefix('=')
        .unwrap_or_else(|| panic!("libsodium-sys-stable is pinned exactly, not {requirement}"));

    let entries = locked("libsodium-sys-stable");
    assert_eq!(entries.len(), 1, "the lock file resolves one release");
    let entry = &entries[0];
    assert!(
        entry.contains(&format!("version = \"{pinned}\"")),
        "{entry:?}"
    );
    assert!(
        entry.contains(
            &"source = \"registry+https://github.com/rust-lang/crates.io-index\"".to_owned()
        ),
        "{entry:?}"
    );
    assert!(
        entry.iter().any(|line| line.starts_with("checksum = \"")),
        "{entry:?}"
    );

    let root = repository_root();
    let own = read(&root.join("crates/kr-crypto/Cargo.toml"));
    assert!(own.contains("libsodium-sys-stable.workspace = true"));
    let mut manifests: Vec<PathBuf> = std::fs::read_dir(root.join("crates"))
        .expect("the crates directory")
        .map(|entry| entry.expect("a crate").path().join("Cargo.toml"))
        .filter(|path| path.is_file())
        .collect();
    manifests.push(root.join("apps/companion/src-tauri/Cargo.toml"));
    for manifest in manifests {
        if manifest.ends_with("kr-crypto/Cargo.toml") {
            continue;
        }
        assert!(
            !read(&manifest).contains("libsodium-sys-stable"),
            "{} depends on the binding directly",
            relative(&manifest)
        );
    }
}

/// KR-REQ-20.01, KR-REQ-20.03: one module is the whole libsodium boundary: no other source file in
/// the repository uses the binding or declares a libsodium function of its own, and it is the only
/// module of the cryptography crate that may contain unsafe code.
#[test]
fn one_module_is_the_whole_libsodium_boundary() {
    let boundary = repository_root().join("crates/kr-crypto/src/sodium.rs");
    let mut naming = Vec::new();
    for path in product_sources() {
        let text = read(&path);
        if text.contains("libsodium_sys") {
            naming.push(relative(&path));
        }
        for declared in ["fn crypto_", "fn sodium_", "fn randombytes_"] {
            assert!(
                !text.contains(declared),
                "{} declares a libsodium function of its own",
                relative(&path)
            );
        }
        if path.starts_with(repository_root().join("crates/kr-crypto/src")) && path != boundary {
            assert!(
                !text.contains("allow(unsafe_code)"),
                "{} relaxes the crate's unsafe-code rule",
                relative(&path)
            );
        }
    }
    assert_eq!(naming, [relative(&boundary)]);
}

/// KR-REQ-20.01: the pairing AEAD is libsodium's XChaCha20-Poly1305: the vector its specification
/// publishes (draft-irtf-cfrg-xchacha, appendix A.3.1) opens through the crate's wrapper to exactly
/// its plaintext, and a changed tag, nonce or additional data does not open.
#[test]
fn the_pairing_aead_opens_the_published_xchacha20_poly1305_vector() {
    let key = SymmetricKey::from_bytes(
        hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .expect("the key")
            .try_into()
            .expect("32 bytes"),
    );
    let nonce = Nonce192::from_bytes(
        hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657")
            .expect("the nonce")
            .try_into()
            .expect("24 bytes"),
    );
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").expect("the additional data");
    let sealed = hex::decode(concat!(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
        "21f9664c97637da9768812f615c68b13b52e",
        // The tag.
        "c0875924c1c7987947deafd8780acf49"
    ))
    .expect("the ciphertext and tag");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one \
                      tip for the future, sunscreen would be it.";

    let opened = aead::open(&key, &nonce, &aad, &sealed).expect("the published vector opens");
    assert_eq!(opened.expose(), plaintext.as_slice());
    assert_eq!(aead::sealed_len(plaintext.len()), sealed.len());

    let mut tag_changed = sealed.clone();
    let last = tag_changed.len() - 1;
    tag_changed[last] ^= 1;
    assert!(matches!(
        aead::open(&key, &nonce, &aad, &tag_changed),
        Err(CryptoError::Authentication { .. })
    ));
    let mut other_nonce = *nonce.as_bytes();
    other_nonce[0] ^= 1;
    assert!(aead::open(&key, &Nonce192::from_bytes(other_nonce), &aad, &sealed).is_err());
    assert!(aead::open(&key, &nonce, b"other data", &sealed).is_err());
}

/// KR-REQ-20.01: an object goes through libsodium's `crypto_secretstream_xchacha20poly1305`: a
/// 24-byte header and 17 bytes per record, readable only in full, so a stream cut before its final
/// record or changed in one byte is refused.
#[test]
fn an_object_is_a_secretstream_that_needs_its_final_record() {
    let key = SymmetricKey::random().expect("a key");
    let plaintext = b"one small backup object".to_vec();
    let object = stream::encrypt_object(&key, &plaintext).expect("encrypts");
    assert_eq!(stream::HEADER_LEN, 24);
    assert_eq!(stream::RECORD_OVERHEAD, 17);
    assert_eq!(
        object.len(),
        stream::HEADER_LEN + plaintext.len() + stream::RECORD_OVERHEAD
    );
    assert_eq!(
        stream::decrypt_object(&key, &object)
            .expect("decrypts")
            .expose(),
        plaintext.as_slice()
    );

    // The same plaintext under the same key is a different object: the header is libsodium's own
    // random value, never one a caller supplies.
    assert_ne!(
        stream::encrypt_object(&key, &plaintext).expect("encrypts"),
        object
    );

    // A two-record object cut after its first record has no final record.
    let long = vec![7u8; stream::RECORD_LEN + 1];
    let two = stream::encrypt_object(&key, &long).expect("encrypts");
    let cut = &two[..stream::HEADER_LEN + stream::RECORD_LEN + stream::RECORD_OVERHEAD];
    assert!(matches!(
        stream::decrypt_object(&key, cut),
        Err(CryptoError::MissingFinalRecord)
    ));

    let mut changed = object;
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(stream::decrypt_object(&key, &changed).is_err());
}

/// KR-REQ-20.03: the cryptographic libraries are pinned exactly, and the PAKE is the pinned
/// `spake2` crate's, used by the pairing crate alone; no crate depends on a curve library to build
/// a primitive of its own.
#[test]
fn every_cryptographic_library_is_pinned_and_the_pake_is_the_librarys() {
    for name in ["libsodium-sys-stable", "spake2", "hkdf", "hmac", "sha2"] {
        let requirement = workspace_requirement(name);
        assert!(
            requirement.starts_with('='),
            "{name} is pinned exactly, not {requirement}"
        );
    }
    let root = repository_root();
    for entry in std::fs::read_dir(root.join("crates")).expect("the crates directory") {
        let manifest = entry.expect("a crate").path().join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        let text = read(&manifest);
        for curve in [
            "curve25519-dalek",
            "x25519-dalek",
            "ed25519-dalek",
            "p256",
            "k256",
        ] {
            assert!(
                !text
                    .lines()
                    .any(|line| line.trim_start().starts_with(curve)),
                "{} depends on {curve} directly",
                relative(&manifest)
            );
        }
        if text.contains("spake2") {
            assert!(
                manifest.ends_with("kr-pairing/Cargo.toml"),
                "{} depends on the PAKE library",
                relative(&manifest)
            );
        }
    }
}

/// KR-REQ-20.03: no product source file carries the constants a hand-written cipher, hash, MAC or
/// curve would: the ChaCha and Salsa20 constants, the SHA-2 initial values and round constants, the
/// Poly1305 clamp, the Curve25519 prime or the start of the AES S-box.
#[test]
fn no_source_file_carries_the_constants_of_a_primitive() {
    const PRIMITIVE_CONSTANTS: &[&str] = &[
        "expand 32-byte k",
        "expand 16-byte k",
        "0x61707865",
        "0x6a09e667",
        "0x428a2f98",
        "0x0ffffffc0fffffff",
        "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
        "0x63, 0x7c, 0x77, 0x7b",
    ];
    for path in product_sources() {
        let text = read(&path).to_ascii_lowercase();
        for constant in PRIMITIVE_CONSTANTS {
            assert!(
                !text.contains(constant),
                "{} carries {constant}",
                relative(&path)
            );
        }
    }
}
