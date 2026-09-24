//! A Pkarr relay running in this process.
//!
//! An endpoint publishes its signed record with `PUT <url>/<key>` and a resolver reads it back with
//! `GET <url>/<key>`, where the key is the endpoint identity in z-base-32. Both carry the signed
//! payload exactly as the endpoint produced it and the resolver verifies the signature itself, so
//! this server stores bytes and never has to read them. It keeps the latest record for each key,
//! which is what a relay does for a record that is republished, and it counts what it was asked for
//! each key, so a test can tell which relay an endpoint published to and which one it resolved
//! from.
//!
//! It answers plain HTTP on loopback from threads of its own, so nothing about it depends on the
//! runtime the endpoints run on, and it closes every connection and joins every thread when it is
//! dropped.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// The most a published record may weigh. A signed Pkarr packet is at most 1,104 bytes.
const MAX_RECORD: usize = 2048;

/// What the relay holds and what it was asked, by endpoint identity in z-base-32.
#[derive(Debug, Default)]
struct Held {
    records: HashMap<String, Vec<u8>>,
    publications: HashMap<String, usize>,
    lookups: HashMap<String, usize>,
}

/// The connections the relay accepted: a handle to close each one, and the thread serving it.
type Connections = Arc<Mutex<Vec<(TcpStream, JoinHandle<()>)>>>;

/// A Pkarr relay on loopback.
pub struct PkarrRelay {
    /// Where an endpoint publishes to and resolves from.
    pub url: kr_transport::config::Url,
    held: Arc<Mutex<Held>>,
    stopping: Arc<AtomicBool>,
    addr: SocketAddr,
    accepting: Option<JoinHandle<()>>,
    connections: Connections,
}

impl PkarrRelay {
    /// Starts a relay on a free loopback port.
    pub fn spawn() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a Pkarr listener");
        let addr = listener.local_addr().expect("a bound address");
        let held = Arc::new(Mutex::new(Held::default()));
        let stopping = Arc::new(AtomicBool::new(false));
        let connections = Connections::default();
        let accepting = {
            let held = Arc::clone(&held);
            let stopping = Arc::clone(&stopping);
            let connections = Arc::clone(&connections);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stopping.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else {
                        continue;
                    };
                    let Ok(closer) = stream.try_clone() else {
                        continue;
                    };
                    let held = Arc::clone(&held);
                    let serving = std::thread::spawn(move || serve(stream, &held));
                    connections
                        .lock()
                        .expect("the connections")
                        .push((closer, serving));
                }
            })
        };
        Self {
            url: format!("http://{addr}/pkarr")
                .parse()
                .expect("a Pkarr relay URL"),
            held,
            stopping,
            addr,
            accepting: Some(accepting),
            connections,
        }
    }

    /// Returns true once the relay holds a record for this endpoint.
    pub fn holds(&self, endpoint: &iroh::EndpointId) -> bool {
        self.record(endpoint).is_some()
    }

    /// The record the relay holds for this endpoint, as the endpoint signed it.
    pub fn record(&self, endpoint: &iroh::EndpointId) -> Option<Vec<u8>> {
        self.held
            .lock()
            .expect("the records")
            .records
            .get(&endpoint.to_z32())
            .cloned()
    }

    /// Stores a record as a relay that received it from elsewhere, without counting a publication.
    pub fn hold(&self, endpoint: &iroh::EndpointId, record: Vec<u8>) {
        self.held
            .lock()
            .expect("the records")
            .records
            .insert(endpoint.to_z32(), record);
    }

    /// How many times this endpoint's record was published here.
    pub fn publications(&self, endpoint: &iroh::EndpointId) -> usize {
        let held = self.held.lock().expect("the records");
        held.publications
            .get(&endpoint.to_z32())
            .copied()
            .unwrap_or(0)
    }

    /// How many times this endpoint's record was looked up here.
    pub fn lookups(&self, endpoint: &iroh::EndpointId) -> usize {
        let held = self.held.lock().expect("the records");
        held.lookups.get(&endpoint.to_z32()).copied().unwrap_or(0)
    }
}

impl Drop for PkarrRelay {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        // Wakes the accept loop so it sees the flag, then waits for it: after that nothing adds a
        // connection, so closing the ones it accepted leaves none behind.
        let _ = TcpStream::connect(self.addr);
        if let Some(accepting) = self.accepting.take() {
            let _ = accepting.join();
        }
        let connections = std::mem::take(&mut *self.connections.lock().expect("the connections"));
        for (closer, serving) in connections {
            let _ = closer.shutdown(Shutdown::Both);
            let _ = serving.join();
        }
    }
}

/// Answers the requests on one connection until the client or the relay closes it.
fn serve(stream: TcpStream, held: &Mutex<Held>) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    loop {
        let mut request_line = String::new();
        match reader.read_line(&mut request_line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let mut parts = request_line.split_whitespace();
        let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
            return;
        };
        let (method, path) = (method.to_owned(), path.to_owned());
        let mut length = 0_usize;
        loop {
            let mut header = String::new();
            match reader.read_line(&mut header) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':')
                && name.trim().eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse().unwrap_or(usize::MAX);
            }
        }
        if length > MAX_RECORD {
            let _ =
                writer.write_all(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n");
            return;
        }
        let mut body = vec![0_u8; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        let key = path.strip_prefix("/pkarr/").map(ToOwned::to_owned);
        let (status, reason, payload) = match (method.as_str(), key) {
            ("PUT", Some(key)) => {
                let mut held = held.lock().expect("the records");
                *held.publications.entry(key.clone()).or_default() += 1;
                held.records.insert(key, body);
                (204, "No Content", Vec::new())
            }
            ("GET", Some(key)) => {
                let mut held = held.lock().expect("the records");
                *held.lookups.entry(key.clone()).or_default() += 1;
                match held.records.get(&key) {
                    Some(record) => (200, "OK", record.clone()),
                    None => (404, "Not Found", Vec::new()),
                }
            }
            _ => (405, "Method Not Allowed", Vec::new()),
        };
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n\r\n",
            payload.len()
        );
        if writer
            .write_all(head.as_bytes())
            .and_then(|()| writer.write_all(&payload))
            .and_then(|()| writer.flush())
            .is_err()
        {
            return;
        }
    }
}
