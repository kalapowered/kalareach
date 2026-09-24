//! A Pkarr relay running in this process.
//!
//! An endpoint publishes its signed record with `PUT <url>/<key>` and a resolver reads it back with
//! `GET <url>/<key>`, where the key is the endpoint identity in z-base-32. Both carry the signed
//! payload exactly as the endpoint produced it and the resolver verifies the signature itself, so
//! this server stores bytes and never has to read them. It keeps the latest record for each key,
//! which is what a relay does for a record that is republished.
//!
//! It answers plain HTTP on loopback from a thread of its own, so nothing about it depends on the
//! runtime the endpoints run on.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// The most a published record may weigh. A signed Pkarr packet is at most 1,104 bytes.
const MAX_RECORD: usize = 2048;

/// The records this relay holds, by endpoint identity in z-base-32.
type Records = Arc<Mutex<HashMap<String, Vec<u8>>>>;

/// A Pkarr relay on loopback.
pub struct PkarrRelay {
    /// Where an endpoint publishes to and resolves from.
    pub url: kr_transport::config::Url,
    records: Records,
    stopping: Arc<AtomicBool>,
    addr: SocketAddr,
}

impl PkarrRelay {
    /// Starts a relay on a free loopback port.
    pub fn spawn() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a Pkarr listener");
        let addr = listener.local_addr().expect("a bound address");
        let records = Records::default();
        let stopping = Arc::new(AtomicBool::new(false));
        {
            let records = Arc::clone(&records);
            let stopping = Arc::clone(&stopping);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stopping.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else {
                        continue;
                    };
                    let records = Arc::clone(&records);
                    std::thread::spawn(move || serve(stream, &records));
                }
            });
        }
        Self {
            url: format!("http://{addr}/pkarr")
                .parse()
                .expect("a Pkarr relay URL"),
            records,
            stopping,
            addr,
        }
    }

    /// Returns true once an endpoint has published a record here.
    pub fn holds(&self, endpoint: &iroh::EndpointId) -> bool {
        self.records
            .lock()
            .expect("the records")
            .contains_key(&endpoint.to_z32())
    }
}

impl Drop for PkarrRelay {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        // Wakes the accept loop so it sees the flag.
        let _ = TcpStream::connect(self.addr);
    }
}

/// Answers the requests on one connection until the client closes it.
fn serve(stream: TcpStream, records: &Mutex<HashMap<String, Vec<u8>>>) {
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
                records.lock().expect("the records").insert(key, body);
                (204, "No Content", Vec::new())
            }
            ("GET", Some(key)) => match records.lock().expect("the records").get(&key) {
                Some(record) => (200, "OK", record.clone()),
                None => (404, "Not Found", Vec::new()),
            },
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
