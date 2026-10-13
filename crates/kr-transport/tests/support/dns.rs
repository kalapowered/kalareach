//! A name server running in this process.
//!
//! A UDP socket on loopback that answers every question with "no such name" and keeps each
//! question it was asked, so a test can tell what an endpoint looked up and that it looked
//! nowhere else. An endpoint is pointed at it with `bind_listener_asking` or `bind_dialer_asking`.
//!
//! It answers from a thread of its own, so nothing about it depends on the runtime the endpoints
//! run on, and it stops and joins that thread when it is dropped.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// The question type for a `TXT` record, which is what an endpoint's record is looked up as.
pub const TXT: u16 = 16;

/// One question the server was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    /// The name asked about, in lower case and with no final dot.
    pub name: String,
    /// The type of record asked for.
    pub kind: u16,
}

/// A name server on loopback.
pub struct NameServer {
    /// Where it listens.
    pub address: SocketAddr,
    asked: Arc<Mutex<Vec<Question>>>,
    stopping: Arc<AtomicBool>,
    serving: Option<JoinHandle<()>>,
}

impl NameServer {
    /// Starts a server on a free loopback port.
    pub fn spawn() -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a name server socket");
        // A wait that ends, so the thread looks at the flag that stops it whatever else happens to
        // the datagram that wakes it. It decides nothing: a question is answered when it arrives.
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(250)))
            .expect("a read timeout");
        let address = socket.local_addr().expect("a bound address");
        let asked = Arc::new(Mutex::new(Vec::new()));
        let stopping = Arc::new(AtomicBool::new(false));
        let serving = {
            let asked = Arc::clone(&asked);
            let stopping = Arc::clone(&stopping);
            std::thread::spawn(move || {
                let mut packet = [0_u8; 1232];
                loop {
                    let received = socket.recv_from(&mut packet);
                    if stopping.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok((length, from)) = received else {
                        continue;
                    };
                    let Some((question, end)) = parse(&packet[..length]) else {
                        continue;
                    };
                    asked.lock().expect("the questions").push(question);
                    let _ = socket.send_to(&no_such_name(&packet[..end]), from);
                }
            })
        };
        Self {
            address,
            asked,
            stopping,
            serving: Some(serving),
        }
    }

    /// Every question asked so far, in the order asked.
    pub fn asked(&self) -> Vec<Question> {
        self.asked.lock().expect("the questions").clone()
    }
}

impl Drop for NameServer {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        // Wakes the thread so it sees the flag, then waits for it.
        if let Ok(waking) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) {
            let _ = waking.send_to(&[0], self.address);
        }
        if let Some(serving) = self.serving.take() {
            let _ = serving.join();
        }
    }
}

/// Reads the one question of a query, and where its bytes end.
fn parse(packet: &[u8]) -> Option<(Question, usize)> {
    // A header is twelve bytes and a query asks one question.
    if packet.len() < 12 || u16::from_be_bytes([packet[4], packet[5]]) != 1 {
        return None;
    }
    let mut at = 12;
    let mut labels = Vec::new();
    loop {
        let length = usize::from(*packet.get(at)?);
        at += 1;
        if length == 0 {
            break;
        }
        // A question's name is written out whole: a pointer in it is not a query.
        if length & 0xC0 != 0 {
            return None;
        }
        let label = packet.get(at..at + length)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        at += length;
    }
    let kind = u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?]);
    let end = at + 4;
    (packet.len() >= end).then(|| {
        (
            Question {
                name: labels.join("."),
                kind,
            },
            end,
        )
    })
}

/// The answer "no such name" to a query whose header and question are `query`.
fn no_such_name(query: &[u8]) -> Vec<u8> {
    let mut answer = query.to_vec();
    // A response that keeps the query's identifier, opcode and recursion request, offers recursion,
    // and says the name does not exist. The question follows as it was asked, and nothing else.
    answer[2] = 0x80 | (query[2] & 0x79);
    answer[3] = 0x83;
    answer[6..12].fill(0);
    answer
}
