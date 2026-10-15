//! Measures what a loopback connection whose peer reads nothing takes before a write stops being
//! taken, for the buffer sizes a pair can be given before it connects.

use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

async fn pair(size: Option<u32>) -> (TcpStream, TcpStream, String) {
    let set = |socket: &TcpSocket| {
        if let Some(size) = size {
            let a = socket.set_send_buffer_size(size);
            let b = socket.set_recv_buffer_size(size);
            format!("set send {a:?} recv {b:?}")
        } else {
            "default".to_owned()
        }
    };
    let listening = TcpSocket::new_v4().expect("a socket");
    let on_listener = set(&listening);
    listening
        .bind((std::net::Ipv4Addr::LOCALHOST, 0).into())
        .expect("binds");
    let listener: TcpListener = listening.listen(1).expect("listens");
    let address = listener.local_addr().expect("an address");
    let client = TcpSocket::new_v4().expect("a socket");
    let on_client = set(&client);
    let read_back = format!(
        "client before connect: send {:?} recv {:?}",
        client.send_buffer_size(),
        client.recv_buffer_size()
    );
    let (here, there) = tokio::join!(client.connect(address), listener.accept());
    let here = here.expect("connects");
    let there = there.expect("accepts").0;
    here.set_nodelay(true).expect("nodelay");
    (
        here,
        there,
        format!("listener {on_listener}; client {on_client}; {read_back}"),
    )
}

/// Writes `chunk` bytes at a time until the system stops taking bytes for a second, or ten
/// seconds have passed, and says how many it took, and how many the first write took.
async fn absorbed(writer: &TcpStream, chunk: usize) -> (usize, usize, bool) {
    let data = vec![b'x'; chunk];
    let started = Instant::now();
    let mut total = 0;
    let mut first = None;
    loop {
        if started.elapsed() > Duration::from_secs(10) {
            return (first.unwrap_or(0), total, false);
        }
        match writer.try_write(&data) {
            Ok(n) => {
                first.get_or_insert(n);
                total += n;
                if total > 32 * 1024 * 1024 {
                    return (first.unwrap_or(0), total, false);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                first.get_or_insert(0);
                match tokio::time::timeout(Duration::from_secs(1), writer.writable()).await {
                    Ok(Ok(())) => {}
                    _ => return (first.unwrap_or(0), total, true),
                }
            }
            Err(error) => panic!("a write failed: {error}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn what_a_peer_that_reads_nothing_takes() {
    for size in [None, Some(4096), Some(65536), Some(1)] {
        for chunk in [16 * 1024, 900_000] {
            let Ok((here, there, how)) =
                tokio::time::timeout(Duration::from_secs(10), pair(size)).await
            else {
                println!("PROBE size {size:?} write {chunk}: the pair did not connect in ten seconds");
                continue;
            };
            let (first, total, stopped) = absorbed(&here, chunk).await;
            println!(
                "PROBE size {size:?} write {chunk}: first write took {first}, in all {total} bytes, stopped: {stopped} ({how})"
            );
            drop(there);
        }
    }
}
