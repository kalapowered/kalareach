//! Measures what a loopback connection whose peer reads nothing takes before a write stops being
//! taken, for the buffer sizes a pair can be given before it connects.

use std::time::Duration;
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

/// Writes 16 KiB at a time until the system stops taking bytes and nothing more is taken for a
/// while, and says how many it took.
async fn absorbed(writer: &TcpStream) -> usize {
    let chunk = vec![b'x'; 16 * 1024];
    let mut total = 0;
    loop {
        match writer.try_write(&chunk) {
            Ok(n) => total += n,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                // Writable again within a few seconds means the system took more.
                match tokio::time::timeout(Duration::from_secs(3), writer.writable()).await {
                    Ok(Ok(())) => {}
                    _ => return total,
                }
            }
            Err(error) => panic!("a write failed: {error}"),
        }
        if total > 64 * 1024 * 1024 {
            return total;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn what_a_peer_that_reads_nothing_takes() {
    for size in [None, Some(0), Some(1), Some(4096), Some(65536), Some(262_144)] {
        let (here, there, how) = pair(size).await;
        let took = absorbed(&here).await;
        println!("PROBE size {size:?}: {took} bytes absorbed ({how})");
        drop(there);
    }
}
