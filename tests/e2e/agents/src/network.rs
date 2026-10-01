//! The one way out of a confined agent: a loopback proxy that relays a tunnel to a fixed set of
//! hosts and answers everything else with a refusal.
//!
//! A sandbox profile cannot name an address as a destination, so the agent's profile denies the
//! network but this proxy's loopback port, and the agent is given the proxy in its proxy
//! variables. The proxy accepts a `CONNECT` to exactly `<host>:<port>` for a host it was given,
//! resolves the name once, refuses the tunnel unless every address the name has is a public
//! unicast one, and connects to one of those addresses, never to the name again. Anything else is
//! answered `403` and counted. It relays bytes and never reads them: what the tunnel carries,
//! down to the TLS server name it names, is outside what it can judge.

use std::io::{ErrorKind, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The longest request head the proxy reads before it answers.
const HEAD_LIMIT: usize = 8192;

/// How long the proxy waits for a request head and for a connection to its destination.
const WAIT: Duration = Duration::from_secs(10);

/// How a name is resolved: the addresses a host has.
pub type Resolver = Arc<dyn Fn(&str, u16) -> std::io::Result<Vec<IpAddr>> + Send + Sync>;

/// What a proxy relays, and how it decides.
#[derive(Clone)]
pub struct Policy {
    /// The hosts a tunnel may go to, compared without regard to case.
    pub hosts: Vec<String>,
    /// The only port a tunnel may go to.
    pub port: u16,
    /// The addresses a host name has.
    pub resolve: Resolver,
    /// Whether an address may be connected to.
    pub allow: fn(IpAddr) -> bool,
}

impl Policy {
    /// The policy for a confined agent: the system's resolver, port 443, public addresses only.
    #[must_use]
    pub fn public(hosts: &[String]) -> Self {
        Self {
            hosts: hosts.to_vec(),
            port: 443,
            resolve: Arc::new(|host, port| {
                Ok((host, port)
                    .to_socket_addrs()?
                    .map(|address| address.ip())
                    .collect())
            }),
            allow: is_public,
        }
    }
}

/// Why a request was not relayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// It was not a `CONNECT`, or its head was not one.
    NotConnect,
    /// The authority is not `<host>:<port>` for a host and the port the policy names.
    Authority,
    /// The host did not resolve.
    Unresolved,
    /// One of the host's addresses is not one a tunnel may go to.
    Address,
    /// The destination did not answer.
    Unreachable,
}

/// What a request comes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Connect to one of these addresses, every one of which the policy allows.
    Allow(Vec<SocketAddr>),
    /// Answer 403.
    Refuse(Refusal),
}

/// What the proxy has done, by count.
#[derive(Debug, Default)]
pub struct Counts {
    allowed: AtomicU64,
    refused: AtomicU64,
}

impl Counts {
    /// The tunnels opened.
    #[must_use]
    pub fn allowed(&self) -> u64 {
        self.allowed.load(Ordering::SeqCst)
    }

    /// The requests refused.
    #[must_use]
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::SeqCst)
    }
}

/// One tunnel the proxy opened: where it went, when, and how many bytes it carried each way once it
/// ended. Never what the bytes were.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tunnel {
    /// The authority the agent asked for.
    pub authority: String,
    /// The address the proxy connected to, which it chose once from the name's addresses.
    pub address: SocketAddr,
    /// When it opened, in milliseconds since the epoch.
    pub opened_ms: u64,
    /// The bytes sent to the destination and received from it; `None` while the tunnel is open.
    pub carried: Option<(u64, u64)>,
}

type Tunnels = Mutex<Vec<Tunnel>>;

/// A running proxy. It stops, and every tunnel with it, when it is dropped.
pub struct Proxy {
    port: u16,
    counts: Arc<Counts>,
    names: Arc<Mutex<Vec<String>>>,
    tunnels: Arc<Tunnels>,
    stop: Arc<AtomicBool>,
    open: Arc<Mutex<Vec<TcpStream>>>,
    accepting: Option<JoinHandle<()>>,
}

impl Proxy {
    /// Starts a proxy on a loopback port of the system's choosing.
    ///
    /// # Errors
    ///
    /// Returns why the listener could not be made.
    pub fn start(policy: Policy) -> std::io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let counts = Arc::new(Counts::default());
        let names = Arc::new(Mutex::new(Vec::new()));
        let tunnels: Arc<Tunnels> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let open = Arc::new(Mutex::new(Vec::new()));
        let policy = Arc::new(policy);
        let accepting = {
            let (counts, names, stop, open, tunnels) = (
                counts.clone(),
                names.clone(),
                stop.clone(),
                open.clone(),
                tunnels.clone(),
            );
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((client, _)) => {
                            // A connection accepted from a non-blocking listener is non-blocking on
                            // some systems; each is served by a thread of its own that waits.
                            if client.set_nonblocking(false).is_err() {
                                continue;
                            }
                            let (policy, counts, names, stop, open, tunnels) = (
                                policy.clone(),
                                counts.clone(),
                                names.clone(),
                                stop.clone(),
                                open.clone(),
                                tunnels.clone(),
                            );
                            std::thread::spawn(move || {
                                serve(client, &policy, (&counts, &names, &tunnels), &stop, &open);
                            });
                        }
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Ok(Self {
            port,
            counts,
            names,
            tunnels,
            stop,
            open,
            accepting: Some(accepting),
        })
    }

    /// The loopback port it listens on.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The address an agent's proxy variables name.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// What it has relayed and refused so far.
    #[must_use]
    pub fn counts(&self) -> &Counts {
        &self.counts
    }

    /// Every tunnel it opened, in order, for the part's private log and the counts of the record.
    #[must_use]
    pub fn tunnels(&self) -> Vec<Tunnel> {
        self.tunnels
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Waits up to `wait` for every tunnel to end, as they do once the agent's processes have: a
    /// tunnel that has not ended after that is reported as open.
    pub fn settle(&self, wait: Duration) {
        let end = std::time::Instant::now() + wait;
        while std::time::Instant::now() < end
            && self
                .tunnels
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .any(|tunnel| tunnel.carried.is_none())
        {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The authorities it refused, one entry each, for the part's private log only.
    #[must_use]
    pub fn refused_authorities(&self) -> Vec<String> {
        self.names
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for stream in self
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
        {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Some(thread) = self.accepting.take() {
            let _ = thread.join();
        }
    }
}

/// Whether `head` is a request head, and what it asks for: the authority of a `CONNECT`.
fn connect_authority(head: &str) -> Option<&str> {
    let line = head.lines().next()?;
    let mut words = line.split(' ');
    let (method, authority, version) = (words.next()?, words.next()?, words.next()?);
    (method == "CONNECT" && version.starts_with("HTTP/1.") && words.next().is_none())
        .then_some(authority)
}

/// A request line as the private log may keep it: its method and the authority it names, with no path,
/// query, user or version, so no URL a plain request carried is kept beyond its host.
fn request_target(line: &str) -> String {
    let mut words = line.split(' ');
    let method: String = words
        .next()
        .unwrap_or_default()
        .chars()
        .filter(char::is_ascii_alphabetic)
        .take(16)
        .collect();
    let target = words.next().unwrap_or_default();
    let authority = target
        .split_once("://")
        .map_or(target, |(_, rest)| rest)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    let authority: String = authority.chars().take(255).collect();
    format!("{method} {authority}")
}

/// What the policy says of a request head. The name is resolved here, once.
#[must_use]
pub fn judge(head: &str, policy: &Policy) -> Verdict {
    let Some(authority) = connect_authority(head) else {
        return Verdict::Refuse(Refusal::NotConnect);
    };
    let Some((host, port)) = authority.rsplit_once(':') else {
        return Verdict::Refuse(Refusal::Authority);
    };
    let named = policy
        .hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(host));
    if !named || port.parse::<u16>() != Ok(policy.port) || host.contains(['[', ']', '@', '/']) {
        return Verdict::Refuse(Refusal::Authority);
    }
    let Ok(addresses) = (policy.resolve)(host, policy.port) else {
        return Verdict::Refuse(Refusal::Unresolved);
    };
    if addresses.is_empty() {
        return Verdict::Refuse(Refusal::Unresolved);
    }
    if !addresses.iter().all(|address| (policy.allow)(*address)) {
        return Verdict::Refuse(Refusal::Address);
    }
    Verdict::Allow(
        addresses
            .into_iter()
            .map(|address| SocketAddr::new(address, policy.port))
            .collect(),
    )
}

fn refuse(client: &mut TcpStream, counts: &Counts, names: &Mutex<Vec<String>>, what: String) {
    counts.refused.fetch_add(1, Ordering::SeqCst);
    names
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(what);
    let _ = client
        .write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
    let _ = client.shutdown(Shutdown::Both);
}

fn serve(
    mut client: TcpStream,
    policy: &Policy,
    (counts, names, tunnels): (&Counts, &Mutex<Vec<String>>, &Tunnels),
    stop: &AtomicBool,
    open: &Mutex<Vec<TcpStream>>,
) {
    let _ = client.set_read_timeout(Some(WAIT));
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match client.read(&mut byte) {
            Ok(1) if head.len() < HEAD_LIMIT => head.push(byte[0]),
            _ => {
                refuse(
                    &mut client,
                    counts,
                    names,
                    "an unfinished request head".to_owned(),
                );
                return;
            }
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    // Only the request line's method and where it points are kept, never a header, and of a URL
    // neither its path nor its query.
    let line = request_target(head.lines().next().unwrap_or_default());
    let candidates = match judge(&head, policy) {
        Verdict::Allow(addresses) => addresses,
        Verdict::Refuse(why) => {
            refuse(&mut client, counts, names, format!("{line} ({why:?})"));
            return;
        }
    };
    let upstream = candidates.iter().find_map(|address| {
        TcpStream::connect_timeout(address, WAIT)
            .ok()
            .map(|up| (*address, up))
    });
    let Some((address, upstream)) = upstream else {
        refuse(
            &mut client,
            counts,
            names,
            format!("{line} ({:?})", Refusal::Unreachable),
        );
        return;
    };
    counts.allowed.fetch_add(1, Ordering::SeqCst);
    let index = {
        let mut tunnels = tunnels.lock().unwrap_or_else(PoisonError::into_inner);
        tunnels.push(Tunnel {
            authority: line.split(' ').nth(1).unwrap_or_default().to_owned(),
            address,
            opened_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| {
                    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
                }),
            carried: None,
        });
        tunnels.len() - 1
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    let _ = client.set_read_timeout(None);
    if let (Ok(a), Ok(b)) = (client.try_clone(), upstream.try_clone()) {
        let mut open = open.lock().unwrap_or_else(PoisonError::into_inner);
        open.push(a);
        open.push(b);
    }
    if stop.load(Ordering::SeqCst) {
        return;
    }
    let (Ok(mut client_read), Ok(mut upstream_write)) = (client.try_clone(), upstream.try_clone())
    else {
        return;
    };
    let forward = std::thread::spawn(move || {
        let sent = relay(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
        sent
    });
    let (mut upstream_read, mut client_write) = (upstream, client);
    let received = relay(&mut upstream_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    let sent = forward.join().unwrap_or(0);
    if let Some(tunnel) = tunnels
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get_mut(index)
    {
        tunnel.carried = Some((sent, received));
    }
}

/// Copies `from` to `to` until either ends or fails, and returns the bytes that were written: each
/// successful write is counted, so a failure partway through a buffer, or after some bytes went
/// through, leaves the count of those, where a plain copy would lose it.
fn relay(from: &mut impl Read, to: &mut impl Write) -> u64 {
    let mut buffer = [0_u8; 16 * 1024];
    let mut written = 0_u64;
    loop {
        let read = match from.read(&mut buffer) {
            Ok(0) | Err(_) => return written,
            Ok(read) => read,
        };
        let mut sent = 0;
        while sent < read {
            match to.write(&buffer[sent..read]) {
                Ok(0) | Err(_) => return written,
                Ok(count) => {
                    sent += count;
                    written += count as u64;
                }
            }
        }
    }
}

/// Whether a tunnel may go to `address`: a public unicast address, none of the ranges that reach a
/// machine of the local network, another protocol's translation, or nothing at all.
#[must_use]
pub fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => public_v4(address),
        IpAddr::V6(address) => public_v6(address),
    }
}

fn public_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_multicast()
        || address.is_documentation()
        || a == 0
        // 100.64.0.0/10 shared address space.
        || (a == 100 && (b & 0xc0) == 64)
        // 192.0.0.0/24 protocol assignments, 192.88.99.0/24 6to4 relays, 198.18.0.0/15 benchmarks.
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b & 0xfe) == 18)
        // 240.0.0.0/4 reserved.
        || a >= 240)
}

fn public_v6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    // Only 2000::/3 holds global unicast addresses; of it, take out what is not the network's own:
    // documentation, protocol assignments (Teredo and others), 6to4, and the ranges other
    // protocols translate to and from an IPv4 address.
    (segments[0] & 0xe000) == 0x2000
        && !(segments[0] == 0x2001 && (segments[1] & 0xfe00) == 0)
        && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        && segments[0] != 0x2002
        && !(segments[0] == 0x3fff && (segments[1] & 0xf000) == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(hosts: &[&str], port: u16, allow: fn(IpAddr) -> bool, to: Vec<IpAddr>) -> Policy {
        Policy {
            hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
            port,
            resolve: Arc::new(move |_, _| Ok(to.clone())),
            allow,
        }
    }

    fn any(_: IpAddr) -> bool {
        true
    }

    fn loopback() -> Vec<IpAddr> {
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
    }

    #[test]
    fn only_a_connect_to_a_named_host_and_port_with_public_addresses_is_allowed() {
        let public = vec![IpAddr::V4(Ipv4Addr::new(104, 18, 16, 93))];
        let named = policy(&["api.example"], 443, is_public, public.clone());
        let ok = "CONNECT api.example:443 HTTP/1.1\r\nhost: api.example:443\r\n\r\n";
        let expected = Verdict::Allow(vec![SocketAddr::new(public[0], 443)]);
        assert_eq!(judge(ok, &named), expected);
        assert_eq!(
            judge(&ok.replace("api.example", "API.Example"), &named),
            expected,
            "host names compare without regard to case"
        );
        for (head, why) in [
            (
                "GET http://api.example/ HTTP/1.1\r\n\r\n",
                Refusal::NotConnect,
            ),
            ("CONNECT api.example:443\r\n\r\n", Refusal::NotConnect),
            (
                "CONNECT api.example:443 HTTP/1.1 x\r\n\r\n",
                Refusal::NotConnect,
            ),
            (
                "CONNECT api.example:80 HTTP/1.1\r\n\r\n",
                Refusal::Authority,
            ),
            ("CONNECT api.example HTTP/1.1\r\n\r\n", Refusal::Authority),
            (
                "CONNECT other.example:443 HTTP/1.1\r\n\r\n",
                Refusal::Authority,
            ),
            ("CONNECT [::1]:443 HTTP/1.1\r\n\r\n", Refusal::Authority),
            (
                "CONNECT api.example.evil:443 HTTP/1.1\r\n\r\n",
                Refusal::Authority,
            ),
            (
                "CONNECT user@api.example:443 HTTP/1.1\r\n\r\n",
                Refusal::Authority,
            ),
        ] {
            assert_eq!(judge(head, &named), Verdict::Refuse(why), "{head:?}");
        }
    }

    #[test]
    fn a_host_with_one_address_that_is_not_public_is_refused_whole() {
        let mixed = vec![
            IpAddr::V4(Ipv4Addr::new(104, 18, 16, 93)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        ];
        let named = policy(&["api.example"], 443, is_public, mixed);
        assert_eq!(
            judge("CONNECT api.example:443 HTTP/1.1\r\n\r\n", &named),
            Verdict::Refuse(Refusal::Address)
        );
        let none = policy(&["api.example"], 443, is_public, Vec::new());
        assert_eq!(
            judge("CONNECT api.example:443 HTTP/1.1\r\n\r\n", &none),
            Verdict::Refuse(Refusal::Unresolved)
        );
    }

    #[test]
    fn a_refused_request_is_kept_as_its_method_and_host_and_no_path_query_or_user() {
        assert_eq!(
            request_target("GET http://user:pw@api.example/some/path?token=abc#x HTTP/1.1"),
            "GET api.example"
        );
        assert_eq!(
            request_target("CONNECT other.example:443 HTTP/1.1"),
            "CONNECT other.example:443"
        );
        assert_eq!(request_target("GET /relative?q=1 HTTP/1.1"), "GET ");
        assert_eq!(request_target(""), " ");
    }

    /// A reader that gives its bytes and then fails, and a writer that takes only so many.
    struct Failing(&'static [u8], bool);

    impl Read for Failing {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.0.is_empty() {
                return if self.1 {
                    Err(std::io::Error::new(ErrorKind::ConnectionReset, "reset"))
                } else {
                    Ok(0)
                };
            }
            let count = self.0.len().min(buffer.len());
            buffer[..count].copy_from_slice(&self.0[..count]);
            self.0 = &self.0[count..];
            Ok(count)
        }
    }

    /// A writer that takes a few bytes of a buffer and then fails.
    struct Partial(usize, Vec<u8>);

    impl Write for Partial {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            if self.0 == 0 {
                return Err(std::io::Error::new(ErrorKind::BrokenPipe, "closed"));
            }
            let count = self.0.min(buffer.len());
            self.0 -= count;
            self.1.extend_from_slice(&buffer[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_write_that_took_part_of_a_buffer_and_then_failed_counts_what_it_took() {
        let mut writer = Partial(3, Vec::new());
        assert_eq!(relay(&mut Failing(b"hello", false), &mut writer), 3);
        assert_eq!(writer.1, b"hel");
    }

    #[test]
    fn a_reset_after_some_bytes_went_through_still_counts_them() {
        let mut taken = Vec::new();
        assert_eq!(relay(&mut Failing(b"hello", true), &mut taken), 5);
        assert_eq!(taken, b"hello");
        assert_eq!(relay(&mut Failing(b"", true), &mut Vec::new()), 0);
        assert_eq!(relay(&mut Failing(b"abc", false), &mut Vec::new()), 3);
    }

    #[test]
    fn the_ranges_that_reach_the_local_network_or_translate_to_it_are_not_public() {
        for text in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "100.64.0.1",
            "192.0.0.8",
            "198.18.0.1",
            "240.0.0.1",
            "192.0.2.1",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "::ffff:104.18.16.93",
            "64:ff9b::7f00:1",
            "2001:db8::1",
            "2001::1",
            "2002::1",
            "3fff::1",
            "100::1",
        ] {
            let address: IpAddr = text.parse().expect("an address");
            assert!(!is_public(address), "{text}");
        }
        for text in ["104.18.16.93", "1.1.1.1", "8.8.8.8", "2606:4700::6812:105d"] {
            let address: IpAddr = text.parse().expect("an address");
            assert!(is_public(address), "{text}");
        }
    }

    #[test]
    fn a_running_proxy_relays_to_a_named_destination_and_refuses_and_counts_the_rest() {
        let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a destination");
        let port = destination.local_addr().expect("its address").port();
        let echo = std::thread::spawn(move || {
            let (mut stream, _) = destination.accept().expect("a tunnel");
            let mut buffer = [0_u8; 5];
            stream.read_exact(&mut buffer).expect("five bytes");
            stream.write_all(&buffer).expect("echoes them");
        });
        let proxy = Proxy::start(policy(&["api.example"], port, any, loopback())).expect("starts");
        let ask = |head: &str| -> String {
            let mut stream =
                TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).expect("connects");
            stream.write_all(head.as_bytes()).expect("sends");
            let mut answer = [0_u8; 64];
            let read = stream.read(&mut answer).expect("an answer");
            String::from_utf8_lossy(&answer[..read]).into_owned()
        };
        assert!(ask("GET http://api.example/ HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 403"));
        assert!(
            ask(&format!("CONNECT other.example:{port} HTTP/1.1\r\n\r\n"))
                .starts_with("HTTP/1.1 403")
        );
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).expect("connects");
        stream
            .write_all(format!("CONNECT api.example:{port} HTTP/1.1\r\n\r\n").as_bytes())
            .expect("sends");
        let mut answer = [0_u8; 39];
        stream.read_exact(&mut answer).expect("the tunnel's answer");
        assert!(answer.starts_with(b"HTTP/1.1 200"));
        stream.write_all(b"hello").expect("through the tunnel");
        let mut echoed = [0_u8; 5];
        stream.read_exact(&mut echoed).expect("its echo");
        assert_eq!(&echoed, b"hello");
        echo.join().expect("the destination ends");
        assert_eq!((proxy.counts().allowed(), proxy.counts().refused()), (1, 2));
        drop(stream);
        // The tunnel is listed with where it went, and, once it ended, how much it carried.
        let mut tunnels = proxy.tunnels();
        for _ in 0..100 {
            if tunnels
                .first()
                .is_some_and(|tunnel| tunnel.carried.is_some())
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
            tunnels = proxy.tunnels();
        }
        assert_eq!(tunnels.len(), 1);
        assert_eq!(tunnels[0].authority, format!("api.example:{port}"));
        assert_eq!(tunnels[0].address.port(), port);
        assert_eq!(tunnels[0].carried, Some((5, 5)));
        let names = proxy.refused_authorities();
        assert_eq!(names.len(), 2);
        assert!(
            names.iter().all(|name| !name.contains("host:")),
            "no header is kept"
        );
    }
}
