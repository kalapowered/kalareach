//! The loopback address a desktop sign-in's answer comes back to.
//!
//! The registered desktop redirect is `http://127.0.0.1:8765/oauth/callback`, so the listener binds
//! that one address, IPv4 loopback only. On Windows the socket takes `SO_EXCLUSIVEADDRUSE` before
//! it binds: Windows otherwise lets another socket that asks for address reuse take over an
//! address another program is actively listening on. Elsewhere an active listener cannot be shared
//! this way. A process that wins the port first sees at most a code bound to a verifier it does
//! not have, so it can stop a sign-in and cannot complete one.

use std::net::{SocketAddr, TcpListener};

/// Binds `address` for listening, so that no other process can share it while it listens.
///
/// # Errors
///
/// Returns the platform's error, which is `AddrInUse` when another program holds the address.
pub fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
    #[cfg(windows)]
    {
        windows::bind(address)
    }
    #[cfg(not(windows))]
    {
        TcpListener::bind(address)
    }
}

#[cfg(windows)]
mod windows {
    use std::net::{SocketAddr, TcpListener};

    use socket2::{Domain, Protocol, Socket, Type};

    pub(super) fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
        let socket = Socket::new(
            Domain::for_address(address),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        exclusive(&socket)?;
        socket.bind(&address.into())?;
        socket.listen(8)?;
        Ok(socket.into())
    }

    /// Sets `SO_EXCLUSIVEADDRUSE`, which no safe wrapper offers.
    #[allow(
        unsafe_code,
        reason = "setting a socket option is a call into Winsock with a raw pointer to the value"
    )]
    fn exclusive(socket: &Socket) -> std::io::Result<()> {
        use std::os::windows::io::AsRawSocket as _;
        use windows_sys::Win32::Networking::WinSock::{
            SO_EXCLUSIVEADDRUSE, SOCKET_ERROR, SOL_SOCKET, setsockopt,
        };

        let enabled: i32 = 1;
        // SAFETY: the handle is an open socket for the whole call, and the value is a live `i32`
        // whose length is the length passed.
        let result = unsafe {
            setsockopt(
                socket.as_raw_socket() as usize,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&raw const enabled).cast::<u8>(),
                4,
            )
        };
        if result == SOCKET_ERROR {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bound_address_is_not_bound_twice() {
        let first = bind("127.0.0.1:0".parse().expect("an address")).expect("a listener");
        let taken = first.local_addr().expect("an address");
        let second = bind(taken).expect_err("the address is held");
        assert_eq!(second.kind(), std::io::ErrorKind::AddrInUse);
    }
}
