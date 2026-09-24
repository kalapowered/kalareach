//! Email: a message handed to a mail submission server under the owner's account.
//!
//! One conversation per attempt, in the order RFC 6409 submission takes: the server's greeting,
//! `EHLO`, `AUTH`, `MAIL FROM`, `RCPT TO`, `DATA`, the message, and the line holding one `.` that
//! ends it. It happens over TLS and nothing else. An account set to implicit TLS (port 465) starts
//! TLS with the first byte; one set to STARTTLS (port 587) says `EHLO` and `STARTTLS` in the clear,
//! and nothing more: a server that does not offer the upgrade is not sent to, and one that sends
//! anything between agreeing to it and starting it is not trusted with the rest. The server's
//! certificate is verified by the operating system's own verifier, the one the managed HTTPS
//! transport uses, and there is no way to switch that off.
//!
//! # What each answer means
//!
//! | Where | Answer | Outcome |
//! | --- | --- | --- |
//! | Before the final `.` is written | No connection, a connection that ends, a deadline | Nothing was sent |
//! | Before the final `.` is written | A 4xx reply | Nothing was sent: the server asked for later |
//! | Before the final `.` is written | A 5xx reply, no STARTTLS, a certificate that does not verify | Nothing was sent, and another attempt would meet the same answer |
//! | After the final `.` is written | A 2xx reply | Delivered |
//! | After the final `.` is written | A 5xx reply | Refused |
//! | After the final `.` is written | Anything else, silence included | Nobody knows |
//!
//! A reply's text is never written anywhere: the outcome carries the reply code and its enhanced
//! status code, because a server's own words can repeat what it was sent, and what it was sent
//! includes the account's credential.
//!
//! # What goes into a header or a command
//!
//! Everything a destination or an event supplies that ends up in a mail command or a header is
//! checked here before it is used, and none of it may carry a line break: an address is a plain
//! `local@domain` in ASCII, so a recipient, a sender or a subject can never add a header of its own
//! or a command to the conversation with the server. The body is quoted-printable, every line ends
//! in CR LF, and a line that begins with `.` is sent with a second one in front of it.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use kr_delivery::destination::ExternalDestination;
use kr_delivery::external::{ExternalMessage, ExternalOutcome};
use kr_protocol::delivery::{MailAccount, MailSecurity};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// The longest address this host sends to or from.
pub const MAX_ADDRESS_LEN: usize = 254;

/// The longest host name a submission server may have.
const MAX_HOST_LEN: usize = 253;

/// Checks one mail address: `local@domain`, ASCII, with nothing a header or a mail command could
/// read as anything but the address.
///
/// # Errors
///
/// Returns the rule the address broke.
pub fn check_address(text: &str) -> Result<(), String> {
    let refused = || {
        "a mail address is local@domain in ASCII letters, digits and the punctuation an address \
         allows, with no spaces, quotes, brackets or line breaks"
            .to_owned()
    };
    if text.len() > MAX_ADDRESS_LEN || text.bytes().filter(|byte| *byte == b'@').count() != 1 {
        return Err(refused());
    }
    let (local, domain) = text.split_once('@').ok_or_else(refused)?;
    let local_ok = !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'.' | b'!'
                        | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                )
        });
    if !local_ok || check_host_name(domain).is_err() || !domain.contains('.') {
        return Err(refused());
    }
    Ok(())
}

/// Checks a host name: dot-separated labels of ASCII letters, digits and hyphens.
fn check_host_name(text: &str) -> Result<(), String> {
    let refused =
        || "a host name is dot-separated labels of ASCII letters, digits and hyphens".to_owned();
    if text.is_empty() || text.len() > MAX_HOST_LEN {
        return Err(refused());
    }
    for label in text.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(refused());
        }
    }
    Ok(())
}

/// Checks a submission server: a host name or an IP address.
///
/// # Errors
///
/// Returns the rule the server broke.
pub fn check_server(text: &str) -> Result<(), String> {
    if text.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    check_host_name(text).map_err(|_| {
        "a mail submission server is a host name or an IP address, with no scheme and no port"
            .to_owned()
    })
}

/// Checks a mail submission account, everything but the password's value.
///
/// The user name and the password are credentials already checked for length and control
/// characters where they were read; a NUL, which the PLAIN mechanism would read as a separator, is
/// one of those.
///
/// # Errors
///
/// Returns the rule the account broke, never the credential.
pub fn check_account(account: &MailAccount) -> Result<(), String> {
    check_server(&account.server)?;
    if account.port.get() == 0 || account.port.get() > u64::from(u16::MAX) {
        return Err("a mail submission port is between 1 and 65535".to_owned());
    }
    check_address(&account.from_address)
        .map_err(|rule| format!("the address mail is sent from: {rule}"))
}

/// How long each part of a submission may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MailDeadlines {
    /// Reaching the server, TLS included.
    pub connect: Duration,
    /// Each reply before the message is sent.
    pub reply: Duration,
    /// The reply to the message itself, which a server may take a while to give.
    pub final_reply: Duration,
}

impl MailDeadlines {
    /// Ten seconds to connect, thirty for a reply, and a minute for the reply to the message.
    ///
    /// Shorter than RFC 5321's suggestions, because a pass waits for each attempt in turn and an
    /// answer that takes minutes holds every notification behind it. A deadline that runs out
    /// after the message was sent is an outcome nobody knows, never a reason to send it again.
    pub const DEFAULT: Self = Self {
        connect: Duration::from_secs(10),
        reply: Duration::from_secs(30),
        final_reply: Duration::from_secs(60),
    };
}

/// The longest reply line this host reads.
const MAX_REPLY_LINE: usize = 2048;

/// The most lines one reply may have.
const MAX_REPLY_LINES: usize = 128;

/// The longest encoded body line, the quoted-printable limit.
const MAX_ENCODED_LINE: usize = 76;

/// What this host calls itself in `EHLO`: an address literal, so no host name leaves it.
const EHLO: &[u8] = b"EHLO [127.0.0.1]";

/// The TLS every submission is made over, and the deadlines it keeps.
#[derive(Clone)]
pub struct MailSubmission {
    tls: Result<Arc<rustls::ClientConfig>, String>,
    deadlines: MailDeadlines,
}

impl std::fmt::Debug for MailSubmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MailSubmission")
            .field("verifier", &self.tls.as_ref().map(|_| "platform"))
            .field("deadlines", &self.deadlines)
            .finish()
    }
}

impl MailSubmission {
    /// Submission verified by the operating system's certificate verifier.
    ///
    /// A host with no usable verifier gets a submission that sends nothing and says why, rather
    /// than one that sends without verifying.
    #[must_use]
    pub fn verified() -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Self::with_verifier(
            rustls_platform_verifier::Verifier::new(Arc::clone(&provider)),
            provider,
        )
    }

    /// Submission verified by the operating system's certificate verifier, which also trusts one
    /// more authority: the one a test's own mail server is issued by.
    ///
    /// It is the same verifier with the same checks, and nothing in it can switch verification
    /// off. It exists only in builds made for this crate's own tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn trusting(authority: &[u8]) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Self::with_verifier(
            rustls_platform_verifier::Verifier::new_with_extra_roots(
                [rustls::pki_types::CertificateDer::from(authority.to_vec())],
                Arc::clone(&provider),
            ),
            provider,
        )
    }

    fn with_verifier(
        verifier: Result<rustls_platform_verifier::Verifier, rustls::Error>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Self {
        let tls = verifier
            .and_then(|verifier| {
                Ok(rustls::ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier))
                    .with_no_client_auth())
            })
            .map(Arc::new)
            .map_err(|error| format!("this host has no certificate verifier for mail: {error}"));
        Self {
            tls,
            deadlines: MailDeadlines::DEFAULT,
        }
    }

    /// The same submission, keeping other deadlines.
    #[must_use]
    pub const fn with_deadlines(mut self, deadlines: MailDeadlines) -> Self {
        self.deadlines = deadlines;
        self
    }

    /// Hands one message to the account's submission server for one recipient.
    ///
    /// `message` is the whole message as [`compose_mail`] builds it; the dot-stuffing and the
    /// line that ends it are added here.
    pub async fn submit(
        &self,
        account: &MailAccount,
        recipient: &str,
        message: &[u8],
    ) -> ExternalOutcome {
        match self.converse(account, recipient, message).await {
            Ok(outcome) | Err(outcome) => outcome,
        }
    }

    async fn converse(
        &self,
        account: &MailAccount,
        recipient: &str,
        message: &[u8],
    ) -> Result<ExternalOutcome, ExternalOutcome> {
        let tls = self
            .tls
            .as_ref()
            .map(Arc::clone)
            .map_err(|detail| unsendable(detail.clone()))?;
        let port = u16::try_from(account.port.get())
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| unsendable("the account's port is not one a server listens on"))?;
        let server_name = ServerName::try_from(account.server.clone())
            .map_err(|_| unsendable("the account's server is not a name TLS can verify"))?;
        let connector = tokio_rustls::TlsConnector::from(tls);
        let tcp = tokio::time::timeout(
            self.deadlines.connect,
            TcpStream::connect((account.server.as_str(), port)),
        )
        .await
        .map_err(|_| not_sent("the mail server could not be reached in time"))?
        .map_err(|_| not_sent("the mail server could not be reached"))?;

        let mut wire = match account.security {
            MailSecurity::ImplicitTls => {
                let stream = self.handshake(&connector, server_name, tcp).await?;
                let mut wire = Wire::new(stream);
                self.expect(&mut wire, None, "the server greeted this host", |code| {
                    code == 220
                })
                .await?;
                wire
            }
            MailSecurity::Starttls => {
                let mut plain = Wire::new(tcp);
                self.expect(&mut plain, None, "the server greeted this host", |code| {
                    code == 220
                })
                .await?;
                let offered = self
                    .expect(
                        &mut plain,
                        Some(EHLO),
                        "this host introduced itself",
                        |code| code == 250,
                    )
                    .await?;
                if !offered.offers("STARTTLS") {
                    // Never downgraded: the account says STARTTLS, and a server that does not offer
                    // it is not sent a credential or a message in the clear.
                    return Err(unsendable(
                        "the mail server does not offer STARTTLS, and this host sends nothing to a \
                         mail server without TLS",
                    ));
                }
                self.expect(
                    &mut plain,
                    Some(b"STARTTLS".as_slice()),
                    "this host asked for TLS",
                    |code| code == 220,
                )
                .await?;
                // Anything the server sent after agreeing and before TLS began was sent in the
                // clear, where anyone on the path could have put it. None of it is read as TLS.
                let tcp = plain.into_drained().ok_or_else(|| {
                    unsendable(
                        "the mail server sent more after agreeing to TLS and before it began, so \
                         the connection is not trusted",
                    )
                })?;
                let stream = self.handshake(&connector, server_name, tcp).await?;
                Wire::new(stream)
            }
        };

        let offered = self
            .expect(
                &mut wire,
                Some(EHLO),
                "this host introduced itself",
                |code| code == 250,
            )
            .await?;
        self.authenticate(&mut wire, &offered, account).await?;
        let from = format!("MAIL FROM:<{}>", account.from_address);
        self.expect(
            &mut wire,
            Some(from.as_bytes()),
            "the sender was named",
            |code| code == 250,
        )
        .await?;
        let to = format!("RCPT TO:<{recipient}>");
        self.expect(
            &mut wire,
            Some(to.as_bytes()),
            "the recipient was named",
            |code| code == 250 || code == 251,
        )
        .await?;
        self.expect(
            &mut wire,
            Some(b"DATA".as_slice()),
            "this host asked to send",
            |code| code == 354,
        )
        .await?;

        // The message, dot-stuffed. Nothing is sent until the line that ends it is written: a
        // failure before that leaves a message the server discards.
        let stuffed = dot_stuff(message);
        wire.send_raw(&stuffed)
            .await
            .map_err(|_| not_sent("the connection ended while the message was being sent"))?;
        // From here the server may have taken the message, whatever else happens.
        if wire.send_raw(b".\r\n").await.is_err() {
            return Err(unknown(
                "the connection ended as the message was finished, so whether the server took it \
                 is not known",
            ));
        }
        let answer = tokio::time::timeout(self.deadlines.final_reply, wire.reply())
            .await
            .map_err(|_| {
                unknown("the mail server did not answer in time after the message was sent")
            })?
            .map_err(|_| {
                unknown(
                    "the connection ended before the mail server said whether it took the message",
                )
            })?;
        let outcome = match answer.code {
            200..=299 => ExternalOutcome::Delivered,
            500..=599 => ExternalOutcome::Refused {
                detail: format!("the mail server refused the message ({})", answer.status()),
            },
            _ => unknown(format!(
                "the mail server answered {} and did not take the message, and whether a copy \
                 reached anyone is not known",
                answer.status()
            )),
        };
        // A polite end. The outcome is already decided and nothing here can change it.
        let _ = tokio::time::timeout(self.deadlines.reply, async {
            if wire.send(b"QUIT").await.is_ok() {
                let _ = wire.reply().await;
            }
        })
        .await;
        Ok(outcome)
    }

    /// Starts TLS on a connection and verifies the server's certificate for `server_name`.
    async fn handshake(
        &self,
        connector: &tokio_rustls::TlsConnector,
        server_name: ServerName<'static>,
        tcp: TcpStream,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ExternalOutcome> {
        match tokio::time::timeout(self.deadlines.connect, connector.connect(server_name, tcp))
            .await
        {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(error))
                if error
                    .get_ref()
                    .is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some()) =>
            {
                Err(unsendable(
                    "TLS with the mail server could not be established: its certificate did not \
                     verify for its name, or it does not speak TLS as the account says",
                ))
            }
            Ok(Err(_)) => Err(not_sent(
                "the connection ended while TLS was being established",
            )),
            Err(_) => Err(not_sent(
                "TLS with the mail server was not established in time",
            )),
        }
    }

    /// Authenticates with the account's credential, by PLAIN where the server offers it and by
    /// LOGIN otherwise. The credential travels only inside TLS, and no error names it.
    async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        wire: &mut Wire<S>,
        offered: &Reply,
        account: &MailAccount,
    ) -> Result<(), ExternalOutcome> {
        let engine = base64::engine::general_purpose::STANDARD;
        let mechanisms = offered.mechanisms();
        if mechanisms.iter().any(|mechanism| mechanism == "PLAIN") {
            let mut token = Vec::with_capacity(
                2 + account.username.expose().len() + account.password.expose().len(),
            );
            token.push(0);
            token.extend_from_slice(account.username.expose().as_bytes());
            token.push(0);
            token.extend_from_slice(account.password.expose().as_bytes());
            let command = kr_crypto::secret::SecretVec::new(
                format!("AUTH PLAIN {}", engine.encode(&token)).into_bytes(),
            );
            drop(kr_crypto::secret::SecretVec::new(token));
            self.expect(
                wire,
                Some(command.expose()),
                "the account's credential was offered",
                |code| code == 235,
            )
            .await?;
            return Ok(());
        }
        if mechanisms.iter().any(|mechanism| mechanism == "LOGIN") {
            self.expect(
                wire,
                Some(b"AUTH LOGIN".as_slice()),
                "this host asked to authenticate",
                |code| code == 334,
            )
            .await?;
            let name = kr_crypto::secret::SecretVec::new(
                engine.encode(account.username.expose()).into_bytes(),
            );
            self.expect(
                wire,
                Some(name.expose()),
                "the account's name was offered",
                |code| code == 334,
            )
            .await?;
            let password = kr_crypto::secret::SecretVec::new(
                engine.encode(account.password.expose()).into_bytes(),
            );
            self.expect(
                wire,
                Some(password.expose()),
                "the account's credential was offered",
                |code| code == 235,
            )
            .await?;
            return Ok(());
        }
        Err(unsendable(
            "the mail server offers neither AUTH PLAIN nor AUTH LOGIN, so the account cannot sign in",
        ))
    }

    /// Sends one command, when there is one, and reads the reply, reading everything but an
    /// accepted reply as the outcome it is before the message is sent.
    async fn expect<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        wire: &mut Wire<S>,
        command: Option<&[u8]>,
        what: &str,
        accepted: impl Fn(u16) -> bool,
    ) -> Result<Reply, ExternalOutcome> {
        if let Some(command) = command {
            wire.send(command)
                .await
                .map_err(|_| not_sent(format!("the connection ended before {what}")))?;
        }
        let reply = tokio::time::timeout(self.deadlines.reply, wire.reply())
            .await
            .map_err(|_| {
                not_sent(format!(
                    "the mail server did not answer in time when {what}"
                ))
            })?
            .map_err(|_| not_sent(format!("the connection ended when {what}")))?;
        if accepted(reply.code) {
            return Ok(reply);
        }
        Err(match reply.code {
            400..=499 => not_sent(format!(
                "the mail server asked for later when {what} ({})",
                reply.status()
            )),
            500..=599 => unsendable(format!(
                "the mail server refused this when {what} ({})",
                reply.status()
            )),
            _ => unsendable(format!(
                "the mail server answered {} when {what}",
                reply.status()
            )),
        })
    }
}

fn not_sent(detail: impl Into<String>) -> ExternalOutcome {
    ExternalOutcome::NotDispatched {
        detail: detail.into(),
    }
}

fn unsendable(detail: impl Into<String>) -> ExternalOutcome {
    ExternalOutcome::Unsendable {
        detail: detail.into(),
    }
}

fn unknown(detail: impl Into<String>) -> ExternalOutcome {
    ExternalOutcome::Unknown {
        detail: detail.into(),
    }
}

/// One reply: its code, its enhanced status code when it has one, and the words of each line.
///
/// The words are read for what an `EHLO` offers and are never written anywhere.
#[derive(Debug)]
struct Reply {
    code: u16,
    enhanced: Option<String>,
    lines: Vec<String>,
}

impl Reply {
    /// The code and the enhanced status code, which is all of a reply this host repeats.
    fn status(&self) -> String {
        match &self.enhanced {
            Some(enhanced) => format!("{} {enhanced}", self.code),
            None => self.code.to_string(),
        }
    }

    /// Whether an `EHLO` reply offers an extension.
    fn offers(&self, keyword: &str) -> bool {
        self.lines.iter().skip(1).any(|line| {
            line.split_ascii_whitespace()
                .next()
                .is_some_and(|word| word.eq_ignore_ascii_case(keyword))
        })
    }

    /// The authentication mechanisms an `EHLO` reply offers, upper-cased.
    fn mechanisms(&self) -> Vec<String> {
        self.lines
            .iter()
            .skip(1)
            .filter_map(|line| {
                let mut words = line.split([' ', '=']);
                let first = words.next()?;
                first
                    .eq_ignore_ascii_case("AUTH")
                    .then(|| words.map(str::to_ascii_uppercase).collect::<Vec<_>>())
            })
            .flatten()
            .collect()
    }
}

/// A connection to a mail server, with what it has read and not yet used.
struct Wire<S> {
    stream: S,
    buffer: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Wire<S> {
    const fn new(stream: S) -> Self {
        Self {
            stream,
            buffer: Vec::new(),
        }
    }

    /// The connection, when nothing it sent is waiting to be read.
    fn into_drained(self) -> Option<S> {
        self.buffer.is_empty().then_some(self.stream)
    }

    /// Writes one command and the CR LF that ends it.
    async fn send(&mut self, command: &[u8]) -> std::io::Result<()> {
        let mut line = Vec::with_capacity(command.len() + 2);
        line.extend_from_slice(command);
        line.extend_from_slice(b"\r\n");
        let written = self.send_raw(&line).await;
        // The line may hold a credential; it is cleared rather than left for the allocator.
        drop(kr_crypto::secret::SecretVec::new(line));
        written
    }

    async fn send_raw(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await
    }

    /// Reads one line, without its line ending.
    async fn line(&mut self) -> std::io::Result<Vec<u8>> {
        loop {
            if let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let mut line: Vec<u8> = self.buffer.drain(..=end).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(line);
            }
            if self.buffer.len() > MAX_REPLY_LINE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "a reply line is longer than this host reads",
                ));
            }
            let mut chunk = [0_u8; 1024];
            let read = self.stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    /// Reads one reply, however many lines it has.
    async fn reply(&mut self) -> std::io::Result<Reply> {
        let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidData, "not a mail reply");
        let mut code = None;
        let mut lines = Vec::new();
        loop {
            let line = self.line().await?;
            if line.len() < 3 || !line[..3].iter().all(u8::is_ascii_digit) {
                return Err(invalid());
            }
            let this: u16 = std::str::from_utf8(&line[..3])
                .ok()
                .and_then(|digits| digits.parse().ok())
                .ok_or_else(invalid)?;
            if code.is_some_and(|code| code != this) || !(100..600).contains(&this) {
                return Err(invalid());
            }
            code = Some(this);
            let last = match line.get(3) {
                None | Some(b' ') => true,
                Some(b'-') => false,
                Some(_) => return Err(invalid()),
            };
            lines.push(String::from_utf8_lossy(line.get(4..).unwrap_or_default()).into_owned());
            if last {
                break;
            }
            if lines.len() >= MAX_REPLY_LINES {
                return Err(invalid());
            }
        }
        let enhanced = lines.first().and_then(|first| {
            let word = first.split_ascii_whitespace().next()?;
            let parts: Vec<&str> = word.split('.').collect();
            (parts.len() == 3
                && matches!(parts[0], "2" | "4" | "5")
                && parts[1..].iter().all(|part| {
                    (1..=3).contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_digit())
                }))
            .then(|| word.to_owned())
        });
        Ok(Reply {
            code: code.ok_or_else(invalid)?,
            enhanced,
            lines,
        })
    }
}

/// Sends every line of a message that begins with `.` with a second `.` in front of it, so no line
/// of the message can end it early, and ends it in CR LF so the line that ends it stands alone.
#[must_use]
pub fn dot_stuff(message: &[u8]) -> Vec<u8> {
    let mut stuffed = Vec::with_capacity(message.len() + 16);
    let mut line_start = true;
    for &byte in message {
        if line_start && byte == b'.' {
            stuffed.push(b'.');
        }
        stuffed.push(byte);
        line_start = byte == b'\n';
    }
    if !stuffed.ends_with(b"\r\n") {
        stuffed.extend_from_slice(b"\r\n");
    }
    stuffed
}

/// Encodes text as quoted-printable, with CR LF line endings and no line longer than 76 bytes.
#[must_use]
pub fn quoted_printable(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len() + text.len() / 4);
    for (index, line) in text.split('\n').enumerate() {
        if index > 0 {
            encoded.push_str("\r\n");
        }
        let line = line.strip_suffix('\r').unwrap_or(line);
        let bytes = line.as_bytes();
        let mut width = 0;
        for (position, &byte) in bytes.iter().enumerate() {
            let last = position + 1 == bytes.len();
            let literal = match byte {
                b' ' | b'\t' => !last,
                b'=' => false,
                33..=126 => true,
                _ => false,
            };
            let piece_len = if literal { 1 } else { 3 };
            // Room for the piece and, unless it ends the line, a soft break after it.
            let room = if last {
                MAX_ENCODED_LINE
            } else {
                MAX_ENCODED_LINE - 1
            };
            if width + piece_len > room {
                encoded.push_str("=\r\n");
                width = 0;
            }
            if literal {
                encoded.push(char::from(byte));
            } else {
                encoded.push_str(&format!("={byte:02X}"));
            }
            width += piece_len;
        }
    }
    encoded
}

/// The date a message was sent, in the form a mail header writes it.
fn mail_date(now_ms: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let seconds = now_ms / 1000;
    let days = seconds / 86_400;
    let of_day = seconds % 86_400;
    // Days since 1970-01-01 to a civil date: the algorithm Howard Hinnant published.
    let shifted = i64::try_from(days).unwrap_or(i64::MAX / 2) + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {day:02} {} {year} {:02}:{:02}:{:02} +0000",
        DAYS[usize::try_from(days % 7).unwrap_or(0)],
        MONTHS[usize::try_from(month - 1).unwrap_or(0)],
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60
    )
}

/// One header value, refused when it could end its header and start another.
fn header_value(value: &str) -> Result<&str, String> {
    if value.chars().any(char::is_control) {
        return Err("a mail header carries no line break and no control character".to_owned());
    }
    Ok(value)
}

/// Encodes a subject as it may appear in a header: as it is when it is printable ASCII, and as one
/// RFC 2047 encoded word otherwise.
fn subject_value(subject: &str) -> Result<String, String> {
    header_value(subject)?;
    if subject.bytes().all(|byte| (32..127).contains(&byte)) {
        return Ok(subject.to_owned());
    }
    Ok(format!(
        "=?UTF-8?B?{}?=",
        base64::engine::general_purpose::STANDARD.encode(subject)
    ))
}

/// Builds the message: its headers and its body, every line ending in CR LF.
///
/// Every header value is checked before it is written, so nothing a destination or an event
/// supplied can end a header and begin another.
///
/// # Errors
///
/// Returns why a header value was refused.
pub fn compose_mail(
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
    now_ms: u64,
    message_id: &str,
) -> Result<Vec<u8>, String> {
    check_address(from).map_err(|rule| format!("the sender: {rule}"))?;
    check_address(to).map_err(|rule| format!("the recipient: {rule}"))?;
    if message_id.is_empty() || !message_id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err("a message identifier is letters and digits".to_owned());
    }
    let domain = from
        .rsplit_once('@')
        .map_or("localhost", |(_, domain)| domain);
    let headers = [
        format!("From: <{}>", header_value(from)?),
        format!("To: <{}>", header_value(to)?),
        format!("Subject: {}", subject_value(subject)?),
        format!("Date: {}", mail_date(now_ms)),
        format!("Message-ID: <{message_id}@{domain}>"),
        "MIME-Version: 1.0".to_owned(),
        "Content-Type: text/plain; charset=utf-8".to_owned(),
        "Content-Transfer-Encoding: quoted-printable".to_owned(),
        // Section 3 of RFC 3834: a message a program sent, which nothing should answer
        // automatically.
        "Auto-Submitted: auto-generated".to_owned(),
    ];
    let mut message = headers.join("\r\n");
    message.push_str("\r\n\r\n");
    message.push_str(&quoted_printable(body));
    message.push_str("\r\n");
    Ok(message.into_bytes())
}

/// The email adapter: one submission per attempt, under the destination's account.
#[derive(Clone, Debug)]
pub struct MailSender {
    submission: Arc<MailSubmission>,
    runtime: tokio::runtime::Handle,
}

impl MailSender {
    /// Builds the adapter over one submission, driven by the daemon's own reactor.
    #[must_use]
    pub fn new(submission: MailSubmission, runtime: tokio::runtime::Handle) -> Self {
        Self {
            submission: Arc::new(submission),
            runtime,
        }
    }

    /// Sends one message to the destination's recipient under the account.
    pub fn send(
        &self,
        destination: &ExternalDestination,
        account: &MailAccount,
        message: &ExternalMessage,
    ) -> ExternalOutcome {
        if let Err(rule) = check_address(&destination.endpoint) {
            return unsendable(format!("the recipient: {rule}"));
        }
        if let Err(rule) = check_account(account) {
            return unsendable(format!("the account: {rule}"));
        }
        let identifier =
            kr_ipc::new_uuid()
                .as_bytes()
                .iter()
                .fold(String::new(), |mut text, byte| {
                    use std::fmt::Write as _;
                    let _ = write!(text, "{byte:02x}");
                    text
                });
        let now_ms = kr_ipc::now_ms().get();
        let composed = match compose_mail(
            &account.from_address,
            &destination.endpoint,
            message.alert.generic_text(),
            &message.body,
            now_ms,
            &identifier,
        ) {
            Ok(composed) => composed,
            Err(rule) => return unsendable(rule),
        };
        self.runtime.block_on(
            self.submission
                .submit(account, &destination.endpoint, &composed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::delivery::{MailSecurity, SecretText};
    use kr_protocol::scalars::U64;

    #[test]
    fn an_address_is_plain_and_can_add_nothing_to_a_header_or_a_command() {
        for accepted in [
            "person@example.com",
            "first.last+alerts@mail.example.co.uk",
            "o'brien@example.org",
        ] {
            assert!(check_address(accepted).is_ok(), "{accepted}");
        }
        for refused in [
            "person@example.com\r\nBcc: someone@example.net",
            "person@example.com>\r\nRCPT TO:<someone@example.net",
            "Person <person@example.com>",
            "person@example.com, someone@example.net",
            "\"quoted\"@example.com",
            "person@@example.com",
            "person@localhost",
            ".person@example.com",
            "person@-example.com",
            "pérson@example.com",
            "",
        ] {
            assert!(check_address(refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn a_server_is_a_host_or_an_address_and_nothing_else() {
        for accepted in ["smtp.example.com", "localhost", "127.0.0.1", "::1"] {
            assert!(check_server(accepted).is_ok(), "{accepted}");
        }
        for refused in [
            "smtps://smtp.example.com",
            "smtp.example.com:465",
            "smtp example com",
            "",
        ] {
            assert!(check_server(refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn a_line_that_begins_with_a_dot_is_sent_with_a_second_one() {
        assert_eq!(
            dot_stuff(b"first\r\n.second\r\n..third\r\nfourth.\r\n"),
            b"first\r\n..second\r\n...third\r\nfourth.\r\n".to_vec()
        );
        assert_eq!(
            dot_stuff(b".\r\n"),
            b"..\r\n".to_vec(),
            "a lone dot is stuffed"
        );
        assert_eq!(
            dot_stuff(b"no final line ending"),
            b"no final line ending\r\n".to_vec(),
            "the line that ends the message always stands alone"
        );
    }

    #[test]
    fn a_quoted_printable_body_has_short_crlf_lines_and_reads_back() {
        let text = format!(
            "caf\u{e9} = \u{2615}\n{}\ntrailing space \n.dot",
            "x".repeat(200)
        );
        let encoded = quoted_printable(&text);
        assert!(encoded.contains("caf=C3=A9 =3D =E2=98=95"), "{encoded}");
        assert!(encoded.contains("trailing space=20"), "{encoded}");
        for line in encoded.split("\r\n") {
            assert!(line.len() <= MAX_ENCODED_LINE, "{} bytes", line.len());
        }
        assert!(!encoded.replace("\r\n", "").contains('\n'));
        assert!(!encoded.replace("\r\n", "").contains('\r'));
        assert!(encoded.bytes().all(|byte| byte.is_ascii()));
    }

    #[test]
    fn no_header_can_be_ended_early_by_what_it_carries() {
        let message = compose_mail(
            "alerts@example.com",
            "person@example.com",
            "A KalaReach session is waiting for an approval.",
            "body",
            1_790_000_000_000,
            "abc123",
        )
        .expect("a message");
        let text = String::from_utf8(message).expect("ASCII");
        assert!(text.contains("\r\nSubject: A KalaReach session is waiting for an approval.\r\n"));
        for (from, to, subject, id) in [
            (
                "alerts@example.com\r\nBcc: x@example.net",
                "person@example.com",
                "s",
                "a1",
            ),
            (
                "alerts@example.com",
                "person@example.com\nBcc: x@example.net",
                "s",
                "a1",
            ),
            (
                "alerts@example.com",
                "person@example.com",
                "s\r\nBcc: x@example.net",
                "a1",
            ),
            (
                "alerts@example.com",
                "person@example.com",
                "s",
                "a1>\r\nBcc",
            ),
        ] {
            assert!(
                compose_mail(from, to, subject, "body", 1, id).is_err(),
                "{from:?} {to:?} {subject:?} {id:?}"
            );
        }
        let encoded = compose_mail(
            "alerts@example.com",
            "person@example.com",
            "caf\u{e9}",
            "body",
            1,
            "a1",
        )
        .expect("a message");
        assert!(
            String::from_utf8(encoded)
                .expect("ASCII")
                .contains("Subject: =?UTF-8?B?")
        );
    }

    #[test]
    fn a_date_is_written_the_way_a_mail_header_writes_it() {
        assert_eq!(mail_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(
            mail_date(1_790_251_140_000),
            "Thu, 24 Sep 2026 11:59:00 +0000"
        );
        assert_eq!(
            mail_date(951_782_400_000),
            "Tue, 29 Feb 2000 00:00:00 +0000"
        );
    }

    #[test]
    fn an_account_is_refused_without_repeating_its_credential() {
        let account = MailAccount {
            server: "smtp.example.com".to_owned(),
            port: U64::new(0),
            security: MailSecurity::ImplicitTls,
            username: SecretText::new("person@example.com").expect("a name"),
            password: SecretText::new("correct horse").expect("a password"),
            from_address: "person@example.com".to_owned(),
        };
        let refusal = check_account(&account).expect_err("port zero");
        assert!(!refusal.contains("correct horse"));
        assert!(
            check_account(&MailAccount {
                port: U64::new(465),
                ..account
            })
            .is_ok()
        );
    }
}
