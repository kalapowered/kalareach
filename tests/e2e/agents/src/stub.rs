//! A stand-in for a vendor's model service, on this machine's loopback, that shows which tools an
//! agent would offer its model without calling one.
//!
//! An agent pointed at the stub sends it the request that would start a turn. The stub keeps only
//! the kind and name of each tool that request offers, answers it with an error so the agent stops
//! there, and answers anything else with "not found". The request's instructions and every header,
//! an authorisation among them, are read only as far as the protocol needs and never kept.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// The most of a request body the stub reads.
const BODY_LIMIT: usize = 64 << 20;

/// What the stub found in the requests it was sent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Found {
    /// The tools of the first request that offered any, one line each: its kind and name.
    tools: Option<Vec<String>>,
    /// Why a request could not be read, where one could not.
    problems: Vec<String>,
}

/// A stub listening on loopback until it is finished.
pub struct RequestStub {
    address: String,
    stop: Arc<AtomicBool>,
    found: Arc<Mutex<Found>>,
    serving: Option<JoinHandle<()>>,
}

impl RequestStub {
    /// Starts the stub on a loopback port of its own.
    ///
    /// # Errors
    ///
    /// Returns why no port could be listened on.
    pub fn start() -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|error| format!("the stub's port: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("the stub's port: {error}"))?;
        let address = format!(
            "http://{}",
            listener
                .local_addr()
                .map_err(|error| format!("the stub's port: {error}"))?
        );
        let stop = Arc::new(AtomicBool::new(false));
        let found = Arc::new(Mutex::new(Found::default()));
        let serving = {
            let stop = Arc::clone(&stop);
            let found = Arc::clone(&found);
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((connection, _)) => answer(connection, &found),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Err(error) => {
                            if let Ok(mut found) = found.lock() {
                                found.problems.push(format!("the stub's port: {error}"));
                            }
                            std::thread::sleep(Duration::from_millis(20));
                        }
                    }
                }
            })
        };
        Ok(Self {
            address,
            stop,
            found,
            serving: Some(serving),
        })
    }

    /// Where the stub listens, as `http://127.0.0.1:<port>`.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Stops the stub and returns the tools the first request that offered any offered, one line
    /// each.
    ///
    /// # Errors
    ///
    /// Returns why nothing was found: no such request arrived, or one could not be read.
    pub fn finish(mut self) -> Result<Vec<String>, String> {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(serving) = self.serving.take() {
            let _ = serving.join();
        }
        let found = self
            .found
            .lock()
            .map_err(|_| "the stub's record is poisoned".to_owned())?
            .clone();
        found.tools.ok_or_else(|| {
            if found.problems.is_empty() {
                "no request offering tools reached the stub".to_owned()
            } else {
                format!(
                    "no request offering tools reached the stub: {}",
                    found.problems.join("; ")
                )
            }
        })
    }
}

impl Drop for RequestStub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(serving) = self.serving.take() {
            let _ = serving.join();
        }
    }
}

/// Reads one request from `connection`, keeps what it offers, and answers it.
fn answer(connection: TcpStream, found: &Mutex<Found>) {
    let _ = connection.set_nonblocking(false);
    let _ = connection.set_read_timeout(Some(Duration::from_secs(10)));
    let mut writer = match connection.try_clone() {
        Ok(writer) => writer,
        Err(_) => return,
    };
    let mut reader = BufReader::new(connection);
    let (status, reply) = match read_request(&mut reader) {
        Ok(Request { method, body }) if method == "POST" => match tools_of(&body) {
            Some(tools) => {
                if let Ok(mut found) = found.lock() {
                    found.tools.get_or_insert(tools);
                }
                (
                    "400 Bad Request",
                    r#"{"error":{"message":"this is a stub that answers no request","type":"invalid_request_error","code":"stub"}}"#,
                )
            }
            None => ("404 Not Found", r#"{"error":{"message":"not found"}}"#),
        },
        Ok(_) => ("404 Not Found", r#"{"error":{"message":"not found"}}"#),
        Err(why) => {
            if let Ok(mut found) = found.lock() {
                found.problems.push(why);
            }
            ("400 Bad Request", r#"{"error":{"message":"unreadable"}}"#)
        }
    };
    let _ = write!(
        writer,
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
        reply.len()
    );
    let _ = writer.flush();
}

/// A request as the stub reads it: its method and its body, decoded from its transfer encoding.
struct Request {
    method: String,
    body: Vec<u8>,
}

/// Reads one HTTP/1.1 request: its request line, its headers, of which only the body's length,
/// transfer encoding and content encoding are looked at, and its body.
fn read_request(reader: &mut impl BufRead) -> Result<Request, String> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|error| format!("a request line: {error}"))?;
    let method = line.split(' ').next().unwrap_or_default().to_owned();
    let mut length = None;
    let mut chunked = false;
    loop {
        let mut header = String::new();
        reader
            .read_line(&mut header)
            .map_err(|error| format!("a header: {error}"))?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let Some((name, value)) = header.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim().to_ascii_lowercase(), value.trim());
        match name.as_str() {
            "content-length" => {
                length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| "a body length that is not a number".to_owned())?,
                );
            }
            "transfer-encoding" => chunked = value.eq_ignore_ascii_case("chunked"),
            "content-encoding" if !value.eq_ignore_ascii_case("identity") => {
                return Err(format!(
                    "a body encoded as {value}, which the stub does not read"
                ));
            }
            _ => {}
        }
    }
    let body = if chunked {
        read_chunks(reader)?
    } else {
        let length = length.unwrap_or(0);
        if length > BODY_LIMIT {
            return Err(format!(
                "a body of {length} bytes, more than the stub reads"
            ));
        }
        let mut body = vec![0; length];
        reader
            .read_exact(&mut body)
            .map_err(|error| format!("a body: {error}"))?;
        body
    };
    Ok(Request { method, body })
}

/// Reads a chunked body to its last chunk.
fn read_chunks(reader: &mut impl BufRead) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let mut size = String::new();
        reader
            .read_line(&mut size)
            .map_err(|error| format!("a chunk: {error}"))?;
        let size = usize::from_str_radix(size.trim().split(';').next().unwrap_or_default(), 16)
            .map_err(|_| "a chunk size that is not a number".to_owned())?;
        if body.len() + size > BODY_LIMIT {
            return Err("a body larger than the stub reads".to_owned());
        }
        let mut chunk = vec![0; size + 2];
        reader
            .read_exact(&mut chunk)
            .map_err(|error| format!("a chunk: {error}"))?;
        if size == 0 {
            return Ok(body);
        }
        body.extend_from_slice(&chunk[..size]);
    }
}

/// The tools a request body offers, one line each, `<kind> <name>`, with a tool a namespace groups
/// named `<namespace>/<name>`: every list named `tools` in it, at the top or in an input item that
/// carries tools; `None` where the body is not JSON or offers none.
fn tools_of(body: &[u8]) -> Option<Vec<String>> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let mut lists = Vec::new();
    let mut searched = vec![&value];
    while let Some(value) = searched.pop() {
        match value {
            serde_json::Value::Object(members) => {
                for (name, member) in members.iter().rev() {
                    match member {
                        serde_json::Value::Array(tools) if name == "tools" => lists.push(tools),
                        _ => searched.push(member),
                    }
                }
            }
            serde_json::Value::Array(items) => searched.extend(items.iter().rev()),
            _ => {}
        }
    }
    if lists.is_empty() {
        return None;
    }
    let mut lines = Vec::new();
    for tools in lists {
        let mut pending: Vec<(String, &serde_json::Value)> = tools
            .iter()
            .rev()
            .map(|tool| (String::new(), tool))
            .collect();
        while let Some((prefix, tool)) = pending.pop() {
            let kind = tool
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let name = tool
                .get("name")
                .or_else(|| tool.get("server_label"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            lines.push(format!("{kind} {prefix}{name}").trim_end().to_owned());
            if let Some(nested) = tool.get("tools").and_then(serde_json::Value::as_array) {
                let prefix = format!("{prefix}{name}/");
                pending.extend(nested.iter().rev().map(|tool| (prefix.clone(), tool)));
            }
        }
    }
    Some(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// Sends `request` to the stub and returns its status line.
    fn send(address: &str, request: &[u8]) -> String {
        let mut stream =
            TcpStream::connect(address.trim_start_matches("http://")).expect("the stub");
        stream.write_all(request).expect("the request");
        let mut reply = String::new();
        stream.read_to_string(&mut reply).expect("the reply");
        reply.lines().next().unwrap_or_default().to_owned()
    }

    /// A POST whose body arrives in `pieces`, each a chunk of its own.
    fn chunked(pieces: &[&[u8]]) -> Vec<u8> {
        let mut request =
            b"POST /v1/responses HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n".to_vec();
        for piece in pieces {
            request.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
            request.extend_from_slice(piece);
            request.extend_from_slice(b"\r\n");
        }
        request.extend_from_slice(b"0\r\n\r\n");
        request
    }

    #[test]
    fn the_stub_keeps_the_tools_of_the_first_request_that_offers_them_and_refuses_it() {
        let stub = RequestStub::start().expect("a stub");
        let address = stub.address().to_owned();
        assert_eq!(
            send(&address, b"GET /v1/models HTTP/1.1\r\nhost: x\r\n\r\n"),
            "HTTP/1.1 404 Not Found"
        );
        let body = br#"{"model":"m","instructions":"secret","tools":[{"type":"function","name":"exec_command"},{"type":"namespace","name":"skills","tools":[{"type":"function","name":"read"}]},{"type":"web_search"}]}"#;
        let mut request = format!(
            "POST /v1/responses HTTP/1.1\r\nauthorization: Bearer stub\r\ncontent-length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        assert_eq!(send(&address, &request), "HTTP/1.1 400 Bad Request");
        let later = chunked(&[br#"{"tools":[{"type":"custom","name":"later"}]}"#]);
        assert_eq!(send(&address, &later), "HTTP/1.1 400 Bad Request");
        assert_eq!(
            stub.finish(),
            Ok(vec![
                "function exec_command".to_owned(),
                "namespace skills".to_owned(),
                "function skills/read".to_owned(),
                "web_search".to_owned(),
            ]),
            "only the first request's tools are kept, each by kind and name"
        );
    }

    #[test]
    fn a_chunked_body_is_read_whole_and_a_stub_nothing_reached_says_so() {
        let stub = RequestStub::start().expect("a stub");
        let address = stub.address().to_owned();
        let request = chunked(&[br#"{"tools":[{"type":"custom","#, br#""name":"another"}]}"#]);
        assert_eq!(send(&address, &request), "HTTP/1.1 400 Bad Request");
        assert_eq!(stub.finish(), Ok(vec!["custom another".to_owned()]));
        let empty = RequestStub::start().expect("a stub");
        assert_eq!(
            empty.finish(),
            Err("no request offering tools reached the stub".to_owned())
        );
    }

    #[test]
    fn tools_an_input_item_carries_are_found_as_well_as_those_at_the_top() {
        let body = br#"{"input":[{"type":"additional_tools","role":"developer","tools":[{"type":"namespace","name":"functions","tools":[{"type":"custom","name":"exec"}]}]},{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}"#;
        assert_eq!(
            tools_of(body),
            Some(vec![
                "namespace functions".to_owned(),
                "custom functions/exec".to_owned()
            ])
        );
        assert_eq!(tools_of(br#"{"input":[]}"#), None);
        assert_eq!(tools_of(b"not json"), None);
    }

    #[test]
    fn an_encoded_body_is_not_read_and_the_stub_says_why() {
        let stub = RequestStub::start().expect("a stub");
        let address = stub.address().to_owned();
        let request =
            b"POST /v1/responses HTTP/1.1\r\ncontent-encoding: zstd\r\ncontent-length: 2\r\n\r\n{}";
        assert_eq!(send(&address, request), "HTTP/1.1 400 Bad Request");
        let result = stub.finish();
        assert!(
            result
                .as_ref()
                .is_err_and(|why| why.contains("a body encoded as zstd")),
            "{result:?}"
        );
    }
}
