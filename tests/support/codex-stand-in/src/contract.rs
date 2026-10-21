//! The pinned release's protocol, as its published schemas state it.
//!
//! The schemas under `schemas/` are the ones the pinned release writes for its application server,
//! kept as they were written. Every frame this program writes or reads is checked against them, in
//! both directions, so a gateway that turns a frame into one the pinned release would not write,
//! or answers what nobody asked, is caught by the program at either end of it. A gateway that
//! turns a frame into another valid one (its members in another order, a number spelled another
//! way) is not caught here; the frames this program writes are built from values, and a test that
//! needs the bytes compares them itself.

use std::collections::BTreeMap;

use jsonschema::Validator;
use serde_json::Value;

/// The release the schemas belong to.
pub const RELEASE: &str = "0.155.1";

fn validator(name: &str, text: &str) -> Validator {
    let schema: Value =
        serde_json::from_str(text).unwrap_or_else(|error| panic!("schema {name}: {error}"));
    jsonschema::validator_for(&schema).unwrap_or_else(|error| panic!("schema {name}: {error}"))
}

/// The validators for one release's frames.
pub struct Contract {
    message: Validator,
    client_request: Validator,
    client_notification: Validator,
    server_request: Validator,
    server_notification: Validator,
    /// The result a method's response carries, by the method of the request it answers.
    results: BTreeMap<&'static str, Validator>,
}

impl Contract {
    /// Reads the schemas this program was built with.
    pub fn pinned() -> Self {
        let results = [
            (
                "initialize",
                validator(
                    "InitializeResponse",
                    include_str!("../schemas/InitializeResponse.json"),
                ),
            ),
            (
                "account/read",
                validator(
                    "GetAccountResponse",
                    include_str!("../schemas/GetAccountResponse.json"),
                ),
            ),
            (
                "thread/start",
                validator(
                    "ThreadStartResponse",
                    include_str!("../schemas/ThreadStartResponse.json"),
                ),
            ),
            (
                "turn/start",
                validator(
                    "TurnStartResponse",
                    include_str!("../schemas/TurnStartResponse.json"),
                ),
            ),
            (
                "item/commandExecution/requestApproval",
                validator(
                    "CommandExecutionRequestApprovalResponse",
                    include_str!("../schemas/CommandExecutionRequestApprovalResponse.json"),
                ),
            ),
            (
                "item/fileChange/requestApproval",
                validator(
                    "FileChangeRequestApprovalResponse",
                    include_str!("../schemas/FileChangeRequestApprovalResponse.json"),
                ),
            ),
            (
                "thread/resume",
                validator(
                    "ThreadResumeResponse",
                    include_str!("../schemas/ThreadResumeResponse.json"),
                ),
            ),
            (
                "thread/fork",
                validator(
                    "ThreadForkResponse",
                    include_str!("../schemas/ThreadForkResponse.json"),
                ),
            ),
            (
                "thread/unsubscribe",
                validator(
                    "ThreadUnsubscribeResponse",
                    include_str!("../schemas/ThreadUnsubscribeResponse.json"),
                ),
            ),
            (
                "turn/steer",
                validator(
                    "TurnSteerResponse",
                    include_str!("../schemas/TurnSteerResponse.json"),
                ),
            ),
            (
                "turn/interrupt",
                validator(
                    "TurnInterruptResponse",
                    include_str!("../schemas/TurnInterruptResponse.json"),
                ),
            ),
        ]
        .into_iter()
        .collect();
        Self {
            message: validator(
                "JSONRPCMessage",
                include_str!("../schemas/JSONRPCMessage.json"),
            ),
            client_request: validator(
                "ClientRequest",
                include_str!("../schemas/ClientRequest.json"),
            ),
            client_notification: validator(
                "ClientNotification",
                include_str!("../schemas/ClientNotification.json"),
            ),
            server_request: validator(
                "ServerRequest",
                include_str!("../schemas/ServerRequest.json"),
            ),
            server_notification: validator(
                "ServerNotification",
                include_str!("../schemas/ServerNotification.json"),
            ),
            results,
        }
    }

    /// Checks one frame as the pinned release's `side` would write it, and says what it is.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the frame: it is not a message of the protocol's envelope, it
    /// names a method or carries parameters the schemas do not allow that side, or it answers
    /// nothing in `asked`.
    pub fn check(
        &self,
        side: Side,
        frame: &Value,
        asked: &BTreeMap<String, String>,
    ) -> Result<Frame, String> {
        let first = |validator: &Validator| {
            validator
                .validate(frame)
                .map_err(|error| format!("{error} at {}", error.instance_path()))
        };
        first(&self.message)?;
        let object = frame
            .as_object()
            .ok_or_else(|| "a frame is a JSON object".to_owned())?;
        // The schemas call an identifier a string or an `int64`, and the format is not checked
        // by the validator, so the range is: an integer past 64 bits, and a number written as a
        // fraction, are not identifiers.
        match object.get("id") {
            None | Some(Value::String(_)) => {}
            Some(Value::Number(number)) if number.is_i64() => {}
            Some(other) => return Err(format!("{other} is not an identifier of the protocol")),
        }
        if object.contains_key("jsonrpc") {
            return Err("the pinned release writes no jsonrpc member".to_owned());
        }
        let method = object.get("method").and_then(Value::as_str);
        let identifier = object.get("id").map(Value::to_string);
        match (method, identifier) {
            (Some(method), Some(id)) => {
                first(match side {
                    Side::Terminal => &self.client_request,
                    Side::Server => &self.server_request,
                })?;
                Ok(Frame::Request {
                    id,
                    method: method.to_owned(),
                })
            }
            (Some(method), None) => {
                first(match side {
                    Side::Terminal => &self.client_notification,
                    Side::Server => &self.server_notification,
                })?;
                Ok(Frame::Notification {
                    method: method.to_owned(),
                })
            }
            (None, Some(id)) => {
                let method = asked
                    .get(&id)
                    .ok_or_else(|| format!("a response to {id}, which nothing asked"))?;
                match (object.get("result"), object.get("error")) {
                    (Some(result), None) => {
                        let schema = self
                            .results
                            .get(method.as_str())
                            .ok_or_else(|| format!("no schema for the result of {method}"))?;
                        schema
                            .validate(result)
                            .map_err(|error| format!("{error} at {}", error.instance_path()))?;
                        Ok(Frame::Response {
                            id,
                            method: method.clone(),
                        })
                    }
                    (None, Some(_)) => Ok(Frame::Failure {
                        id,
                        method: method.clone(),
                    }),
                    _ => Err("a response carries a result or an error, and not both".to_owned()),
                }
            }
            (None, None) => Err("a frame with no method and no identifier".to_owned()),
        }
    }
}

/// Which end wrote a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The native terminal.
    Terminal,
    /// The application server.
    Server,
}

/// What a checked frame is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// A request, by its identifier as written and its method.
    Request {
        /// The identifier, in its JSON form.
        id: String,
        /// The method.
        method: String,
    },
    /// A notification.
    Notification {
        /// The method.
        method: String,
    },
    /// A successful response.
    Response {
        /// The identifier, in its JSON form.
        id: String,
        /// The method of the request it answers.
        method: String,
    },
    /// An error response.
    Failure {
        /// The identifier, in its JSON form.
        id: String,
        /// The method of the request it answers.
        method: String,
    },
}
