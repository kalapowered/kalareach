//! The `kr-bridge` builtin: the one-shot activation the guarded startup entry performs.
//!
//! Copyright (c) Kala Powered.
//!
//! This file is added to fish by the KalaReach reader patch set and is
//! distributed under the GNU General Public Licence, version 2, that governs the rest of
//! the package; see shells/fish/LICENSE.
//!
//! The native bridge has already loaded before the user's configuration ran. What is left for the
//! startup entry is the half that has to run after it: saying, once, that the user-facing hooks
//! are live, which is what lets the session report itself ready. In a shell that never registered,
//! and in every child of a managed root shell, `status` fails and the entry does nothing.

use super::prelude::*;
use crate::err_str;
use crate::reader::kr_bridge::{
    KR_LOSS_POST_STARTUP_FAILURE, KR_LOSS_SEMANTIC_HOOK_LOSS,
    KR_LOSS_UNQUALIFIED_ROOT_REPLACEMENT, hooks_activated, lost, registered,
};
use crate::reader::{Reader, reader_current_data};

pub fn kr_bridge(parser: &mut Parser, streams: &mut IoStreams, argv: &mut [&wstr]) -> BuiltinResult {
    let Some(&cmd) = argv.first() else {
        return Err(STATUS_INVALID_ARGS);
    };
    let opts = HelpOnlyCmdOpts::parse(argv, parser, streams)?;
    if opts.print_help {
        builtin_print_help(parser, streams, cmd);
        return Ok(SUCCESS);
    }

    let Some(request) = argv.get(opts.optind) else {
        err_str!("expected activated, lost or status")
            .cmd(cmd)
            .finish(streams);
        return Err(STATUS_INVALID_ARGS);
    };

    if *request == L!("status") {
        return if registered() {
            Ok(SUCCESS)
        } else {
            Err(STATUS_CMD_ERROR)
        };
    }

    if *request == L!("activated") {
        if !registered() {
            return Err(STATUS_CMD_ERROR);
        }
        let Some(data) = reader_current_data() else {
            return Err(STATUS_CMD_ERROR);
        };
        let mut reader = Reader { data, parser };
        hooks_activated(&mut reader);
        return Ok(SUCCESS);
    }

    if *request == L!("lost") {
        let reason = argv.get(opts.optind + 1).copied().unwrap_or(L!(""));
        let loss = if reason == L!("post-startup-failure") {
            KR_LOSS_POST_STARTUP_FAILURE
        } else if reason == L!("unqualified-root-replacement") {
            KR_LOSS_UNQUALIFIED_ROOT_REPLACEMENT
        } else {
            KR_LOSS_SEMANTIC_HOOK_LOSS
        };
        let detail = argv.get(opts.optind + 2).copied().unwrap_or(L!(""));
        let Some(data) = reader_current_data() else {
            return Err(STATUS_CMD_ERROR);
        };
        let mut reader = Reader { data, parser };
        lost(&mut reader, loss, detail);
        return Ok(SUCCESS);
    }

    err_str!("unknown request").cmd(cmd).finish(streams);
    Err(STATUS_INVALID_ARGS)
}
