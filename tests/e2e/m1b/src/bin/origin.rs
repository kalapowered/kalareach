//! Says whether the origin `KR_M1B_ORIGIN` names is one the checkpoint can run against, by the
//! product's own parsers: a canonical HTTPS rendezvous origin, and an origin a service request
//! travels to. It exits 0 when it is, and 2, with the rule the value broke, when it is not. The
//! value itself is never printed: an address may carry a credential in front of its host.

use std::process::ExitCode;

fn main() -> ExitCode {
    let named = std::env::var(kr_e2e_m1b::ORIGIN_VARIABLE).unwrap_or_default();
    match kr_e2e_m1b::canonical_origin(&named) {
        Ok(_) => ExitCode::SUCCESS,
        Err(rule) => {
            eprintln!("{rule}");
            ExitCode::from(2)
        }
    }
}
