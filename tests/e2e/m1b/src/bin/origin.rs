//! Says whether the origin given as the one argument is one a deployment check can run against,
//! by the product's own parsers: a canonical HTTPS rendezvous origin, and an origin a service
//! request travels to. It exits 0 when it is, and 2, with the rule the value broke, when it is not
//! or when it is not given exactly one origin. The value itself is never printed: whatever it
//! holds stays out of the log the refusal is written to.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let (Some(named), None) = (arguments.next(), arguments.next()) else {
        eprintln!("the origin checker takes the origin as its one argument");
        return ExitCode::from(2);
    };
    let Some(named) = named.to_str() else {
        eprintln!("the origin is not text, so it is no origin");
        return ExitCode::from(2);
    };
    match kr_e2e_m1b::canonical_origin(named) {
        Ok(_) => ExitCode::SUCCESS,
        Err(rule) => {
            eprintln!("the origin {rule}");
            ExitCode::from(2)
        }
    }
}
