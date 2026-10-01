//! The description process with no model, which this crate's own tests start in place of
//! `kr-describe-inference`: the serving code over a model that answers from the prompt, or a child
//! that breaks the wire on purpose, as its script says. It is built only with the `testing` feature.

fn main() {
    std::process::exit(kr_describe::testing::stub_main());
}
