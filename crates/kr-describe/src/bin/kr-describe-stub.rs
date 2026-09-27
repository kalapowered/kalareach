//! The description process with no model, which the description tests start in place of
//! `kr-describe-inference`: the same serving code over a model that answers from the prompt, or a
//! child that breaks the wire on purpose. It is built only with the `testing` feature.

fn main() {
    std::process::exit(kr_describe::testing::stub_main());
}
