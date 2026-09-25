//! A call inside a macro whose expansion brings in a name of its own.

#[allow(non_snake_case)]
mod Pin {
    /// KR-REQ-03.11: a case of the name an expansion brings in for itself.
    pub fn new(_: &u8) {}
}

#[tokio::test]
async fn calls_a_name_inside_a_macro_that_brings_in_its_own() {
    tokio::select! {
        _ = async {} => { let _ = Pin::new(&1_u8); }
    }
}
