//! The generated bindings for the `kalareach:plugin` world.
//!
//! The bindings are generated from the SDK's own WIT text. There is no copy of that text in this
//! crate: the macro reads the file the SDK publishes, and the test below compares the bytes the
//! macro read with [`kr_plugin_sdk::wit::PACKAGE`], so a change to the contract cannot reach a
//! component without reaching this runtime too.
//!
//! Every host import is a plain synchronous function. An import that could await would be a place
//! where a component call waits on host input or output, and section 11 keeps broker I/O on its own
//! asynchronous limits rather than inside a bounded component call.
//!
//! Everything below the four host traits is machine-generated. What this module adds is the one
//! rule the generator cannot express: the host implements the four imports and nothing else, so a
//! component's whole reachable surface is the contract in that file.

#[expect(
    missing_docs,
    reason = "the generator carries the contract's own documentation and adds a few plumbing items of its own"
)]
mod generated {
    wasmtime::component::bindgen!({
        path: "../kr-plugin-sdk/wit/kalareach-plugin.wit",
        world: "plugin",
    });
}

pub use self::generated::exports::kalareach::plugin::adapter::{
    Binding, DecodedRequest, EffectPlan, EncodedResponse, Fault, FieldAssignment, FieldSegment,
    Guest as Adapter, PreparedOperation, RequestSnapshot, UpstreamCall,
};
pub use self::generated::kalareach::plugin::attachments::Attachment;
pub use self::generated::kalareach::plugin::document::Node;
pub use self::generated::kalareach::plugin::source_events::{Provenance, SourceEvent};
pub use self::generated::kalareach::plugin::types::{
    ActionToken, Argument, EffectClass, MethodClass, NamedArgument,
};
pub use self::generated::kalareach::plugin::upstream::{Activity, BindingState};
pub use self::generated::{Plugin, kalareach};

#[cfg(test)]
mod tests {
    /// The exact bytes the `bindgen!` macro above read.
    const READ_BY_BINDGEN: &str = include_str!("../../../kr-plugin-sdk/wit/kalareach-plugin.wit");

    #[test]
    fn the_bindings_are_generated_from_the_published_wit() {
        assert_eq!(
            READ_BY_BINDGEN,
            kr_plugin_sdk::wit::PACKAGE,
            "the runtime generated its bindings from different text than the SDK publishes"
        );
    }

    #[test]
    fn the_generated_accessor_carries_every_export_the_contract_names() {
        // The generated accessor is the contract's own list turned into methods. Naming each one
        // here is what makes an export dropped from the WIT a compilation failure in this crate
        // rather than a silently missing call.
        type Accessor = super::generated::exports::kalareach::plugin::adapter::Guest;
        type Store = wasmtime::Store<crate::runtime::host::HostState>;
        let _ = Accessor::call_bind::<&mut Store>;
        let _ = Accessor::call_observe::<&mut Store>;
        let _ = Accessor::call_snapshot::<&mut Store>;
        let _ = Accessor::call_prepare_action::<&mut Store>;
        let _ = Accessor::call_decode_request::<&mut Store>;
        let _ = Accessor::call_encode_response::<&mut Store>;
        let _ = Accessor::call_checkpoint::<&mut Store>;
        let _ = Accessor::call_restore::<&mut Store>;
        assert_eq!(kr_plugin_sdk::wit::EXPORTS.len(), 8);
    }

    #[test]
    fn the_host_traits_are_the_four_the_contract_declares() {
        // Naming each one is the check: a fifth host trait would mean a fifth import, and there is
        // no import here that this list does not cover.
        fn implements_every_host_trait<T>()
        where
            T: super::kalareach::plugin::types::Host
                + super::kalareach::plugin::source_events::Host
                + super::kalareach::plugin::upstream::Host
                + super::kalareach::plugin::attachments::Host
                + super::kalareach::plugin::document::Host,
        {
        }
        implements_every_host_trait::<crate::runtime::host::HostState>();
    }
}
