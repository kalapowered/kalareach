//! The WIT package parses and declares exactly the documented interface.

use wit_parser::{Resolve, WorldItem};

use kr_plugin_sdk::wit;

fn resolve() -> (Resolve, wit_parser::WorldId) {
    let mut resolve = Resolve::default();
    let package = resolve
        .push_str("kalareach-plugin.wit", wit::PACKAGE)
        .expect("the WIT package parses");
    let world = resolve
        .select_world(&[package], Some(wit::WORLD))
        .expect("the world is declared");
    (resolve, world)
}

#[test]
fn the_package_parses() {
    let (resolve, world) = resolve();
    assert_eq!(resolve.worlds[world].name, wit::WORLD);
}

#[test]
fn the_world_exports_exactly_the_eight_component_functions() {
    let (resolve, world) = resolve();
    let mut found: Vec<String> = Vec::new();
    for (key, item) in &resolve.worlds[world].exports {
        let WorldItem::Interface { id, .. } = item else {
            panic!("the world exports something other than an interface: {key:?}");
        };
        let interface = &resolve.interfaces[*id];
        assert_eq!(
            interface.name.as_deref(),
            Some(wit::EXPORT_INTERFACE),
            "the world exports an unexpected interface"
        );
        found.extend(interface.functions.keys().cloned());
    }
    found.sort();
    let mut expected: Vec<String> = wit::EXPORTS.iter().map(|name| (*name).to_owned()).collect();
    expected.sort();
    assert_eq!(found, expected);
}

#[test]
fn the_world_imports_exactly_the_four_host_interfaces() {
    let (resolve, world) = resolve();
    let mut found: Vec<String> = Vec::new();
    for (key, item) in &resolve.worlds[world].imports {
        match item {
            WorldItem::Interface { id, .. } => {
                let name = resolve.interfaces[*id]
                    .name
                    .clone()
                    .expect("an imported interface is named");
                // `types` is imported implicitly by the interfaces that use it.
                if name != "types" {
                    found.push(name);
                }
            }
            _ => panic!("the world imports something other than an interface: {key:?}"),
        }
    }
    found.sort();
    let mut expected: Vec<String> = wit::IMPORTS.iter().map(|name| (*name).to_owned()).collect();
    expected.sort();
    assert_eq!(found, expected);
}

#[test]
fn no_host_import_sends_anything() {
    // The component proposes effects and the broker dispatches them. An import that sent data
    // would let an observation callback act, which is exactly what the grant separation exists to
    // prevent, so the import surface carries no such function.
    let (resolve, world) = resolve();
    for (key, item) in &resolve.worlds[world].imports {
        let WorldItem::Interface { id, .. } = item else {
            continue;
        };
        for name in resolve.interfaces[*id].functions.keys() {
            assert!(
                ![
                    "send", "write", "submit", "dispatch", "respond", "spawn", "open"
                ]
                .iter()
                .any(|forbidden| name.contains(forbidden)),
                "the import {key:?} offers {name}"
            );
        }
    }
}
