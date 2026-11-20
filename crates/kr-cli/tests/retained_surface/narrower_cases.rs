//! The cases of the narrower kind's checker: each is the control with one change, and asserts the
//! exact list of texts it must give, so that a rule taken away turns its list empty.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::narrower::{
    Account, Evidence, Helper, Input, Item, LevelRecord, Narrower, Range, Reader, Sender,
    check_held, check_narrower,
};
use super::walker::{Depth, Followed, Lookup, SightKind, Sighting};
use super::{REMOVED, Root, Same, compare_with_records};

pub const ROOT: &str = "the envelope a worker checks";

pub fn leak<T>(items: Vec<T>) -> &'static [T] {
    Box::leak(items.into_boxed_slice())
}

/// A reader that answers what a case sets and touches no file.
#[derive(Clone)]
pub struct Fixed {
    pub krates: BTreeMap<String, Lookup>,
    pub roots: BTreeMap<String, Lookup>,
    pub items: BTreeMap<(String, String), Lookup>,
    pub sightings: Result<Vec<Sighting>, String>,
}

impl Reader for Fixed {
    fn krate(&self, krate: &str) -> Lookup {
        self.krates
            .get(krate)
            .cloned()
            .unwrap_or_else(|| Lookup::Failed(format!("no answer set for the crate {krate}")))
    }

    fn root(&self, root: &Root) -> Lookup {
        self.roots
            .get(&root.label)
            .cloned()
            .unwrap_or_else(|| Lookup::Failed(format!("no answer set for {}", root.label)))
    }

    fn item(&self, krate: &str, name: &str) -> Lookup {
        self.items
            .get(&(krate.to_owned(), name.to_owned()))
            .cloned()
            .unwrap_or_else(|| Lookup::Failed(format!("no answer set for {krate}::{name}")))
    }

    fn sightings(&self) -> Result<Vec<Sighting>, String> {
        self.sightings.clone()
    }
}

fn found(digest: &str) -> Lookup {
    Lookup::Found(digest.to_owned())
}

fn sighting(krate: &str, name: &str, kinds: &[SightKind]) -> Sighting {
    Sighting {
        krate: krate.to_owned(),
        name: name.to_owned(),
        kinds: kinds.iter().copied().collect(),
    }
}

pub fn the_root(label: &str, krate: &'static str, depth: Depth) -> Root {
    super::root(label, krate, &["check_envelope"], depth)
}

/// Everything a run reads: the entry, the trees, the record and the settings.
#[derive(Clone)]
pub struct World {
    pub entry: Narrower,
    pub empty_table: bool,
    /// Entries after the first, checked in the same run.
    pub more: Vec<Narrower>,
    pub current: Fixed,
    pub release: Fixed,
    pub roots: Vec<(String, &'static str, Depth)>,
    pub worker_input_roots: Vec<&'static str>,
    pub peer_classes: Vec<&'static str>,
    pub record: BTreeMap<String, Value>,
    pub retained: usize,
    pub same: Vec<Same>,
    pub frozen: bool,
    pub this_level: &'static str,
}

fn at(krate: &str, name: &str) -> (String, String) {
    (krate.to_owned(), name.to_owned())
}

/// The control: one client crate with a builder, the old macro that only earlier releases have
/// and a removed builder's account; a daemon crate with a relay, a route that builds and an
/// account; a client crate with a relay and an account; and crates that send none.
pub fn control() -> World {
    let entry = Narrower {
        level: "0.78",
        root: ROOT,
        recorded: "rec",
        digest: "dig",
        refuses: "refuses a thing",
        rest: "the rest",
        registry: "the registry",
        unreached: "nobody",
        searched: leak(vec!["git grep one", "git grep two"]),
        range: Range {
            first_tag: "packages/v0.2.0+aaaaaaaaaaaa",
            why_first: "the first tag",
            tags: 3,
        },
        helpers: leak(vec![Helper {
            krate: "kr_worker",
            name: "helper_fn",
            now: "h-now",
            before: "h-before",
            what: "a helper",
        }]),
        senders: leak(vec![
            Sender {
                class: "the companion",
                sends: "builds",
                evidence: Evidence::Builds {
                    items: leak(vec![
                        Item {
                            krate: "kr_client",
                            name: "Link::target",
                            now: "d-target",
                            across: &[("a1", "reads the target"), ("a2", "same text, moved")],
                        },
                        Item {
                            krate: "kr_client",
                            name: "agent_prompt_command",
                            now: "absent",
                            across: &[("a3", "the old macro")],
                        },
                    ]),
                },
            },
            Sender {
                class: "relay",
                sends: "copies",
                evidence: Evidence::Relays {
                    items: leak(vec![Item {
                        krate: "kr_controller",
                        name: "relay_mutation",
                        now: "d-relay",
                        across: &[],
                    }]),
                },
            },
            Sender {
                class: "voice",
                sends: "none of the six",
                evidence: Evidence::Builds {
                    items: leak(vec![Item {
                        krate: "kr_controller",
                        name: "method_for",
                        now: "d-voice",
                        across: &[],
                    }]),
                },
            },
            Sender {
                class: "kr",
                sends: "copies",
                evidence: Evidence::Relays {
                    items: leak(vec![Item {
                        krate: "kr_cli",
                        name: "relay",
                        now: "d-kr",
                        across: &[("k1", "copies")],
                    }]),
                },
            },
            Sender {
                class: "hook",
                sends: "none",
                evidence: Evidence::SendsNone {
                    crates: &["kr_hook", "kr_automation"],
                },
            },
        ]),
        accounts: leak(vec![
            Account {
                krate: "kr_client",
                name: "Session::mutate",
                kinds: &[SightKind::Request],
                now: "absent",
                why: "a removed builder",
            },
            Account {
                krate: "kr_cli",
                name: "other_builder",
                kinds: &[SightKind::Names],
                now: "d-other",
                why: "builds another method",
            },
            Account {
                krate: "kr_controller",
                name: "Controller::other",
                kinds: &[SightKind::Names],
                now: "d-dae",
                why: "a daemon account",
            },
        ]),
    };
    let items = |pairs: &[(&str, &str, Lookup)]| {
        pairs
            .iter()
            .map(|(krate, name, lookup)| (at(krate, name), lookup.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let krates: BTreeMap<String, Lookup> = ["kr_hook", "kr_automation"]
        .iter()
        .map(|name| ((*name).to_owned(), found("")))
        .collect();
    let current = Fixed {
        krates: krates.clone(),
        roots: BTreeMap::from([(ROOT.to_owned(), found("dig"))]),
        items: items(&[
            ("kr_worker", "helper_fn", found("h-now")),
            ("kr_client", "Link::target", found("d-target")),
            ("kr_client", "agent_prompt_command", Lookup::Absent),
            ("kr_controller", "relay_mutation", found("d-relay")),
            ("kr_controller", "method_for", found("d-voice")),
            ("kr_cli", "relay", found("d-kr")),
            ("kr_client", "Session::mutate", Lookup::Absent),
            ("kr_cli", "other_builder", found("d-other")),
            ("kr_controller", "Controller::other", found("d-dae")),
        ]),
        sightings: Ok(vec![
            sighting("kr_client", "Link::target", &[SightKind::Target]),
            sighting("kr_cli", "other_builder", &[SightKind::Names]),
        ]),
    };
    let release = Fixed {
        krates,
        roots: BTreeMap::from([(ROOT.to_owned(), found("rec"))]),
        items: items(&[
            ("kr_worker", "helper_fn", found("h-before")),
            ("kr_client", "Link::target", found("a1")),
            ("kr_client", "agent_prompt_command", found("a3")),
            ("kr_cli", "relay", found("k1")),
        ]),
        sightings: Ok(Vec::new()),
    };
    World {
        entry,
        empty_table: false,
        more: Vec::new(),
        current,
        release,
        roots: vec![(ROOT.to_owned(), "kr_worker", Depth::Alone)],
        worker_input_roots: vec![ROOT],
        peer_classes: vec!["the companion", "relay", "voice", "kr", "hook"],
        record: BTreeMap::from([(ROOT.to_owned(), json!({ "digest": "rec", "followed": [] }))]),
        retained: 1,
        same: Vec::new(),
        frozen: false,
        this_level: "0.78",
    }
}

impl World {
    fn run(&self, release_mode: bool) -> Vec<String> {
        let roots: Vec<Root> = self
            .roots
            .iter()
            .map(|(label, krate, depth)| the_root(label, krate, *depth))
            .collect();
        let record: serde_json::Map<String, Value> = self.record.clone().into_iter().collect();
        let defines = |_: &str| false;
        let levels: Vec<LevelRecord> = (0..self.retained)
            .map(|_| LevelRecord {
                level: "0.77",
                roots: &record,
                surface_defines: &defines,
            })
            .collect();
        let mut table = vec![self.entry.clone()];
        table.extend(self.more.iter().cloned());
        let entries = if self.empty_table {
            &[][..]
        } else {
            &table[..]
        };
        let input = Input {
            entries,
            roots: &roots,
            worker_input_roots: &self.worker_input_roots,
            receiver_crates: &["kr_protocol", "kr_worker"],
            daemon_crates: &["kr_controller"],
            peer_classes: &self.peer_classes,
            this_level: self.this_level,
            frozen: self.frozen,
            same: &self.same,
            retained: &levels,
            current: &self.current,
            release: release_mode.then_some(&self.release as &dyn Reader),
        };
        check_narrower(&input)
    }

    pub fn own(&self) -> Vec<String> {
        self.run(false)
    }

    pub fn release(&self) -> Vec<String> {
        self.run(true)
    }

    fn edit_sender(&mut self, class: &str, edit: impl FnOnce(&mut Sender)) {
        let mut senders = self.entry.senders.to_vec();
        edit(
            senders
                .iter_mut()
                .find(|sender| sender.class == class)
                .expect("a sender"),
        );
        self.entry.senders = leak(senders);
    }

    fn edit_items(&mut self, class: &str, edit: impl FnOnce(&mut Vec<Item>)) {
        self.edit_sender(class, |sender| {
            let mut items = sender.evidence.items().to_vec();
            edit(&mut items);
            sender.evidence = match sender.evidence {
                Evidence::Builds { .. } => Evidence::Builds { items: leak(items) },
                Evidence::Relays { .. } => Evidence::Relays { items: leak(items) },
                Evidence::SendsNone { .. } => panic!("a row that sends none has no items"),
            };
        });
    }

    fn edit_accounts(&mut self, edit: impl FnOnce(&mut Vec<Account>)) {
        let mut accounts = self.entry.accounts.to_vec();
        edit(&mut accounts);
        self.entry.accounts = leak(accounts);
    }

    fn edit_helper(&mut self, edit: impl FnOnce(&mut Helper)) {
        let mut helpers = self.entry.helpers.to_vec();
        edit(&mut helpers[0]);
        self.entry.helpers = leak(helpers);
    }

    fn lookup_of(&mut self, krate: &str, name: &str, lookup: Lookup) {
        self.current.items.insert(at(krate, name), lookup);
    }
}

/// A change to the control, with what the case says it is and the text it must give.
type Change = fn(&mut World);
type Case = (&'static str, Change, &'static str);
type TextCase = (&'static str, Change, String);
type LookupCase = (fn(&mut World, Lookup), Lookup, &'static str);

pub fn said(text: &str) -> String {
    format!("narrower {ROOT}: {text}")
}

fn none() -> Vec<String> {
    Vec::new()
}

#[test]
fn the_control_gives_no_problem_in_either_mode() {
    assert_eq!(control().own(), none());
    assert_eq!(control().release(), none());
}

#[test]
fn a_root_that_is_not_a_worker_input_root_is_refused() {
    let mut world = control();
    world.worker_input_roots = vec!["ActionTarget::validate"];
    world.entry.root = "ActionTarget::validate";
    world.roots = vec![(
        "ActionTarget::validate".to_owned(),
        "kr_protocol",
        Depth::Everything,
    )];
    let said = |text: &str| format!("narrower ActionTarget::validate: {text}");
    assert_eq!(
        world.own(),
        vec![
            said("the root is in kr_protocol, not in kr_worker"),
            said("the root is followed at Everything, not at Alone"),
        ]
    );
    world.worker_input_roots = vec![ROOT];
    assert_eq!(
        world.own(),
        vec![
            said("the root is not a worker input root"),
            said("the root is in kr_protocol, not in kr_worker"),
            said("the root is followed at Everything, not at Alone"),
        ]
    );
}

#[test]
fn each_way_a_root_can_fail_to_be_a_worker_input_root_has_a_text_of_its_own() {
    let mut protocol = control();
    protocol.roots = vec![(ROOT.to_owned(), "kr_protocol", Depth::Alone)];
    assert_eq!(
        protocol.own(),
        vec![said("the root is in kr_protocol, not in kr_worker")]
    );
    let mut missing = control();
    missing.roots = Vec::new();
    assert_eq!(missing.own(), vec![said("no root has this label")]);
    let mut attention = control();
    attention.worker_input_roots = vec!["another root"];
    assert_eq!(
        attention.own(),
        vec![said("the root is not a worker input root")]
    );
    let mut rules = control();
    rules.roots = vec![(ROOT.to_owned(), "kr_worker", Depth::Rules)];
    assert_eq!(
        rules.own(),
        vec![said("the root is followed at Rules, not at Alone")]
    );
}

#[test]
fn a_digest_that_is_not_the_current_one_is_refused() {
    let mut world = control();
    world.entry.digest = "other";
    assert_eq!(
        world.own(),
        vec![said(
            "this checkout's digest of the root is dig, the entry names other"
        )]
    );
}

#[test]
fn a_now_that_differs_from_this_checkout_is_refused_for_each_kind_of_item() {
    let cases: [Case; 5] = [
        (
            "a helper",
            |w| w.edit_helper(|helper| helper.now = "x"),
            "the helper kr_worker::helper_fn has the digest h-now in this checkout, the entry names x",
        ),
        (
            "a client item",
            |w| w.edit_items("the companion", |items| items[0].now = "x"),
            "the client item kr_client::Link::target has the digest d-target in this checkout, the entry names x",
        ),
        (
            "a daemon item",
            |w| w.edit_items("voice", |items| items[0].now = "x"),
            "the daemon item kr_controller::method_for has the digest d-voice in this checkout, the entry names x",
        ),
        (
            "a client account",
            |w| w.edit_accounts(|accounts| accounts[1].now = "x"),
            "the client account kr_cli::other_builder has the digest d-other in this checkout, the entry names x",
        ),
        (
            "a daemon account",
            |w| w.edit_accounts(|accounts| accounts[2].now = "x"),
            "the daemon account kr_controller::Controller::other has the digest d-dae in this checkout, the entry names x",
        ),
    ];
    for (what, change, text) in cases {
        let mut world = control();
        change(&mut world);
        assert_eq!(world.own(), vec![said(text)], "{what}");
    }
}

#[test]
fn an_item_that_the_entry_says_is_gone_and_this_checkout_defines_is_refused() {
    let mut item = control();
    item.lookup_of("kr_client", "agent_prompt_command", found("z"));
    assert_eq!(
        item.own(),
        vec![said(
            "the client item kr_client::agent_prompt_command is defined in this checkout, and the entry says it is gone (z)"
        )]
    );
    let mut account = control();
    account.lookup_of("kr_client", "Session::mutate", found("z"));
    assert_eq!(
        account.own(),
        vec![said(
            "the client account kr_client::Session::mutate is defined in this checkout, and the entry says it is gone (z)"
        )]
    );
}

#[test]
fn a_helper_that_moves_is_told_alone() {
    let mut world = control();
    world.lookup_of("kr_worker", "helper_fn", found("moved"));
    assert_eq!(
        world.own(),
        vec![said(
            "the helper kr_worker::helper_fn has the digest moved in this checkout, the entry names h-now"
        )]
    );
}

#[test]
fn the_record_decides_whether_the_entry_is_current() {
    let mut stale = control();
    stale.entry.recorded = "x";
    assert_eq!(
        stale.own(),
        vec![said("stale: the record holds rec, the entry names x")]
    );
    let mut missing = control();
    missing.record.clear();
    assert_eq!(
        missing.own(),
        vec![said(
            "stale: the record of level 0.77 has no root of this label"
        )]
    );
    let mut same = control();
    same.entry.digest = "rec";
    assert_eq!(
        same.own(),
        vec![
            said("nothing differs, so there is nothing to excuse"),
            said("this checkout's digest of the root is dig, the entry names rec"),
        ]
    );
    let mut release = control();
    release.entry.digest = "rec";
    assert_eq!(
        release.release(),
        vec![said("nothing differs, so there is nothing to excuse")]
    );
}

#[test]
fn an_empty_field_is_refused_with_the_name_of_the_field() {
    let cases: Vec<Case> = vec![
        ("refuses", |w| w.entry.refuses = "", "refuses is empty"),
        ("rest", |w| w.entry.rest = " ", "rest is empty"),
        ("registry", |w| w.entry.registry = "", "registry is empty"),
        (
            "unreached",
            |w| w.entry.unreached = "",
            "unreached is empty",
        ),
        ("searched", |w| w.entry.searched = &[], "searched is empty"),
        (
            "a searched line",
            |w| w.entry.searched = &["git grep one", ""],
            "searched line 2 is empty",
        ),
        (
            "first_tag",
            |w| w.entry.range.first_tag = "",
            "range.first_tag is empty",
        ),
        (
            "why_first",
            |w| w.entry.range.why_first = "",
            "range.why_first is empty",
        ),
        ("tags", |w| w.entry.range.tags = 0, "range.tags is zero"),
        (
            "a helper",
            |w| w.edit_helper(|helper| helper.what = ""),
            "helper kr_worker::helper_fn says nothing in what",
        ),
        (
            "a sender",
            |w| w.edit_sender("the companion", |sender| sender.sends = ""),
            "sender the companion says nothing in sends",
        ),
        (
            "an account's why",
            |w| w.edit_accounts(|accounts| accounts[0].why = ""),
            "account kr_client::Session::mutate says nothing in why",
        ),
        (
            "an account's kinds",
            |w| w.edit_accounts(|accounts| accounts[0].kinds = &[]),
            "account kr_client::Session::mutate covers no kind of sighting",
        ),
        (
            "an across sentence",
            |w| {
                w.edit_items("the companion", |items| {
                    items[0].across = &[("a1", " "), ("a2", "same text, moved")];
                });
            },
            "item kr_client::Link::target says nothing of its text a1",
        ),
    ];
    for (what, change, text) in cases {
        let mut world = control();
        change(&mut world);
        assert_eq!(world.own(), vec![said(text)], "{what}");
    }
}

#[test]
fn each_peer_class_has_exactly_one_row() {
    let mut removed = control();
    removed.entry.senders = leak(
        removed
            .entry
            .senders
            .iter()
            .filter(|sender| sender.class != "kr")
            .cloned()
            .collect(),
    );
    assert_eq!(removed.own(), vec![said("the peer class kr has no row")]);
    let mut stranger = control();
    let mut senders = stranger.entry.senders.to_vec();
    senders.push(Sender {
        class: "a stranger",
        sends: "none",
        evidence: Evidence::SendsNone {
            crates: &["kr_other"],
        },
    });
    stranger.entry.senders = leak(senders);
    assert_eq!(stranger.own(), vec![said("a stranger is no peer class")]);
    let mut twice = control();
    let mut senders = twice.entry.senders.to_vec();
    senders.push(senders[4].clone());
    twice.entry.senders = leak(senders);
    assert_eq!(twice.own(), vec![said("the peer class hook has 2 rows")]);
}

fn an_item(krate: &'static str, name: &'static str) -> Item {
    Item {
        krate,
        name,
        now: "d",
        across: &[("e", "s")],
    }
}

fn an_account(krate: &'static str, name: &'static str) -> Account {
    Account {
        krate,
        name,
        kinds: &[SightKind::Names],
        now: "d",
        why: "w",
    }
}

#[test]
fn the_shape_of_the_senders_is_refused_in_each_way() {
    let cases: Vec<TextCase> = vec![
        (
            "Builds with no items",
            |w| w.edit_items("the companion", |items| items.clear()),
            "sender the companion lists no item".to_owned(),
        ),
        (
            "Relays with no items",
            |w| w.edit_items("kr", |items| items.clear()),
            "sender kr lists no item".to_owned(),
        ),
        (
            "SendsNone with no crates",
            |w| w.edit_sender("hook", |s| s.evidence = Evidence::SendsNone { crates: &[] }),
            "sender hook names no crate that sends none".to_owned(),
        ),
        (
            "a receiver crate in SendsNone",
            |w| {
                w.edit_sender("hook", |s| {
                    s.evidence = Evidence::SendsNone {
                        crates: &["kr_hook", "kr_worker"],
                    };
                });
            },
            "sender hook names kr_worker, a receiver crate, as sending none".to_owned(),
        ),
        (
            "an item in a receiver crate",
            |w| w.edit_items("relay", |items| items.push(Item { across: &[], ..an_item("kr_worker", "x") })),
            "the item kr_worker::x is in a receiver crate".to_owned(),
        ),
        (
            "an account in a receiver crate",
            |w| w.edit_accounts(|accounts| accounts.push(an_account("kr_protocol", "x"))),
            "the account kr_protocol::x is in a receiver crate".to_owned(),
        ),
        (
            "a Builds item in a SendsNone crate",
            |w| w.edit_items("the companion", |items| items.push(an_item("kr_hook", "x"))),
            "the item kr_hook::x is in a crate that a row says sends none".to_owned(),
        ),
        (
            "a Relays item in a SendsNone crate",
            |w| w.edit_items("kr", |items| items.push(an_item("kr_hook", "x"))),
            "the item kr_hook::x is in a crate that a row says sends none".to_owned(),
        ),
        (
            "an account in a SendsNone crate",
            |w| w.edit_accounts(|accounts| accounts.push(an_account("kr_hook", "x"))),
            "the account kr_hook::x is in a crate that a row says sends none".to_owned(),
        ),
        (
            "two accounts for one item",
            |w| w.edit_accounts(|accounts| accounts.push(accounts[1].clone())),
            "two accounts cover kr_cli::other_builder".to_owned(),
        ),
        (
            "an account repeating an item",
            |w| w.edit_accounts(|accounts| accounts.push(an_account("kr_client", "Link::target"))),
            "the account for kr_client::Link::target repeats an item".to_owned(),
        ),
        (
            "a name in two rows",
            |w| w.edit_items("kr", |items| items.push(an_item("kr_client", "Link::target"))),
            "kr_client::Link::target is in two rows".to_owned(),
        ),
        (
            "a client item with no across",
            |w| w.edit_items("the companion", |items| items[0].across = &[]),
            "the item kr_client::Link::target of a client crate has no texts across the range"
                .to_owned(),
        ),
        (
            "a daemon item with across",
            |w| w.edit_items("relay", |items| items[0].across = &[("x", "y")]),
            "the item kr_controller::relay_mutation of a daemon crate has texts across the range"
                .to_owned(),
        ),
        (
            "absent on a daemon item",
            |w| w.edit_items("voice", |items| items[0].now = "absent"),
            "the item kr_controller::method_for is absent now and is not in a client crate"
                .to_owned(),
        ),
        (
            "absent on a daemon account",
            |w| w.edit_accounts(|accounts| accounts[2].now = "absent"),
            "the account kr_controller::Controller::other is absent now and is not in a client crate"
                .to_owned(),
        ),
        (
            "absent on a helper",
            |w| w.edit_helper(|helper| helper.now = "absent"),
            "the helper kr_worker::helper_fn is absent now".to_owned(),
        ),
    ];
    for (what, change, text) in cases {
        let mut world = control();
        change(&mut world);
        assert_eq!(world.own(), vec![said(&text)], "{what}");
    }
}

fn with_sightings(sightings: Vec<Sighting>) -> World {
    let mut world = control();
    world.current.sightings = Ok(sightings);
    world
}

#[test]
fn a_sighting_that_no_item_and_no_account_covers_is_refused() {
    let world = with_sightings(vec![sighting("kr_cli", "uncovered", &[SightKind::Names])]);
    assert_eq!(
        world.own(),
        vec![said(
            "the sighting kr_cli::uncovered ({Names}) is no item of a row and no account covers it"
        )]
    );
}

#[test]
fn a_sighting_that_something_covers_or_that_is_outside_the_scan_is_accepted() {
    let world = with_sightings(vec![
        sighting("kr_cli", "other_builder", &[SightKind::Names]),
        sighting("kr_worker", "anything", &[SightKind::Request]),
        sighting("kr_controller", "method_for", &[SightKind::Names]),
    ]);
    assert_eq!(world.own(), none());
}

#[test]
fn a_sighting_in_a_crate_that_sends_none_is_one_problem_only() {
    let world = with_sightings(vec![sighting("kr_hook", "send", &[SightKind::Names])]);
    assert_eq!(
        world.own(),
        vec![said(
            "kr_hook::send is a sighting in a crate that a row says sends none"
        )]
    );
}

#[test]
fn a_sighting_with_a_kind_the_account_lacks_is_refused() {
    let lacking = with_sightings(vec![sighting(
        "kr_cli",
        "other_builder",
        &[SightKind::Names, SightKind::Request],
    )]);
    assert_eq!(
        lacking.own(),
        vec![said(
            "the account for kr_cli::other_builder lacks the kind [Request] of its sighting ({Names, Request})"
        )]
    );
    let expands = with_sightings(vec![sighting(
        "kr_client",
        "macro:x",
        &[SightKind::Expands],
    )]);
    assert_eq!(
        expands.own(),
        vec![said(
            "the sighting kr_client::macro:x ({Expands}) is no item of a row and no account covers it"
        )]
    );
}

#[test]
fn a_failed_scan_is_a_text_of_its_own() {
    let mut world = control();
    world.current.sightings = Err("boom".to_owned());
    assert_eq!(
        world.own(),
        vec![said("the scan of this checkout failed: boom")]
    );
}

#[test]
fn every_way_a_lookup_can_fail_has_a_text_of_its_own() {
    let failed = || Lookup::Failed("e".to_owned());
    let cases: Vec<LookupCase> = vec![
        (
            |w, l| w.lookup_of("kr_client", "Link::target", l),
            Lookup::Absent,
            "the client item kr_client::Link::target is absent in this checkout, and the entry names the digest d-target",
        ),
        (
            |w, l| w.lookup_of("kr_client", "agent_prompt_command", l),
            failed(),
            "the client item kr_client::agent_prompt_command cannot be read in this checkout: e",
        ),
        (
            |w, l| w.lookup_of("kr_worker", "helper_fn", l),
            Lookup::Absent,
            "the helper kr_worker::helper_fn is absent in this checkout",
        ),
        (
            |w, l| w.lookup_of("kr_worker", "helper_fn", l),
            failed(),
            "the helper kr_worker::helper_fn cannot be read in this checkout: e",
        ),
        (
            |w, l| w.lookup_of("kr_controller", "method_for", l),
            Lookup::Absent,
            "the daemon item kr_controller::method_for is absent in this checkout",
        ),
        (
            |w, l| w.lookup_of("kr_cli", "other_builder", l),
            Lookup::Absent,
            "the client account kr_cli::other_builder is absent in this checkout, and the entry names the digest d-other",
        ),
        (
            |w, l| w.lookup_of("kr_cli", "other_builder", l),
            failed(),
            "the client account kr_cli::other_builder cannot be read in this checkout: e",
        ),
        (
            |w, l| {
                w.current.roots.insert(ROOT.to_owned(), l);
            },
            Lookup::Absent,
            "the root is absent in this checkout",
        ),
        (
            |w, l| {
                w.current.roots.insert(ROOT.to_owned(), l);
            },
            failed(),
            "the root cannot be read in this checkout: e",
        ),
        (
            |w, l| {
                w.current.krates.insert("kr_hook".to_owned(), l);
            },
            Lookup::Absent,
            "the crate kr_hook, which sends none, is absent in this checkout",
        ),
        (
            |w, l| {
                w.current.krates.insert("kr_hook".to_owned(), l);
            },
            failed(),
            "the crate kr_hook, which sends none, cannot be read: e",
        ),
    ];
    let mut texts = std::collections::BTreeSet::new();
    for (change, lookup, text) in cases {
        let mut world = control();
        change(&mut world, lookup);
        assert_eq!(world.own(), vec![said(text)], "{text}");
        assert!(texts.insert(text), "{text} is told once");
    }
    assert_eq!(texts.len(), 11);
}

#[test]
fn a_release_tree_is_held_to_the_recorded_root() {
    let mut other = control();
    other.release.roots.insert(ROOT.to_owned(), found("other"));
    assert_eq!(
        other.release(),
        vec![said(
            "the release's tree has the digest other for the root, the entry records rec"
        )]
    );
    let mut absent = control();
    absent.release.roots.insert(ROOT.to_owned(), Lookup::Absent);
    assert_eq!(
        absent.release(),
        vec![said("the root is absent in the release's tree")]
    );
    let mut failed = control();
    failed
        .release
        .roots
        .insert(ROOT.to_owned(), Lookup::Failed("e".to_owned()));
    assert_eq!(
        failed.release(),
        vec![said("the root cannot be read in the release's tree: e")]
    );
}

#[test]
fn a_release_tree_is_held_to_the_digest_before_for_a_helper() {
    let helper = |lookup: Lookup, before: &'static str| {
        let mut world = control();
        world.edit_helper(|helper| helper.before = before);
        world
            .release
            .items
            .insert(at("kr_worker", "helper_fn"), lookup);
        world.release()
    };
    assert_eq!(
        helper(found("other"), "h-before"),
        vec![said(
            "the helper kr_worker::helper_fn has the digest other in the release's tree, the entry names h-before"
        )]
    );
    assert_eq!(
        helper(Lookup::Absent, "h-before"),
        vec![said(
            "the helper kr_worker::helper_fn is absent in the release's tree, and the entry names the digest h-before"
        )]
    );
    assert_eq!(helper(Lookup::Absent, "absent"), none());
    assert_eq!(
        helper(Lookup::Failed("e".to_owned()), "absent"),
        vec![said(
            "the helper kr_worker::helper_fn cannot be read in the release's tree: e"
        )]
    );
}

#[test]
fn a_release_tree_is_held_to_the_texts_a_client_item_lists() {
    let item = |lookup: Lookup, across: &'static [(&'static str, &'static str)]| {
        let mut world = control();
        world.edit_items("the companion", |items| items[0].across = across);
        world
            .release
            .items
            .insert(at("kr_client", "Link::target"), lookup);
        world.release()
    };
    assert_eq!(
        item(found("zz"), &[("a1", "s")]),
        vec![said(
            "the item kr_client::Link::target has a text (zz) in the release's tree that the entry does not list"
        )]
    );
    assert_eq!(
        item(Lookup::Absent, &[("a1", "s")]),
        vec![said(
            "the item kr_client::Link::target is absent in the release's tree, and the entry lists no absent text"
        )]
    );
    assert_eq!(
        item(Lookup::Absent, &[("a1", "s"), ("absent", "t")]),
        none()
    );
    assert_eq!(
        item(Lookup::Failed("e".to_owned()), &[("a1", "s")]),
        vec![said(
            "the item kr_client::Link::target cannot be read in the release's tree: e"
        )]
    );
    // A daemon item and an account are not read in a release's tree: no answer is set for them.
    let mut world = control();
    world.release.items.clear();
    world
        .release
        .items
        .insert(at("kr_worker", "helper_fn"), found("h-before"));
    world
        .release
        .items
        .insert(at("kr_client", "Link::target"), found("a1"));
    world
        .release
        .items
        .insert(at("kr_client", "agent_prompt_command"), found("a3"));
    world
        .release
        .items
        .insert(at("kr_cli", "relay"), found("k1"));
    assert_eq!(world.release(), none());
}

#[test]
fn the_guards_stop_every_later_rule() {
    let mut frozen = control();
    frozen.frozen = true;
    assert_eq!(
        frozen.own(),
        vec![said(
            "from the public freeze this change needs a new public major"
        )]
    );
    let mut level = control();
    level.this_level = "0.79";
    assert_eq!(
        level.own(),
        vec![said("level 0.78 is not this build's level 0.79")]
    );
    let two = "an entry of the narrower table is read against exactly one retained record, and this build retains";
    let mut none_retained = control();
    none_retained.retained = 0;
    assert_eq!(none_retained.own(), vec![format!("{two} 0")]);
    let mut two_retained = control();
    two_retained.retained = 2;
    assert_eq!(two_retained.own(), vec![format!("{two} 2")]);
    let mut exactly_one = control();
    exactly_one.retained = 1;
    assert_eq!(exactly_one.own(), none());
    let mut empty = control();
    empty.empty_table = true;
    empty.retained = 2;
    assert_eq!(empty.own(), none());
    let mut stopped = control();
    stopped.frozen = true;
    stopped.entry.refuses = "";
    assert_eq!(
        stopped.own(),
        vec![said(
            "from the public freeze this change needs a new public major"
        )]
    );
}

#[test]
fn a_same_entry_and_a_narrower_entry_for_one_digest_are_refused() {
    let mut world = control();
    world.same = vec![Same {
        root: ROOT,
        digest: "dig",
        reason: "r",
    }];
    assert_eq!(
        world.own(),
        vec![said(
            "a Same entry and this entry both excuse the digest dig"
        )]
    );
}

#[test]
fn the_modes_read_their_own_rules_only() {
    let mut release = control();
    release.entry.helpers = leak(vec![Helper {
        now: "wrong",
        ..release.entry.helpers[0].clone()
    }]);
    release.current.items.clear();
    assert_eq!(release.release(), none());
    let mut own = control();
    own.release.roots.insert(ROOT.to_owned(), found("wrong"));
    own.release.items.clear();
    assert_eq!(own.own(), none());
}

#[test]
fn a_failure_of_the_shape_stops_the_lookups_and_the_rules_of_a_stage_do_not_stop_each_other() {
    let mut shape = control();
    shape.worker_input_roots = Vec::new();
    shape.entry.refuses = "";
    shape.entry.digest = "other";
    assert_eq!(
        shape.own(),
        vec![
            said("the root is not a worker input root"),
            said("refuses is empty")
        ]
    );
}

#[test]
fn the_lookups_do_not_stop_each_other() {
    let mut world = control();
    world.entry.recorded = "x";
    world.edit_items("the companion", |items| items[0].now = "x");
    assert_eq!(
        world.own(),
        vec![
            said("stale: the record holds rec, the entry names x"),
            said(
                "the client item kr_client::Link::target has the digest d-target in this checkout, the entry names x"
            ),
        ]
    );
}

fn the_entry_for(root: &'static str, digest: &'static str) -> Narrower {
    Narrower {
        root,
        digest,
        ..control().entry
    }
}

fn followed(digest: &str, items: &[&str]) -> Followed {
    Followed {
        digest: digest.to_owned(),
        items: items.iter().map(|item| (*item).to_owned()).collect(),
    }
}

fn compare(
    record: Value,
    followed: &[(&str, Followed)],
    same: &[Same],
    narrower: &[Narrower],
    own_tree: bool,
    defines: bool,
) -> Vec<String> {
    let record: serde_json::Map<String, Value> = record.as_object().expect("an object").clone();
    let defines = move |_: &str| defines;
    let levels = [LevelRecord {
        level: "0.77",
        roots: &record,
        surface_defines: &defines,
    }];
    let followed: BTreeMap<String, Followed> = followed
        .iter()
        .map(|(label, followed)| ((*label).to_owned(), followed.clone()))
        .collect();
    compare_with_records(&levels, &followed, same, narrower, own_tree)
}

#[test]
fn the_comparison_with_the_records_excuses_a_difference_by_a_same_or_a_narrower_entry() {
    let a_record = json!({ "T": { "digest": "d1", "followed": ["a"] } });
    let changed = [("T", followed("d2", &["b"]))];
    let text = "level 0.77: what T names changed (digest d2 now, d1 recorded); items only recorded: [\"a\"]; items only now: [\"b\"]";
    assert_eq!(
        compare(a_record.clone(), &changed, &[], &[], true, false),
        vec![text.to_owned()]
    );
    let same = [Same {
        root: "T",
        digest: "d2",
        reason: "r",
    }];
    assert_eq!(
        compare(a_record.clone(), &changed, &same, &[], true, false),
        none()
    );
    let narrower = [the_entry_for("T", "d2")];
    assert_eq!(
        compare(a_record.clone(), &changed, &[], &narrower, true, false),
        none()
    );
    // A narrower entry covers its own root and no other.
    let two = [("T", followed("d2", &["b"])), ("U", followed("d4", &[]))];
    let two_records = json!({
        "T": { "digest": "d1", "followed": ["a"] },
        "U": { "digest": "d3", "followed": [] }
    });
    assert_eq!(
        compare(two_records, &two, &[], &narrower, true, false),
        vec!["level 0.77: what U names changed (digest d4 now, d3 recorded); items only recorded: []; items only now: []".to_owned()]
    );
}

#[test]
fn the_comparison_with_the_records_finds_a_rule_that_went_and_a_type_that_gained_one() {
    let gone = json!({ "gone": { "digest": "d1", "followed": [] } });
    assert_eq!(
        compare(gone.clone(), &[], &[], &[], true, false),
        vec!["level 0.77: gone had a rule recorded and this tree follows none".to_owned()]
    );
    let removed = [Same {
        root: "gone",
        digest: REMOVED,
        reason: "r",
    }];
    assert_eq!(compare(gone, &[], &removed, &[], true, false), none());
    let none_recorded = json!({});
    let gained = [("T", followed("d2", &[]))];
    assert_eq!(
        compare(none_recorded.clone(), &gained, &[], &[], true, true),
        vec!["level 0.77: T is a type of the surface that had no rule of its own and has one now (digest d2)".to_owned()]
    );
    let excused = [Same {
        root: "T",
        digest: "d2",
        reason: "r",
    }];
    assert_eq!(
        compare(none_recorded.clone(), &gained, &excused, &[], true, true),
        none()
    );
    assert_eq!(
        compare(none_recorded, &gained, &[], &[], true, false),
        none()
    );
}

#[test]
fn a_same_entry_that_matches_no_digest_is_refused_in_an_own_tree_run_only() {
    let record = json!({ "T": { "digest": "d2", "followed": [] } });
    let tree = [("T", followed("d2", &[]))];
    let stale = [Same {
        root: "T",
        digest: "old",
        reason: "why",
    }];
    assert_eq!(
        compare(record.clone(), &tree, &stale, &[], true, false),
        vec!["a Same entry for T matches no digest now (why)".to_owned()]
    );
    assert_eq!(compare(record, &tree, &stale, &[], false, false), none());
}

#[test]
fn a_guard_that_refuses_stops_every_rule_after_it() {
    // Each input has a later fault, so a guard that goes on gives more than its own text.
    let two = "an entry of the narrower table is read against exactly one retained record, and this build retains";
    let mut level = control();
    level.this_level = "0.79";
    level.entry.refuses = "";
    assert_eq!(
        level.own(),
        vec![said("level 0.78 is not this build's level 0.79")]
    );
    let mut two_records = control();
    two_records.retained = 2;
    two_records.entry.refuses = "";
    assert_eq!(two_records.own(), vec![format!("{two} 2")]);
    let mut no_record = control();
    no_record.retained = 0;
    no_record.entry.refuses = "";
    assert_eq!(no_record.own(), vec![format!("{two} 0")]);
    // The public freeze comes first, whatever the number of records.
    let freeze = said("from the public freeze this change needs a new public major");
    for retained in [0, 2] {
        let mut frozen = control();
        frozen.frozen = true;
        frozen.retained = retained;
        assert_eq!(frozen.own(), vec![freeze.clone()], "{retained} records");
    }
}

#[test]
fn every_entry_of_the_table_is_checked() {
    let mut world = control();
    let mut second = world.entry.clone();
    second.refuses = "";
    world.more = vec![second];
    assert_eq!(world.own(), vec![said("refuses is empty")]);
    let mut third = control();
    let mut bad = third.entry.clone();
    bad.refuses = "";
    third.more = vec![third.entry.clone(), bad];
    assert_eq!(third.own(), vec![said("refuses is empty")]);
}

#[test]
fn the_rules_of_the_shape_do_not_stop_each_other() {
    let mut world = control();
    world.entry.refuses = "";
    world.edit_items("kr", |items| items.clear());
    assert_eq!(
        world.own(),
        vec![said("refuses is empty"), said("sender kr lists no item")]
    );
}

#[test]
fn a_root_that_differs_does_not_stop_the_sightings() {
    let mut world = control();
    world.entry.digest = "other";
    world.current.sightings = Ok(vec![sighting("kr_cli", "uncovered", &[SightKind::Names])]);
    assert_eq!(
        world.own(),
        vec![
            said("this checkout's digest of the root is dig, the entry names other"),
            said(
                "the sighting kr_cli::uncovered ({Names}) is no item of a row and no account covers it"
            ),
        ]
    );
}

#[test]
fn the_record_and_the_lookups_of_a_release_do_not_stop_each_other() {
    let mut world = control();
    world.entry.recorded = "x";
    assert_eq!(
        world.release(),
        vec![
            said("stale: the record holds rec, the entry names x"),
            said("the release's tree has the digest rec for the root, the entry records x"),
        ]
    );
    let mut lookups = control();
    lookups
        .release
        .roots
        .insert(ROOT.to_owned(), found("other"));
    lookups
        .release
        .items
        .insert(at("kr_worker", "helper_fn"), found("zz"));
    lookups
        .release
        .items
        .insert(at("kr_client", "Link::target"), found("yy"));
    assert_eq!(
        lookups.release(),
        vec![
            said("the release's tree has the digest other for the root, the entry records rec"),
            said(
                "the helper kr_worker::helper_fn has the digest zz in the release's tree, the entry names h-before"
            ),
            said(
                "the item kr_client::Link::target has a text (yy) in the release's tree that the entry does not list"
            ),
        ]
    );
}

#[test]
fn a_same_entry_for_another_root_or_another_digest_excuses_nothing_here() {
    let mut another_digest = control();
    another_digest.same = vec![Same {
        root: ROOT,
        digest: "other",
        reason: "r",
    }];
    assert_eq!(another_digest.own(), none());
    let mut another_root = control();
    another_root.same = vec![Same {
        root: "another root",
        digest: "dig",
        reason: "r",
    }];
    assert_eq!(another_root.own(), none());
}

#[test]
fn three_accounts_for_one_item_give_one_text() {
    let mut world = control();
    world.edit_accounts(|accounts| {
        accounts.push(accounts[1].clone());
        accounts.push(accounts[1].clone());
    });
    assert_eq!(
        world.own(),
        vec![said("two accounts cover kr_cli::other_builder")]
    );
}

#[test]
fn a_daemon_account_that_is_absent_or_cannot_be_read_has_its_own_text() {
    let mut absent = control();
    absent.lookup_of("kr_controller", "Controller::other", Lookup::Absent);
    assert_eq!(
        absent.own(),
        vec![said(
            "the daemon account kr_controller::Controller::other is absent in this checkout"
        )]
    );
    let mut failed = control();
    failed.lookup_of(
        "kr_controller",
        "Controller::other",
        Lookup::Failed("e".to_owned()),
    );
    assert_eq!(
        failed.own(),
        vec![said(
            "the daemon account kr_controller::Controller::other cannot be read in this checkout: e"
        )]
    );
}

#[test]
fn a_sighting_is_covered_by_the_crate_and_the_name_together() {
    let world = with_sightings(vec![
        sighting("kr_cli", "Link::target", &[SightKind::Target]),
        sighting("kr_client", "other_builder", &[SightKind::Names]),
    ]);
    assert_eq!(
        world.own(),
        vec![
            said(
                "the sighting kr_cli::Link::target ({Target}) is no item of a row and no account covers it"
            ),
            said(
                "the sighting kr_client::other_builder ({Names}) is no item of a row and no account covers it"
            ),
        ]
    );
}

#[test]
fn the_sightings_are_not_read_in_a_release_run() {
    let mut world = control();
    world.current.sightings = Ok(vec![sighting("kr_cli", "uncovered", &[SightKind::Names])]);
    assert_eq!(world.release(), none());
}

#[test]
fn every_class_of_peer_needs_a_row() {
    let mut world = control();
    world.entry.senders = &[];
    world.peer_classes = super::narrower::PEER_CLASSES.to_vec();
    let rows: Vec<String> = [
        "the companion",
        "a device's mutation relayed by the daemon",
        "the daemon's local prompt route",
        "the workflow and voice routes",
        "kr",
        "kr-hook",
        "the plugin host, the plugin runtime and the automation engine",
    ]
    .iter()
    .map(|class| said(&format!("the peer class {class} has no row")))
    .collect();
    assert_eq!(world.own(), rows);
}

#[test]
fn a_change_of_another_root_or_digest_is_not_excused_by_an_entry_for_its_neighbour() {
    let record = json!({
        "T": { "digest": "d1", "followed": ["a"] },
        "U": { "digest": "d3", "followed": [] }
    });
    let both = [("T", followed("d2", &["b"])), ("U", followed("d2", &[]))];
    let only_u = "level 0.77: what U names changed (digest d2 now, d3 recorded); items only recorded: []; items only now: []";
    let narrower = [the_entry_for("T", "d2")];
    assert_eq!(
        compare(record.clone(), &both, &[], &narrower, true, false),
        vec![only_u.to_owned()]
    );
    let same = [Same {
        root: "T",
        digest: "d2",
        reason: "r",
    }];
    assert_eq!(
        compare(record.clone(), &both, &same, &[], true, false),
        vec![only_u.to_owned()]
    );
    // A digest of the root that is not the one now excuses nothing, in a release tree too.
    let text = "level 0.77: what T names changed (digest d2 now, d1 recorded); items only recorded: [\"a\"]; items only now: [\"b\"]";
    let one = [("T", followed("d2", &["b"]))];
    let record_t = json!({ "T": { "digest": "d1", "followed": ["a"] } });
    let other_same = [Same {
        root: "T",
        digest: "d9",
        reason: "r",
    }];
    assert_eq!(
        compare(record_t.clone(), &one, &other_same, &[], false, false),
        vec![text.to_owned()]
    );
    let other_narrower = [the_entry_for("T", "d9")];
    assert_eq!(
        compare(record_t, &one, &[], &other_narrower, false, false),
        vec![text.to_owned()]
    );
}

/// What a release holds of the rule: the root and the helper.
fn a_release_with(root: Lookup, helper: Lookup) -> Fixed {
    Fixed {
        krates: BTreeMap::new(),
        roots: BTreeMap::from([(ROOT.to_owned(), root)]),
        items: BTreeMap::from([(at("kr_worker", "helper_fn"), helper)]),
        sightings: Ok(Vec::new()),
    }
}

fn the_entry_holds_in(world: &World, releases: &[(&str, &Fixed)]) -> Vec<String> {
    let roots: Vec<Root> = world
        .roots
        .iter()
        .map(|(label, krate, depth)| the_root(label, krate, *depth))
        .collect();
    let releases: Vec<(&str, &dyn Reader)> = releases
        .iter()
        .map(|(tag, release)| (*tag, *release as &dyn Reader))
        .collect();
    check_held(std::slice::from_ref(&world.entry), &roots, &releases)
}

const EARLY: &str = "packages/v0.78.0+aaaaaaaaaaaa";
const LATE: &str = "packages/v0.78.1+bbbbbbbbbbbb";

#[test]
fn the_root_and_the_helper_are_held_to_every_release_of_the_level() {
    let world = control();
    let same = a_release_with(found("dig"), found("h-now"));
    assert_eq!(
        the_entry_holds_in(&world, &[(EARLY, &same), (LATE, &same)]),
        none()
    );

    // The root: another digest, no root, a root that cannot be read; the tag is named, and the
    // release that holds it is not.
    let root = |lookup: Lookup| {
        the_entry_holds_in(
            &world,
            &[
                (EARLY, &same),
                (LATE, &a_release_with(lookup, found("h-now"))),
            ],
        )
    };
    assert_eq!(
        root(found("other")),
        vec![said(&format!(
            "{LATE} has the digest other for the root, the entry names dig"
        ))]
    );
    assert_eq!(
        root(Lookup::Absent),
        vec![said(&format!("the root is absent in {LATE}"))]
    );
    assert_eq!(
        root(Lookup::Failed("e".to_owned())),
        vec![said(&format!("the root cannot be read in {LATE}: e"))]
    );

    // The helper, the same three ways, apart from the root.
    let helper = |lookup: Lookup| {
        the_entry_holds_in(
            &world,
            &[
                (EARLY, &a_release_with(found("dig"), lookup)),
                (LATE, &same),
            ],
        )
    };
    assert_eq!(
        helper(found("other")),
        vec![said(&format!(
            "{EARLY} has the digest other for the helper kr_worker::helper_fn, the entry names h-now"
        ))]
    );
    assert_eq!(
        helper(Lookup::Absent),
        vec![said(&format!(
            "the helper kr_worker::helper_fn is absent in {EARLY}"
        ))]
    );
    assert_eq!(
        helper(Lookup::Failed("e".to_owned())),
        vec![said(&format!(
            "the helper kr_worker::helper_fn cannot be read in {EARLY}: e"
        ))]
    );

    // Both at once, in the order root then helper.
    assert_eq!(
        the_entry_holds_in(
            &world,
            &[(EARLY, &a_release_with(Lookup::Absent, Lookup::Absent))]
        ),
        vec![
            said(&format!("the root is absent in {EARLY}")),
            said(&format!(
                "the helper kr_worker::helper_fn is absent in {EARLY}"
            )),
        ]
    );
}

#[test]
fn an_entry_whose_root_no_root_has_is_told_once_and_nothing_else_is_read() {
    let mut world = control();
    world.roots.clear();
    let same = a_release_with(found("dig"), found("h-now"));
    assert_eq!(
        the_entry_holds_in(&world, &[(EARLY, &same), (LATE, &same)]),
        vec![said(
            "no root has this label, so no release can be held to it"
        )]
    );
}

#[test]
fn no_entry_and_no_release_are_no_problem() {
    let world = control();
    assert_eq!(the_entry_holds_in(&world, &[]), none());
    let roots = [the_root(ROOT, "kr_worker", Depth::Alone)];
    let wrong = a_release_with(found("other"), Lookup::Absent);
    assert_eq!(
        check_held(&[], &roots, &[(EARLY, &wrong as &dyn Reader)]),
        none()
    );
}
