//! The entries of the narrower kind: the rules of a worker's input that refuse more than the
//! retained release's rule did.
//!
//! An entry is made with the change that needs it, and is held to this checkout by
//! `the_entries_of_the_narrower_table_hold` and to every release of its level by the check a landing
//! runs. `the_senders_of_each_entry_at_each_release` reads every release tag below the level and holds
//! each row, account and range of an entry to what those releases sent.

use super::compiler::SightKind;
use super::narrower::{Account, Evidence, Helper, Item, Narrower, Range, Sender};

pub const NARROWER: &[Narrower] = &[
    // The envelope a worker checks: it refuses an envelope that names less or other than its parameters.
    Narrower {
        level: "0.79",
        root: "the envelope a worker checks",
        recorded: "670be1d3a4a028b44f5f5fbc5c7cb20eeed1398c6fef1ef521d2fffa69934143",
        digest: "5056aa8b73bcc549a5ee33af494310015c60b1acdc75cafbf2ca9de811358e0d",
        refuses: "An envelope that names no application instance for agent.prompt.submit, agent.prompt.queue, agent.turn.steer, agent.turn.cancel, agent.approval.respond or plugin.action.invoke; an envelope that names another binding revision than the parameters name; and an envelope that names the instance and no binding revision, which is the retained release's own refusal by the target's own check (`ActionTarget::validate`), repeated by the comparison the entry's root makes and reached by no envelope that passes that check.",
        rest: "The root differs from the retained release's `WorkerService::check_envelope` by the refusal of an envelope with no instance and by the comparison of the envelope's binding revision with the parameters' (which, for an envelope that names the instance and no revision, repeats the refusal that the retained release's `ActionTarget::validate` already makes), the binding and the comment that go with them, and its call of `params_application_target`, which replaces `params_application_instance`; nothing else. Run `git log -p -L '/    fn check_envelope(/,/^    }$/:crates/kr-worker/src/service.rs' packages/v0.78.0+e03f8dd17f5c..HEAD` to see the function's diff against the retained release.",
        registry: "The six methods' rows in `crates/kr-protocol/src/method.rs` decide `selects_an_instance` through `ResourceSelectorKind::ApplicationInstance`; no digest holds them. When the six rows lose it, a bare envelope takes `None => {}` and is admitted, and an envelope that names an instance reaches the branch that serves the session itself, so every case of `crates/kr-worker/tests/agent_service.rs` that sends one of the six fails (74 of the program's 77 at this checkout), among them the two that assert the refusals, `kr_req_23_30_an_envelope_that_names_no_instance_or_another_revision_is_refused_before_admission` and `kr_req_23_30_a_retry_of_an_uncertain_action_cannot_leave_its_subject_by_its_envelope`. The case of the third refusal, `kr_req_23_30_an_envelope_that_names_the_instance_and_no_revision_is_refused_before_admission`, stays green, because the target's own check refuses that envelope first.",
        unreached: "Clients outside this repository; phone builds of releases that the history of tags does not hold; a later daemon that retains this level and sends what a later release builds; and the receiver crates `kr_protocol` and `kr_worker`, which decode and check what they are sent and send none of the six. The compiler's reading reports the client crates only: it does not read `kr_controller`, so no check finds a new sender of the six in the daemon, and only the digests of the daemon items the rows list hold it.",
        searched: &[
            "git grep -n -w -E 'Method::(AgentPromptSubmit|AgentPromptQueue|AgentTurnSteer|AgentTurnCancel|AgentApprovalRespond|PluginActionInvoke)' -- crates apps ':!crates/kr-protocol/retained' ':!*/tests/*'",
            "git grep -n 'MutationRequest {' -- crates apps",
        ],
        range: Range {
            first_tag: "packages/v0.2.0+86926e6f4d1f",
            why_first: "The oldest release tag; its `crates/kr-protocol/src/method.rs` already holds the wire name of one of the six, and a 0.79 daemon admits a client of public major 1 whatever release built it, so no shorter range exists.",
            tags: 128,
        },
        helpers: &[
            Helper {
                krate: "kr_worker",
                name: "WorkerService::params_name_an_instance",
                now: "5b5eced965b06eed87476e9556fde0c5bb3f1afc63b59a9f32c29c726ed586a0",
                before: "absent",
                what: "Says which methods' parameters name the application instance they act on: the six. The root refuses an envelope with no instance only for these; the retained release has no such helper.",
            },
            Helper {
                krate: "kr_worker",
                name: "WorkerService::params_application_target",
                now: "64a390ce114a047a8f89adfbf99dc552568a824eeba06401fa8a75b8a906c0ef",
                before: "absent",
                what: "Reads the application instance and the binding revision the parameters of one of the six name. It replaces `params_application_instance`, which read the instance alone and which the retained release has.",
            },
        ],
        senders: &[
            Sender {
                class: "the companion",
                sends: "Each of the six commands of the companion's host builds the envelope's target from the application instance and the binding revision its parameters carry (`WorkerLinks::mutate` calls `link.target(Some(instance), Some(binding))`; the releases 0.49.0 to 0.71.0 build the target there with `Nullable::some` of both instead), so the envelope names both as the parameters do; a prompt that names a draft builds its target the same way (`send_draft_prompt`); the items between a command and `WorkerLinks::mutate` that choose the target passed with the parameters are listed too (`macro:agent_mutate_command`, `macro:agent_prompt_command`, `send_prompt`, `WorkerLinks::submit`), and the carriers of `kr_client` pass the target on as given. The page sets `resource_id` of the plugin action in `model/agent.ts`, audited apart.",
                evidence: Evidence::Builds {
                    items: &[
                        Item {
                            krate: "companion_tauri",
                            name: "Link::target",
                            now: "a42ef3b1ec362e36123845e29a6ba5a2413c4aec864f29443ec5a706e884e763",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "a42ef3b1ec362e36123845e29a6ba5a2413c4aec864f29443ec5a706e884e763",
                                    "Builds the envelope's target from the instance and the binding revision its caller passes, each as given, so the envelope names what the caller named.",
                                ),
                            ],
                        },
                        Item {
                            krate: "companion_tauri",
                            name: "WorkerLinks::mutate",
                            now: "119b78a88b569cf4bf3ada8ff7735e3de77e81038705a42a37f1719d23c1e192",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "56049481c5610e20ba5cdcd97a3ecfdcdf4bf7582b5f696c306e34837fab18dc",
                                    "Builds the envelope's target with `Nullable::some` of the instance and of the binding revision its caller passes, so the envelope names what the parameters' target names.",
                                ),
                                (
                                    "d7f1edd9868390c0a73f29accc7f5e42b5e9ca454e16c3817fd3ea38a3da47cf",
                                    "Builds the envelope's target by `link.target(Some(..), Some(..))` from the application instance and the binding revision of the mutation target its caller passes (`about`), checks it with `ActionTarget::validate` and sends it through `submit`, so the envelope names what the parameters' target names.",
                                ),
                                (
                                    "119b78a88b569cf4bf3ada8ff7735e3de77e81038705a42a37f1719d23c1e192",
                                    "Builds the envelope's target by `link.target(Some(..), Some(..))` from the application instance and the binding revision of the mutation target its caller passes (`about`), checks it with `ActionTarget::validate` and sends it through `submit`, so the envelope names what the parameters' target names.",
                                ),
                            ],
                        },
                        Item {
                            krate: "companion_tauri",
                            name: "WorkerLinks::submit",
                            now: "c80494085c258f747b439851df1c978988ebdfa0530b9c37ae4c76a74362968b",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "751fef0b22a2bc9e832bd645c18b673c03ba498245a1e958dcfb8fefec61f241",
                                    "Sends the method, the target and the parameters through the link's session as given, with no preconditions; it sets neither the instance nor the revision.",
                                ),
                                (
                                    "c80494085c258f747b439851df1c978988ebdfa0530b9c37ae4c76a74362968b",
                                    "Sends the method, the target, the preconditions and the parameters through the link's session as given; it sets neither the instance nor the revision.",
                                ),
                            ],
                        },
                        Item {
                            krate: "companion_tauri",
                            name: "send_prompt",
                            now: "461099d4541b7046a4296c37ffb7182d924b335872632dd4e6e3c1f5efba2dc5",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "fb71a7c64895756533e607b11252aeb087b746b78d5e2108553a6967d050366e",
                                    "Takes the target from the prompt's own parameters (`typed.target`) and passes it to `WorkerLinks::mutate`; a prompt that names a draft is refused on a host this device is paired with (`not_on_a_paired_host`) and otherwise the parameters go to `send_draft_prompt`, which builds its target from the parameters' instance and binding revision; the envelope names what the parameters name.",
                                ),
                                (
                                    "461099d4541b7046a4296c37ffb7182d924b335872632dd4e6e3c1f5efba2dc5",
                                    "Takes the target from the prompt's own parameters (`typed.target`) and passes it to `WorkerLinks::mutate`; a prompt that names a draft goes through `WorkerLinks::mutate` too when this device is paired with a host, and when it is paired with none the parameters go to `send_draft_prompt`, which builds its target from the parameters' instance and binding revision; the envelope names what the parameters name.",
                                ),
                            ],
                        },
                        Item {
                            krate: "companion_tauri",
                            name: "send_draft_prompt",
                            now: "9fcd39084a7888940c8ff84bf9a5f93e2f372546d465c429d36adbf5e9ad6df3",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "f0bfeab7a21c55bb19ba7fa5ca6804c94eb84dec1df25f32629d11eab20f5cbe",
                                    "Builds the prompt's target with `Nullable::some` of the instance and of the binding revision its parameters name, so the envelope names both as the parameters do.",
                                ),
                                (
                                    "9fcd39084a7888940c8ff84bf9a5f93e2f372546d465c429d36adbf5e9ad6df3",
                                    "Builds the prompt's target with `Nullable::some` of the instance and of the binding revision its parameters name, so the envelope names both as the parameters do.",
                                ),
                            ],
                        },
                        Item {
                            krate: "companion_tauri",
                            name: "target",
                            now: "4dd760c8c1e6d982dcda3b5fd123ca3abb4e40afd5cd46d2d6f2e4ac3893f515",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "dca01ba7bfb13e9d7c539f202a7a362e2503197231d705abe277868982f5204f",
                                    "Holds the items named `target` in 2 files: the declaration of the module `target` in `lib.rs`; `Subject::target`'s function in `target.rs`, which builds the target of a command that names a subject and sets the instance and the binding revision only when the page names them. None of the six takes a subject or a terminal.",
                                ),
                                (
                                    "f0004b936ae47bbea3a7b195c7e29ba48a8b436fd94388d737d5914b1499531c",
                                    "Holds the items named `target` in 3 files: the declaration of the module `target` in `lib.rs`; `Subject::target`'s function in `target.rs`, which builds the target of a command that names a subject and sets the instance and the binding revision only when the page names them; the terminal's `target` in `terminal/view.rs`, which builds a terminal's target with the instance and the binding revision null. None of the six takes a subject or a terminal.",
                                ),
                                (
                                    "4dd760c8c1e6d982dcda3b5fd123ca3abb4e40afd5cd46d2d6f2e4ac3893f515",
                                    "Holds the items named `target` in 4 files: `Link::target`'s function in `agent.rs`, which builds the envelope's target from the instance and the binding revision its caller passes; the declaration of the module `target` in `lib.rs`; `Subject::target`'s function in `target.rs`, which builds the target of a command that names a subject and sets the instance and the binding revision only when the page names them; the terminal's `target` in `terminal/view.rs`, which builds a terminal's target with the instance and the binding revision null. None of the six takes a subject or a terminal.",
                                ),
                            ],
                        },
                        Item {
                            krate: "companion_tauri",
                            name: "NAMED_COMMANDS",
                            now: "16d6956228dc3d902dd13aca1542ce4ca39458c42d9253ff2551076d5a0c7771",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "5d39a125c4cfb542b92356d7a1f086fac65551dddd9569db441a3fc382eb163f",
                                    "Names the host's commands and the method each sends; none of the six is among them, so nothing of it sends one.",
                                ),
                                (
                                    "bbe55fa8f5ed37814f63d6f58b3695304964d0241a3cde410c448967c28c8c5e",
                                    "Names the host's commands and the method each sends; none of the six is among them, so nothing of it sends one.",
                                ),
                                (
                                    "58deb1aa6b443e2d1678275a2ddcb0d9d5e716ae7edc35ce5d610f9830d236ea",
                                    "Names the host's commands and the method each sends; none of the six is among them, so nothing of it sends one.",
                                ),
                                (
                                    "a3609c3bf07fc2b499ee7d3010cd5f4dc8c4c59c19bf5b099e2ce0bdf2c5a0f4",
                                    "Names the host's commands and the method each sends; none of the six is among them, so nothing of it sends one.",
                                ),
                                (
                                    "b59219371fe19669a0249aa8b0be516c47c458d2f96ba6984460f4fc2324127b",
                                    "Names the host's commands and the method each sends; none of the six is among them, so nothing of it sends one.",
                                ),
                                (
                                    "48727f6e15076021a3b63e729c8e64001db0c8b749e661eab329d5e81b9972b7",
                                    "Names the host's commands and the method each sends; none of the six is among them, so nothing of it sends one.",
                                ),
                                (
                                    "f4ba4e224a8ec54b56e02c352459352fba2ccf83604fc08567b56322e7e35f4f",
                                    "Names the host's commands and the method each sends; 5 of the six are among them (not `plugin_action_invoke`). It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "a70afae1c163171c368859b7c2181ba24fd39ee9cdcb4a8cc45adee55c1c8060",
                                    "Names the host's commands and the method each sends; 5 of the six are among them (not `plugin_action_invoke`). It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "b310b32539b6323e686c85b7e8b4fc65e45e2895cb4dbf75927f920b4276ec44",
                                    "Names the host's commands and the method each sends; 5 of the six are among them (not `plugin_action_invoke`). It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "e8f4c773b889f1c8f9dc2382531231e7986e81dc0cd01c6f1dbefa1f0c827b6d",
                                    "Names the host's commands and the method each sends; 5 of the six are among them (not `plugin_action_invoke`). It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "a1ab8143a268e3a1f2e2e711c38963a5776f4508efb910f6e434775555ae9b6c",
                                    "Names the host's commands and the method each sends; 5 of the six are among them (not `plugin_action_invoke`). It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "e99b16a0467274365d436ee547171685d67f62a402321f437453e490b49d23e1",
                                    "Names the host's commands and the method each sends; 5 of the six are among them (not `plugin_action_invoke`). It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "3ea8857129f8a776eed627e2856920fab93f7aa349f0743579cd7a127c1582fc",
                                    "Names the host's commands and the method each sends; 5 of the six are among them (not `plugin_action_invoke`). It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "eea16cafd4e534be4df64d64f9ee05ebb24990438da9e9e5421d9d96180105e4",
                                    "Names the host's commands and the method each sends; 5 of the six are among them (not `plugin_action_invoke`). It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "1091f5c0a06c42cc975345dfd79538d985aca0a8fc57337beb14d0204006fa5a",
                                    "Names the host's commands and the method each sends; 5 of the six are among them (not `plugin_action_invoke`). It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "d57458c22d77ace86b82966d81024e9b25f7d56e7ed0299e4fccbfafca8865c4",
                                    "Names the host's commands and the method each sends; 5 of the six are among them (not `plugin_action_invoke`). It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "b8da4c496be033c31d2608f29dc226527a7f4d8ee2b805eadbf748c1a96ef865",
                                    "Names the host's commands and the method each sends; 5 of the six are among them (not `plugin_action_invoke`). It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "d936da138931633c02247d05d26f58a2612dca741144d486516a83a3d536c75b",
                                    "Names the host's commands and the method each sends; 5 of the six are among them (not `plugin_action_invoke`). It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "81f7e25cae76ae437be0256196bc7e1d0d442ced4c06df418eb63b8fe96f4cce",
                                    "Names the host's commands and the method each sends; 5 of the six are among them (not `plugin_action_invoke`). It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "3c845fec48348bbdfe1fabc691f450b83d0ef09dda45f5b57b49c38b542a58ad",
                                    "Names the host's commands and the method each sends; 5 of the six are among them (not `plugin_action_invoke`). It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "306ebc084747a1fa2e18b4abf55dd480f5c3551a6b0b6190ed178f99b6335297",
                                    "Names the host's commands and the method each sends; 5 of the six are among them (not `plugin_action_invoke`). It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "10897daf9bd82a41cbbcc6b7258b29dc040eeb8d1102277a7e384d7312aeec75",
                                    "Names the host's commands and the method each sends; 5 of the six are among them (not `plugin_action_invoke`). It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "cc0499df80ba06b4bd634b1048293155336b1e2bca81cbf6065c8f709f05fcaf",
                                    "Names the host's commands and the method each sends; all six are among them. It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "bc8fc85526def6d4f64f2a5b835d9a283418ab00c0e84a73349e4fb5396c591d",
                                    "Names the host's commands and the method each sends; all six are among them. It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "87f60005879e8639a55d60d4dd55d2a82a9d4415bec9fb527757076f3b717e5b",
                                    "Names the host's commands and the method each sends; all six are among them. It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "2de24bd1fda1c22187e8643ce6965715ec777ac2cd92a1fb40b93beebc71f5f3",
                                    "Names the host's commands and the method each sends; all six are among them. It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "1c7e8eb359a08f1a1242bf3af81ebdff7b19529db030c075482ce8f477dc16c2",
                                    "Names the host's commands and the method each sends; all six are among them. It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "7650166cd3c3194256586bdc5c7d340264276cd885e0c7d68aa01291c1b030cb",
                                    "Names the host's commands and the method each sends; all six are among them. It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "6c9e6a48430c1eb8c7ef992d5679fe1be1380c8585a9f261f8d994d71b32e95c",
                                    "Names the host's commands and the method each sends; all six are among them. It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "6a3f93ca63d14ddf2715533a8532cae0c411f417e99ce6bfb988053630fdb2df",
                                    "Names the host's commands and the method each sends; all six are among them. It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "5bdb9205ab3d1d7508b8debd33ed317606231681742fcef15eae45f581197c79",
                                    "Names the host's commands and the method each sends; all six are among them. It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                                (
                                    "16d6956228dc3d902dd13aca1542ce4ca39458c42d9253ff2551076d5a0c7771",
                                    "Names the host's commands and the method each sends; all six are among them. It builds no request, and each of those commands takes its target from its parameters.",
                                ),
                            ],
                        },
                        Item {
                            krate: "companion_tauri",
                            name: "agent_prompt_submit",
                            now: "88d2ff596c595aa0efad292a1c92271cbc0c9a6e306bb6f29fb7a93d3cccf260",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "ca64c159e77e6508a22aba5006ad6e1fae00aeec297ac02894845e6c799b96bb",
                                    "Invokes `agent_mutate_command!` for `AgentPromptSubmit`; the macro's body, listed beside, passes the target its parameters carry to the link.",
                                ),
                                (
                                    "5f66b8a8b49d519c0e0949fb4e835fb6399595fbe6292a388b8de5f50cc426e1",
                                    "Invokes `agent_prompt_command!` for `AgentPromptSubmit`; the macro's body, listed beside, passes the target its parameters carry to the link, or sends a draft with it.",
                                ),
                                (
                                    "8ba36ceab556056f5004a9727ef4ec70173dd872f09f2a53523f7c66100ed7f8",
                                    "Defines the command, which hands its parameters to `send_prompt` (listed beside) with `AgentPromptSubmit`; the target is the one the parameters carry.",
                                ),
                                (
                                    "88d2ff596c595aa0efad292a1c92271cbc0c9a6e306bb6f29fb7a93d3cccf260",
                                    "Defines the command, which hands its parameters to `send_prompt` (listed beside) with `AgentPromptSubmit`; the target is the one the parameters carry.",
                                ),
                            ],
                        },
                        Item {
                            krate: "companion_tauri",
                            name: "agent_prompt_queue",
                            now: "5b3e9669e09ad77a5f9e10aa89eaa38df354932481e23cc402a7638a5352300e",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "da96c79cfc488d1d866c99c05c5b334f6efd29916494270549d1a3b6b6a9cd15",
                                    "Invokes `agent_mutate_command!` for `AgentPromptQueue`; the macro's body, listed beside, passes the target its parameters carry to the link.",
                                ),
                                (
                                    "6ce9ac86e99e8887d997e4f2671406ba37b7c039aa15e37bd0e69b8f1afb85f7",
                                    "Invokes `agent_prompt_command!` for `AgentPromptQueue`; the macro's body, listed beside, passes the target its parameters carry to the link, or sends a draft with it.",
                                ),
                                (
                                    "ea8d57dea78b62e1721dec5b82e57d369b8275d72ba340e19b0d5bb37080cf13",
                                    "Defines the command, which hands its parameters to `send_prompt` (listed beside) with `AgentPromptQueue`; the target is the one the parameters carry.",
                                ),
                                (
                                    "5b3e9669e09ad77a5f9e10aa89eaa38df354932481e23cc402a7638a5352300e",
                                    "Defines the command, which hands its parameters to `send_prompt` (listed beside) with `AgentPromptQueue`; the target is the one the parameters carry.",
                                ),
                            ],
                        },
                        Item {
                            krate: "companion_tauri",
                            name: "agent_mutate_command! invocation @apps/companion/src-tauri/src/commands.rs",
                            now: "4bed2b1531608938457b2cca742c574beedd66849e763157feaa5592fa9e4c6b",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "7209ceb9e0947351cd341d13fabc46d35efa80ad53b9e10643509b9a63214136",
                                    "Invokes `agent_mutate_command!` for `agent_prompt_submit`, `agent_prompt_queue`, `agent_turn_steer`, `agent_turn_cancel`, `agent_approval_respond`; the macro's body, listed beside, passes the target each command's parameters carry to the link.",
                                ),
                                (
                                    "eb060f2d9d61ca706301a107e87e86794985a788e59d2e2e3a6f786cba71bdb4",
                                    "Invokes `agent_mutate_command!` for `agent_turn_steer`, `agent_turn_cancel`, `agent_approval_respond`; the macro's body, listed beside, passes the target each command's parameters carry to the link.",
                                ),
                                (
                                    "4bed2b1531608938457b2cca742c574beedd66849e763157feaa5592fa9e4c6b",
                                    "Invokes `agent_mutate_command!` for `agent_turn_steer`, `agent_turn_cancel`, `agent_approval_respond`, `plugin_action_invoke`; the macro's body, listed beside, passes the target each command's parameters carry to the link.",
                                ),
                            ],
                        },
                        Item {
                            krate: "companion_tauri",
                            name: "agent_prompt_command! invocation @apps/companion/src-tauri/src/commands.rs",
                            now: "absent",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "71e5ce6676b29e2945b5ad4eb0a98b59425b6fbeb1e0a4670b29939fec7586dc",
                                    "Invokes `agent_prompt_command!` for `agent_prompt_submit`, `agent_prompt_queue`; the macro's body, listed beside, passes the target each command's parameters carry to the link.",
                                ),
                            ],
                        },
                        Item {
                            krate: "companion_tauri",
                            name: "macro:agent_mutate_command",
                            now: "4e0d31574e80d231d5809d0dae94a1f0a7e2c640d6570e482ff9044db1f425c4",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "3ad1e6bad0d75dae5eaab6be2adb5bf91aa13a1d760a1cd0b3a9b4eab8f93526",
                                    "Passes the instance and the binding revision of the parameters' target (`target.subject.application_instance_id`, `target.binding_revision`) to `WorkerLinks::mutate`, with the parameters as decoded.",
                                ),
                                (
                                    "983226c91a4347f2099939be4ac192dffec66b6dbe7f6b3622ccdaa53ae1830d",
                                    "Passes the parameters' target (`typed.target`) whole to `WorkerLinks::mutate`, with the parameters as decoded.",
                                ),
                                (
                                    "4e0d31574e80d231d5809d0dae94a1f0a7e2c640d6570e482ff9044db1f425c4",
                                    "Passes the parameters' target (`typed.target`) whole to `WorkerLinks::mutate`, with the parameters as decoded.",
                                ),
                            ],
                        },
                        Item {
                            krate: "companion_tauri",
                            name: "macro:agent_prompt_command",
                            now: "absent",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "3c334f9ab3a45f01b1284ce4be1ee905eea4f79db2f81162cc45472eaee6d0e7",
                                    "Defines the prompt commands: a prompt that names a draft goes to `send_draft_prompt`, and any other passes the instance and the binding revision of the parameters' target to `WorkerLinks::mutate`.",
                                ),
                                (
                                    "3af18343051d40542388f3e1d2ccdf4b077bfc1ec8bf434dced5c44a07599f42",
                                    "Defines the prompt commands: a prompt that names a draft is refused on a host this device is paired with (`not_on_a_paired_host`) and otherwise goes to `send_draft_prompt`, and any other passes the parameters' target (`typed.target`) to `WorkerLinks::mutate`.",
                                ),
                            ],
                        },
                        Item {
                            krate: "kr_client",
                            name: "Session::submit_mutation",
                            now: "5b783c08dbeb48f64459628cc6e2e58e812077a8b2dea5652c27676a43425476",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "3faa988d114ab28bbce978621e83cfbba1a9887707cde7e52f16de916592e734",
                                    "Carries the method, the target and the parameters its caller gives; it sets neither an instance nor a revision of its own.",
                                ),
                                (
                                    "c06e8d70017e0bf49c8d45ab4b389ed3043b43a67e040710cfb34071ec3af53e",
                                    "Carries the method, the target and the parameters its caller gives; it sets neither an instance nor a revision of its own.",
                                ),
                                (
                                    "aa80e1cd1c33c7dfca71b46c7e7c32d737cad86b6a45bc7768fbd707491fe09f",
                                    "Carries the method, the target and the parameters its caller gives; it sets neither an instance nor a revision of its own.",
                                ),
                                (
                                    "4b48ce3de6d4399f8abc4a50944c2806f6d3d2d02f2174197bc0289894f0780d",
                                    "Carries the method, the target and the parameters its caller gives; it sets neither an instance nor a revision of its own.",
                                ),
                                (
                                    "a7d578ea7411fd93c506496f2b1fff3a0c5c566a6e4d53aa4e88e6f69b4c744f",
                                    "Carries the method, the target and the parameters its caller gives; it sets neither an instance nor a revision of its own.",
                                ),
                                (
                                    "926546ee2a3fceb60f2a9bb11b0c463413fd37e6f93fa84586dd42124a856c51",
                                    "Carries the method, the target and the parameters its caller gives; it sets neither an instance nor a revision of its own.",
                                ),
                                (
                                    "5b783c08dbeb48f64459628cc6e2e58e812077a8b2dea5652c27676a43425476",
                                    "Carries the method, the target and the parameters its caller gives; it sets neither an instance nor a revision of its own.",
                                ),
                            ],
                        },
                        Item {
                            krate: "kr_client",
                            name: "Session::mutate",
                            now: "5eaf3a04295c63efc8a492a39bc17d296e1be2de0efd97767fbe87adabc5639b",
                            across: &[
                                (
                                    "ed80277d71a32e2c8eabee984c955222b8dc97f948c865e5ceb8b61fa5bb1d2a",
                                    "Carries the method, the target and the parameters its caller gives; it sets neither an instance nor a revision of its own.",
                                ),
                                (
                                    "83c5e513f0333cff8b268664280c5f749888735b387ed7428aa4b971b590c57f",
                                    "Carries the method, the target and the parameters its caller gives; it sets neither an instance nor a revision of its own.",
                                ),
                                (
                                    "5eaf3a04295c63efc8a492a39bc17d296e1be2de0efd97767fbe87adabc5639b",
                                    "Carries the method, the target and the parameters its caller gives; it sets neither an instance nor a revision of its own.",
                                ),
                            ],
                        },
                        Item {
                            krate: "kr_client",
                            name: "Session::compose",
                            now: "bc23617965c11b51c5aa2210d303101349d638ab69859a3dfbf83955ae89745e",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "56d29c65d9ffd1e0abd32f61302d651ad274904bf52701f764a80eb6b4e36767",
                                    "Composes the request from the method, the target and the parameters its caller gives; it sets neither an instance nor a revision of its own.",
                                ),
                                (
                                    "bc23617965c11b51c5aa2210d303101349d638ab69859a3dfbf83955ae89745e",
                                    "Composes the request from the method, the target and the parameters its caller gives; it sets neither an instance nor a revision of its own.",
                                ),
                            ],
                        },
                        Item {
                            krate: "kr_client",
                            name: "Session::repeat",
                            now: "56293ad6993533ee0658dd74b37b2f30692d0d8e0547c0e440aa0266b28f4284",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "28727174f221b440680669f35ebdb1c40525d5ce64ff6003cbc8605c1f5fbe40",
                                    "Sends a composed request again as it was; the instance and the revision are those it was composed with.",
                                ),
                                (
                                    "56293ad6993533ee0658dd74b37b2f30692d0d8e0547c0e440aa0266b28f4284",
                                    "Sends a composed request again as it was; the instance and the revision are those it was composed with.",
                                ),
                            ],
                        },
                        Item {
                            krate: "kr_client",
                            name: "Session::submit_composed",
                            now: "b5ab18b349500774635cd9ed26228f8c924e5d35b291b8b64c2d4e5986162199",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "3d743109300e8912a896926f064b5ad792cf014ea6a1c4e928539930c53feff9",
                                    "Submits a composed request as it was composed; the instance and the revision are those it was composed with.",
                                ),
                                (
                                    "04fe0ffbb55fa86f200088ec9591cca911054fd9efb3b83c900c8a329fa23e82",
                                    "Submits a composed request as it was composed; the instance and the revision are those it was composed with.",
                                ),
                                (
                                    "ae5698668059da4ae97eef38d7dc5de13a8c2626473a1ad54de9488c774415d2",
                                    "Submits a composed request as it was composed; the instance and the revision are those it was composed with.",
                                ),
                                (
                                    "05e4eef5650f578de8d90d6d727a7edd49fa7de444549183b5ef8c0ac84b96e4",
                                    "Submits a composed request as it was composed; the instance and the revision are those it was composed with.",
                                ),
                                (
                                    "b5ab18b349500774635cd9ed26228f8c924e5d35b291b8b64c2d4e5986162199",
                                    "Submits a composed request as it was composed; the instance and the revision are those it was composed with.",
                                ),
                            ],
                        },
                    ],
                },
            },
            Sender {
                class: "a device's mutation relayed by the daemon",
                sends: "The daemon copies a device's decoded mutation to the worker's link and constructs none: it reads and changes neither the application instance nor the binding revision of the envelope, so a device's envelope reaches the worker as the device built it.",
                evidence: Evidence::Relays {
                    items: &[
                        Item {
                            krate: "kr_ipc",
                            name: "Client::forward",
                            now: "c7b0447079478e6bc8412f9ad9525658b7196b79b6437502d5364d61ec9bef58",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "de4a469a20b31559e83e484cca30624cccaa59051cdd448aee5a18ee65252c18",
                                    "Copies the mutation it is given to the worker's link with the caller's actor; it reads and changes neither the instance nor the revision.",
                                ),
                                (
                                    "2e78dcff9e57186cf55ed8e5711ccc5696d401ddbf069fd4229a8b2e25d02176",
                                    "Copies the mutation it is given to the worker's link with the caller's actor; it reads and changes neither the instance nor the revision.",
                                ),
                                (
                                    "c7b0447079478e6bc8412f9ad9525658b7196b79b6437502d5364d61ec9bef58",
                                    "Copies the mutation it is given to the worker's link with the caller's actor; it reads and changes neither the instance nor the revision.",
                                ),
                            ],
                        },
                        Item {
                            krate: "kr_ipc",
                            name: "Client::forward_for",
                            now: "8a2f9c6b03a6ba6537c3e3b7b9f82ecce3ac888c9e3dd3bd88c03b446c1406f3",
                            across: &[
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                                (
                                    "91c5472c9a8e5b92bbc8e7ce732335e548f25d43e8128c53b8955174eced4b97",
                                    "Copies the mutation it is given to the worker's link with the caller's actor and rights; it reads and changes neither the instance nor the revision.",
                                ),
                                (
                                    "8a2f9c6b03a6ba6537c3e3b7b9f82ecce3ac888c9e3dd3bd88c03b446c1406f3",
                                    "Copies the mutation it is given to the worker's link with the caller's actor and rights; it reads and changes neither the instance nor the revision.",
                                ),
                            ],
                        },
                        Item {
                            krate: "kr_controller",
                            name: "WorkerProxy::forward_mutation",
                            now: "fe8973577dc71e9496fba7c7c5cd104b1f420511e203c26d8c0576e6f02ebf9f",
                            across: &[],
                        },
                        Item {
                            krate: "kr_controller",
                            name: "RemoteConnection::proxied_mutation",
                            now: "f8d3ed7f71784d2311f79d0b812aace9a5b683d22239d03ed6e1b6c3588e4e8a",
                            across: &[],
                        },
                    ],
                },
            },
            Sender {
                class: "the daemon's local prompt route",
                sends: "The daemon's route for a prompt a caller at this machine made forwards the caller's envelope and does not replace it (`Controller::local_prompt`): the worker sees the instance and the revision the caller named.",
                evidence: Evidence::Relays {
                    items: &[
                        Item {
                            krate: "kr_ipc",
                            name: "LocalClient::forward",
                            now: "absent",
                            across: &[
                                (
                                    "8759defa47fa479f91521c137d3b64a2990bff1bfa651c99d4fbf57d29231311",
                                    "Copies the mutation it is given to the worker's link with the caller's actor; it reads and changes neither the instance nor the revision.",
                                ),
                                (
                                    "4c874e2a2859eb217f3bf19e25f9371b077da733e3567465f13417ccb0d7d558",
                                    "Copies the mutation it is given to the worker's link with the caller's actor; it reads and changes neither the instance nor the revision.",
                                ),
                                (
                                    "7e0c625962b4fa57a83f46d5e8c587189c3a064723e5e224feee37df354936dc",
                                    "Copies the mutation it is given to the worker's link with the caller's actor; it reads and changes neither the instance nor the revision.",
                                ),
                                (
                                    "4351654b5326dae1c624ab990b44ff4464db14f0609ae08ff5ddce6366667605",
                                    "Copies the mutation it is given to the worker's link with the caller's actor; it reads and changes neither the instance nor the revision.",
                                ),
                                (
                                    "6cd176c13ca65aef63b5cc1f3a2967e90ba4ebd5256beee672d0d827a6554541",
                                    "Copies the mutation it is given to the worker's link with the caller's actor; it reads and changes neither the instance nor the revision.",
                                ),
                                (
                                    "absent",
                                    "The release has no item of this name, so nothing of it builds or carries a request.",
                                ),
                            ],
                        },
                        Item {
                            krate: "kr_controller",
                            name: "Controller::local_prompt",
                            now: "9ab8280153325de474140d0be35753a72530700850622051683f6ec238323474",
                            across: &[],
                        },
                        Item {
                            krate: "kr_controller",
                            name: "Controller::prompt_the_worker",
                            now: "579852de968acbad1d009b9c715b77cd0f0cc18915d68daed8a147ca1998cdec",
                            across: &[],
                        },
                        Item {
                            krate: "kr_controller",
                            name: "Controller::prompt_over_the_link",
                            now: "edc8f17fa1b1c14622e7a629ce116fbdb5d054aa9e41608677e062c74a5717b9",
                            across: &[],
                        },
                    ],
                },
            },
            Sender {
                class: "the workflow and voice routes",
                sends: "None of the six reaches a worker from these routes: `method_for` maps three voice actions to three of the six, but `voice_perform` answers `performed: false` for a method of a session's worker, `workflow_session_close` builds `SessionClose` only, with no instance and no revision, and `HostActions::execute` refuses the workflow actions that are none of its own.",
                evidence: Evidence::Builds {
                    items: &[
                        Item {
                            krate: "kr_controller",
                            name: "method_for",
                            now: "7b3f742e790e6956856d00e1d035b35aa3c77b93084540469623d9fe2ce07224",
                            across: &[],
                        },
                        Item {
                            krate: "kr_controller",
                            name: "Controller::voice_perform",
                            now: "b2265c95d9f9a1204bad26fb056dc5f1d6c6b4c819fde03524634bf07402d082",
                            across: &[],
                        },
                        Item {
                            krate: "kr_controller",
                            name: "Controller::workflow_session_close",
                            now: "67fbceb374b47ffe275c61700212072141e6868893530d8b8516022c52a02d4f",
                            across: &[],
                        },
                        Item {
                            krate: "kr_controller",
                            name: "HostActions::execute",
                            now: "66f8dc0a4cf8aa25fe14e4a08319e661586ddc00316691002a63bbb17dcd43ec",
                            across: &[],
                        },
                    ],
                },
            },
            Sender {
                class: "kr",
                sends: "`kr bridge --stdio` carries a decoded frame to the destination and back and constructs none; the instance and the revision are the invoker's. The builders of `kr`'s own commands are accounts, because no text of `kr_cli` names one of the six.",
                evidence: Evidence::Relays {
                    items: &[Item {
                        krate: "kr_cli",
                        name: "relay",
                        now: "d8a251af1cc2bb3413b78bd9568823a324ca6965d30bf78e2314250dc4a5e2dc",
                        across: &[
                            (
                                "absent",
                                "The release has no item of this name, so nothing of it builds or carries a request.",
                            ),
                            (
                                "624fba2197423744ffab1ad413c8d45d8ef76ae6e9288a1aa5765455af07ea8c",
                                "Carries frames between the invoker and the destination as they come; it builds no request and reads neither the instance nor the revision.",
                            ),
                            (
                                "8ad4625a01181e728e0ac5df253995503ca5a5c6e321f5b50f4db24dc52e406d",
                                "Carries frames between the invoker and the destination as they come; it builds no request and reads neither the instance nor the revision.",
                            ),
                            (
                                "d8a251af1cc2bb3413b78bd9568823a324ca6965d30bf78e2314250dc4a5e2dc",
                                "Carries frames between the invoker and the destination as they come; it builds no request and reads neither the instance nor the revision.",
                            ),
                        ],
                    }],
                },
            },
            Sender {
                class: "kr-hook",
                sends: "The hook's channel relay carries a Channels frame to the registration's launch endpoint and no mutation on the control endpoint, so it sends none of the six.",
                evidence: Evidence::SendsNone {
                    crates: &["kr_hook"],
                },
            },
            Sender {
                class: "the plugin host, the plugin runtime and the automation engine",
                sends: "The plugin host and the plugin runtime hold no sighting of a method, request or target at any release; the automation engine's one sighting names a method only to read a recorded answer (an account).",
                evidence: Evidence::SendsNone {
                    crates: &["kr_plugin_host", "kr_plugin_runtime"],
                },
            },
        ],
        accounts: &[
            Account {
                krate: "companion_tauri",
                name: "Subject::target",
                kinds: &[SightKind::Target],
                now: "2a5cdd6c9fc7ed2ddafad4851a6dda9a93554332fa0eeb0fce7974348708f85a",
                why: "Builds the target of a command that names a subject (sessions, shares, pairing), and sets the instance and the binding revision only when the page names them; none of the six takes a subject, because their commands take the target from their parameters.",
            },
            Account {
                krate: "kr_cli",
                name: "mutate",
                kinds: &[SightKind::Target],
                now: "22c676faa91324edfe10c4dc79b20e47f58edd5cc76428d15946a90308f6b4bc",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "run",
                kinds: &[SightKind::Target],
                now: "dac77ba41d7407f8f4f143f23743def2f9fcc68922118dbf10d2e96f9c72118a",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers, a bridge or the desktop checks; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "send_geometry",
                kinds: &[SightKind::Request],
                now: "absent",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "session_target",
                kinds: &[SightKind::Target],
                now: "295e034deba2e562caf4b43e55ef7b144f5a5e551f994a814f69b8457884b918",
                why: "Builds the target of a session command with `application_instance_id` and `agent_binding_revision` null.",
            },
            Account {
                krate: "kr_cli",
                name: "target",
                kinds: &[SightKind::Target],
                now: "363f8ad6a761b09ff92c976b64b346325c4a5babd46e96510f394f9653c39c37",
                why: "Builds the target of a session command with `application_instance_id` and `agent_binding_revision` null.",
            },
            Account {
                krate: "kr_ipc",
                name: "LocalClient::compose",
                kinds: &[SightKind::Request],
                now: "absent",
                why: "Carries a request its caller composed over the daemon's own socket; it sets no application instance and names none of the six, and the daemon's relays of the six are the rows above.",
            },
            Account {
                krate: "kr_ipc",
                name: "LocalClient::mutate",
                kinds: &[SightKind::Request],
                now: "absent",
                why: "Carries a request its caller composed over the daemon's own socket; it sets no application instance and names none of the six, and the daemon's relays of the six are the rows above.",
            },
            Account {
                krate: "kr_ipc",
                name: "LocalClient::repeat",
                kinds: &[SightKind::Request],
                now: "absent",
                why: "Carries a request its caller composed over the daemon's own socket; it sets no application instance and names none of the six, and the daemon's relays of the six are the rows above.",
            },
            Account {
                krate: "kr_plugin_sdk",
                name: "a_catalogue_result_cannot_claim_a_host_outcome",
                kinds: &[SightKind::Unread],
                now: "7d2aa606aca64c46e22115712b715e8569ca3ecde414d89d7e88bcbed45ddbb5",
                why: "Test or example code of the plugin SDK that names a method on no report of any build; it builds no request for a worker.",
            },
            Account {
                krate: "kr_plugin_sdk",
                name: "evidence",
                kinds: &[SightKind::Unread],
                now: "77ce8974a691ec06d00454ea5c6405acaf9547df29b826cbc19c8ae88a8a63ed",
                why: "Test or example code of the plugin SDK that names a method on no report of any build; it builds no request for a worker.",
            },
            Account {
                krate: "kr_project",
                name: "protect_stored_result",
                kinds: &[SightKind::Names],
                now: "4a13cc586f03fb32651094be9d150a59f815bb50cc998c10a1d5cdae88d861ee",
                why: "Maps a method's wire name to the type of its stored answer for the methods of one crate and refuses every other; it builds no request.",
            },
            Account {
                krate: "kr_shell_integration",
                name: "is_root_method_name",
                kinds: &[SightKind::Names],
                now: "4c71de739642e98ea288364e3a2b7d940ca3847ca5f991bbc6d43dea65fcc37f",
                why: "Tells whether a method is a root method of the shell integration, or lists them; it builds no request.",
            },
            Account {
                krate: "kr_shell_integration",
                name: "root_methods",
                kinds: &[SightKind::Names],
                now: "absent",
                why: "Tells whether a method is a root method of the shell integration, or lists them; it builds no request.",
            },
            Account {
                krate: "kr_transfer",
                name: "ChunkChannel::send_chunk",
                kinds: &[SightKind::Request],
                now: "68b85383cbade60192febf33750a5af9c856ee70de90859c0afd8698c5abbf6e",
                why: "Sends a chunk of a transfer; it builds a chunk's request with no application instance.",
            },
            Account {
                krate: "kr_transport",
                name: "PairingMethod::from_name",
                kinds: &[SightKind::Names],
                now: "204ba194258948c005045bf9dd680122231a88170d66d95a70b3b182dfa00f19",
                why: "Maps a wire name to a pairing method; only the three pairing methods match, and it builds no request.",
            },
            Account {
                krate: "kr_changeset",
                name: "protect_stored_result",
                kinds: &[SightKind::Names],
                now: "d8f44760a47be34117062c2118d7bbd90d2f2f9d8ddcc92a41b76386711cc22e",
                why: "Maps a method's wire name to the type of its stored answer for the methods of one crate and refuses every other; it builds no request.",
            },
            Account {
                krate: "kr_cli",
                name: "crosses_again",
                kinds: &[SightKind::Names, SightKind::Request],
                now: "03493fbe79142a73da276889ed72ce98fce90e488efac1d55b7327c63473b46c",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "enrol",
                kinds: &[SightKind::Target],
                now: "3565904c2f178f5ea7716669b4192b85f45b56c8dfe9fc35cb3e76877917640a",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "forget",
                kinds: &[SightKind::Target],
                now: "1d753bba2da86cb8b9318366e9bf333ebef0a5b8578c539d0323af3672f300f3",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "refresh",
                kinds: &[SightKind::Target],
                now: "94d2709dc251fb231725a78e8931513b1dcd73f08b0ccd73ea77f46e708b73d3",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_automation",
                name: "AutomationService::answered",
                kinds: &[SightKind::Names],
                now: "86cd4fb0e035b4d37563c76f3cd65276696b1e7b5e5ae23c0bb412a62deaaa1c",
                why: "Reads a recorded action's method from its wire name to give back the stored answer of a workflow action; it has arms for the workflow methods only, refuses every other, and builds no request.",
            },
            Account {
                krate: "kr_cli",
                name: "Daemon::mutate",
                kinds: &[SightKind::Target],
                now: "24fc9ef51835d2a02ca46eaab434937fcbb9f37bf97d080bc251a89fbd9c8e43",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "Workers::knowing",
                kinds: &[SightKind::Target],
                now: "492f69fa88261edb874a00e3e45584f95bc900d0975c741530871d65dcb9d6cb",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "approve",
                kinds: &[SightKind::Target],
                now: "ea6ff2765b29836473be22b662318c820a7e5945039c2a3a2a9a4fa8548c6a95",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "cancel",
                kinds: &[SightKind::Target],
                now: "756ccbfb6f390cd99f220c05bfb625b56d831125aebc9b384c84e18695c838d5",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "invite",
                kinds: &[SightKind::Target],
                now: "ee2139952acc3736f4e3004925b945e7698ada98f13859d453caf3ad769f226c",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_client",
                name: "SessionChannel::complete",
                kinds: &[SightKind::Target],
                now: "074f25e7a6f5ffb9386a346e7efb29fafe2c3296a23958bf360a3b4908ac776e",
                why: "Carries or tags a request its caller made (the attempt, the lease, the chunk lane, the receipts); it sets no application instance and names none of the six.",
            },
            Account {
                krate: "companion_tauri",
                name: "View::mutation",
                kinds: &[SightKind::Request],
                now: "832dd037f4a1fc81e604fd9e1f8b661ba576d8e8f31a61c1709b54f6bbe58dbc",
                why: "Builds the request of a terminal command from the method and target its caller passes; no text of the terminal names one of the six.",
            },
            Account {
                krate: "kr_client",
                name: "ChunkLane::send_chunk",
                kinds: &[SightKind::Request],
                now: "78c8bcc0cebf38e238b2153b102299c0864a298271708d4fd2657da826cc0d7a",
                why: "Carries or tags a request its caller made (the attempt, the lease, the chunk lane, the receipts); it sets no application instance and names none of the six.",
            },
            Account {
                krate: "kr_cli",
                name: "ask",
                kinds: &[SightKind::Request, SightKind::Target],
                now: "2d42b96c0ba2078c27d9e102e123d76a4834ab9f3aa1ef639af9eb920b7ea46c",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "resume_holder",
                kinds: &[SightKind::Target],
                now: "ca45f0a43dc1fdd2fc6ddbeea31cf7fe4f5b32bda241a364279f01a69cd2bdc7",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_plugin_catalogue",
                name: "file:bundled-plugins/targets/packages/kalareach/claude-code/0.4.0/fixtures/conformance.json",
                kinds: &[SightKind::Unread],
                now: "absent",
                why: "A file of a bundled plugin that holds a wire name as data; it is no code and builds no request.",
            },
            Account {
                krate: "kr_plugin_catalogue",
                name: "file:bundled-plugins/targets/packages/kalareach/claude-code/0.4.0/presentation.json",
                kinds: &[SightKind::Unread],
                now: "absent",
                why: "A file of a bundled plugin that holds a wire name as data; it is no code and builds no request.",
            },
            Account {
                krate: "kr_plugin_catalogue",
                name: "file:bundled-plugins/targets/packages/kalareach/codex/0.2.1/fixtures/conformance.json",
                kinds: &[SightKind::Unread],
                now: "4c7ed97c5201b381be0864e4a2113fd61cc7c6dafada121f07caedbce5c535c0",
                why: "A file of a bundled plugin that holds a wire name as data; it is no code and builds no request.",
            },
            Account {
                krate: "kr_plugin_catalogue",
                name: "file:bundled-plugins/targets/packages/kalareach/gemini-cli/0.4.0/fixtures/conformance.json",
                kinds: &[SightKind::Unread],
                now: "absent",
                why: "A file of a bundled plugin that holds a wire name as data; it is no code and builds no request.",
            },
            Account {
                krate: "kr_cli",
                name: "Reached::compose",
                kinds: &[SightKind::Request, SightKind::Target],
                now: "ca2781441ef0dad130aeac0118b1d3f7f5b7ffad721606b56524687fca143c7e",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "Reached::send",
                kinds: &[SightKind::Request],
                now: "a1e9eaa32026b798e7c422fe17b9398392ae4e3f549de26ce1db171c8c56b525",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "Attaching::target",
                kinds: &[SightKind::Target],
                now: "65639ae514963f5e1e62de5e7667b667ef09dbbcba1632170d74d4046fcc1ecd",
                why: "Builds the target of a session command with `application_instance_id` and `agent_binding_revision` null.",
            },
            Account {
                krate: "kr_cli",
                name: "BridgedLink::mutate",
                kinds: &[SightKind::Request],
                now: "4bbc25666df0bfd79451ac52e15d3ac9407ebc63ddbb39f07d66d6f2595bfbc1",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "create_over",
                kinds: &[SightKind::Target],
                now: "ae7c137a4a8b028162899812d8d7c2a4aa310f16c3e45383b89cdae2fea28bb9",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "establish_clock",
                kinds: &[SightKind::Target],
                now: "9ccb97320aaaa91dd1c6f6a7096d31a6983dff205421472aa69eb05102d8cad5",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "Host::answer",
                kinds: &[SightKind::Target],
                now: "ac03ed7f9495a179f0a883edf944adb2d06522004b85e657200ab1efcc5e1e1a",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "answer",
                kinds: &[SightKind::Target],
                now: "0b92cc06a20bac8c3afcd05eb4b32f8440b06ba233defba6b6a55fe223ba75b8",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "dismiss",
                kinds: &[SightKind::Target],
                now: "e4a0d6d40fc14ff7b08ee5bb5845d750af588a10bca106a273a33e6a3074dfa8",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "send",
                kinds: &[SightKind::Target],
                now: "8d39829b399d5aa3f9b8d102235b17c2f934bff7d580058c42b57ad3236b2907",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "settle",
                kinds: &[SightKind::Target],
                now: "ce8471e116debb3b1eb8ad45fdebc9e6bf875a8c39a7da1bbf168ae04a0ffaa2",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal), or closes a file dialog and builds no request; its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "target_of",
                kinds: &[SightKind::Target],
                now: "f48a4f74fdac8004ab63cf3f470ea54c8e60e34174b19441b404f7eb6efae1f1",
                why: "Builds the target of a question's request with `application_instance_id` and `agent_binding_revision` null.",
            },
            Account {
                krate: "companion_tauri",
                name: "target_on",
                kinds: &[SightKind::Target],
                now: "42993e98462758c73bf4bcb5ddc776a316fcf7b2689bb43a98f8a1e2454beeeb",
                why: "Builds the target of a question's request with `application_instance_id` and `agent_binding_revision` null.",
            },
            Account {
                krate: "kr_cli",
                name: "end_exclusive_management",
                kinds: &[SightKind::Target],
                now: "7baafce73d9ff02ec132f979c90a9c06d9e7c868359023dd06d47a4eef1ac609",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "About::of",
                kinds: &[SightKind::Request],
                now: "6401a1fd8aaab2a87e0fabdf0b74d118ce69411aba0b144027485822b93c33f3",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "Carry::begin",
                kinds: &[SightKind::Request],
                now: "d2411e0b14c4f54b2cd07e5cbd8a1198541265cc2609c236f098a109f7dd1ea5",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "Carry::carry_on",
                kinds: &[SightKind::Request],
                now: "75599030747731828e388aa7219364335beea27b9ae1afb305d676246091746b",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "Wire::mutation",
                kinds: &[SightKind::Request],
                now: "2585ce7280cf0dff3ad6464fee98e1dcbfb22d9f84f97997529e6c5f2a8f18ef",
                why: "Builds the request of a terminal command from the method and target its caller passes; no text of the terminal names one of the six.",
            },
            Account {
                krate: "companion_tauri",
                name: "ask_the_host",
                kinds: &[SightKind::Request],
                now: "82d63877a2f72b6a511f9eeef2d06d04618254d614a55f88b907a351a7bf0818",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "create",
                kinds: &[SightKind::Target],
                now: "05bd5c5d36c5f1650f83e7af7b577426c50c70dfe14e4e1414f3b1bbcd6e72a3",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "includes_live_screen",
                kinds: &[SightKind::Request],
                now: "f3fb1f8755d388782a57a4a3107972639dea7f73dc06752149d8a879d175a996",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "open_paired",
                kinds: &[SightKind::Target],
                now: "ee488f0528df26feca09a766a2fd979d38714ff67d0c05390d04495d38b953cc",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "redeem",
                kinds: &[SightKind::Target],
                now: "46ffedb591f57df71196f1ae9232b5a6c49d9aa3f2d194e07146fb04613f0d86",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "revoke",
                kinds: &[SightKind::Target],
                now: "1d0f30f0fdceb71056aad2d50895f3834b15972e8846bfbef0ad84aa57c767b7",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "transfer_ask",
                kinds: &[SightKind::Target],
                now: "8d2adff2b05967ae9a0a49fee60a0eb6aa75551bdc04fe1e36786b8dc2933caf",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "Host::on_the_host",
                kinds: &[SightKind::Target],
                now: "2bcb016e351adb4ff6fffea8e0d3f9f84fa154ce446b6239e2fc1e08d7686cf0",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_client",
                name: "Attempt::confirmed_after",
                kinds: &[SightKind::Request],
                now: "e3fe020cc361a1ba9579bbd709a08d2e950819c0af2a43aa3ce9db0213b4076c",
                why: "Carries or tags a request its caller made (the attempt, the lease, the chunk lane, the receipts); it sets no application instance and names none of the six.",
            },
            Account {
                krate: "kr_client",
                name: "Attempt::gate",
                kinds: &[SightKind::Request],
                now: "b6123e5d11cad8e0ef5ce247509a43255f345c9e78bb492714cbc349f0dcb376",
                why: "Carries or tags a request its caller made (the attempt, the lease, the chunk lane, the receipts); it sets no application instance and names none of the six.",
            },
            Account {
                krate: "kr_client",
                name: "Attempt::is_the_plan",
                kinds: &[SightKind::Request, SightKind::Target],
                now: "323f4fbda09b41f81e5d25dc29371747de274aa3c95fed4d04f2756efe6443d3",
                why: "Carries or tags a request its caller made (the attempt, the lease, the chunk lane, the receipts); it sets no application instance and names none of the six.",
            },
            Account {
                krate: "kr_client",
                name: "ComposedMutation::action_id",
                kinds: &[SightKind::Request],
                now: "35db92a6781fc60378d2fcb64c60bd3c0015855e9bd6fd5530c1bf6d63b26e92",
                why: "Carries or tags a request its caller made (the attempt, the lease, the chunk lane, the receipts); it sets no application instance and names none of the six.",
            },
            Account {
                krate: "kr_ipc",
                name: "Client::compose",
                kinds: &[SightKind::Request],
                now: "b4a2ae848778b64195420e15ffe24cc6ced0ac83251fda7cc97adc11fed616ac",
                why: "Carries a request its caller composed over the daemon's own socket; it sets no application instance and names none of the six, and the daemon's relays of the six are the rows above.",
            },
            Account {
                krate: "kr_ipc",
                name: "Client::mutate",
                kinds: &[SightKind::Request],
                now: "95cf8734f4c956bef7831b6ead8484be925e572b5180879bb9eed2a24b30a216",
                why: "Carries a request its caller composed over the daemon's own socket; it sets no application instance and names none of the six, and the daemon's relays of the six are the rows above.",
            },
            Account {
                krate: "kr_ipc",
                name: "Client::repeat",
                kinds: &[SightKind::Request],
                now: "9807e7777891d3fac4a76335bda46bd6248c5fd9674adca09a36708b0cdb024f",
                why: "Carries a request its caller composed over the daemon's own socket; it sets no application instance and names none of the six, and the daemon's relays of the six are the rows above.",
            },
            Account {
                krate: "companion_tauri",
                name: "Revocations::revoke_direct",
                kinds: &[SightKind::Target],
                now: "bc06b8158a82ecef2514ae4e46f609f390ba37cba06d877154595df9267f2e95",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "kr_client",
                name: "SessionHost::enable",
                kinds: &[SightKind::Target],
                now: "2506dcaa0db07834950c5593f2221af68a5dd278ff929e357ccaf734239e9e0d",
                why: "Carries or tags a request its caller made (the attempt, the lease, the chunk lane, the receipts); it sets no application instance and names none of the six.",
            },
            Account {
                krate: "companion_tauri",
                name: "Binding::gate",
                kinds: &[SightKind::Request],
                now: "e1bf702cb44368cc63f6e81cc9b58f3281782cd7c5851e78e77301effc787a91",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "ConnectionLine::register",
                kinds: &[SightKind::Target],
                now: "911548d832d6f52adafeb1d7552388cb8343c4f3bf925d61c12ebc5697a49167",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "ConnectionLine::update_preview_key",
                kinds: &[SightKind::Target],
                now: "aac20f219ce510f78be3f9039a2f00696cbd33daba5ce25ca17e67c96b8f3300",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "kr_client",
                name: "LeaseKeeper::step",
                kinds: &[SightKind::Target],
                now: "daa0a0e893ca584ba2493ab7e7778b9d71fc7e2d5488187dc24ab4abe38f4a68",
                why: "Carries or tags a request its caller made (the attempt, the lease, the chunk lane, the receipts); it sets no application instance and names none of the six.",
            },
            Account {
                krate: "kr_plugin_catalogue",
                name: "file:bundled-plugins/targets/packages/kalareach/claude-code/0.5.0/fixtures/conformance.json",
                kinds: &[SightKind::Unread],
                now: "2dae4c0cf28d5cb2e3bb1cfc802a090df11f93d64701412cd1c0851fbf15b7e7",
                why: "A file of a bundled plugin that holds a wire name as data; it is no code and builds no request.",
            },
            Account {
                krate: "kr_plugin_catalogue",
                name: "file:bundled-plugins/targets/packages/kalareach/claude-code/0.5.0/presentation.json",
                kinds: &[SightKind::Unread],
                now: "9a38ac71cc38b8554e3d8985cc71692d190fffc2383ed6854b82792b146f2848",
                why: "A file of a bundled plugin that holds a wire name as data; it is no code and builds no request.",
            },
            Account {
                krate: "kr_plugin_catalogue",
                name: "file:bundled-plugins/targets/packages/kalareach/gemini-cli/0.5.0/fixtures/conformance.json",
                kinds: &[SightKind::Unread],
                now: "ea52b067d37aa0f3acf6fa42be8a065d69ea7a3ebb269da83dec2c6b4069fa6f",
                why: "A file of a bundled plugin that holds a wire name as data; it is no code and builds no request.",
            },
            Account {
                krate: "companion_tauri",
                name: "Deletions::finish",
                kinds: &[SightKind::Target],
                now: "732e35bbce686b8294006b0bb6ea7c48b9977fa7b4236799a227d8daac6c7767",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "a_share_with_no_view_of_the_session_is_listed_with_its_rights",
                kinds: &[SightKind::Unread],
                now: "7e414240de94c57997fd578b0f3b0d2131aa807d3ad59499434b77ea48670ae8",
                why: "A test body of `kr_cli` that names a method on no report of any build; it builds no request for a worker.",
            },
            Account {
                krate: "companion_tauri",
                name: "Challenge::sent",
                kinds: &[SightKind::Request],
                now: "3e0c112f46899bd344f1fddabd2822c7e383bd1080693d6b3e6e135a97f430dd",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "hand_over",
                kinds: &[SightKind::Target],
                now: "2187850a80a0d1f18aca9e8e2e6e2f790c055044d8c56b53132b5b33e7166190",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "Daemon::mutate_within",
                kinds: &[SightKind::Target],
                now: "4eca210fdeb45753772d9c12a94dd4d3fb519c89d2ece50d72bba3ee7928a8e5",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "Workers::answer",
                kinds: &[SightKind::Request],
                now: "f0c295979862596e5437f8e4ea557fd7c443737904a504f1d3431741be4a55b5",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "mutate_naming",
                kinds: &[SightKind::Request],
                now: "8cefde1aca77c91466df27ada8524311778096dc15da43d9b9a8e67d8177ca62",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_cli",
                name: "send_mutation",
                kinds: &[SightKind::Request],
                now: "682cfb8fd4a9dc331a21296f419bfd7c7e3f8e9d1d0432be1c2b1c89935e6a3f",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "kr_client",
                name: "NetworkCarrier::exchange",
                kinds: &[SightKind::Request],
                now: "705b70dff3abe16e4e445408aa7f3095002e20f3ac0b1087fcf0640efc437dea",
                why: "Carries or tags a request its caller made (the attempt, the lease, the chunk lane, the receipts); it sets no application instance and names none of the six.",
            },
            Account {
                krate: "kr_client",
                name: "Outcomes::sent_before",
                kinds: &[SightKind::Request],
                now: "b78478b9b840f146704a4e39d141f31fb97c6b814b12cbf26d4ad151bf6050b3",
                why: "Carries or tags a request its caller made (the attempt, the lease, the chunk lane, the receipts); it sets no application instance and names none of the six.",
            },
            Account {
                krate: "kr_ipc",
                name: "Client::mutate_within",
                kinds: &[SightKind::Request],
                now: "923bccb2850eabf1c828373559f0a2e6b8558c60a8842c88dbf34bc693b7bbf4",
                why: "Carries a request its caller composed over the daemon's own socket; it sets no application instance and names none of the six, and the daemon's relays of the six are the rows above.",
            },
            Account {
                krate: "kr_cli",
                name: "Daemon::mutate_unconfirmable",
                kinds: &[SightKind::Target],
                now: "7ab9b8acb48985e667709d2349984da7c4efbdb291160eb1a6af5f2626c0b2b9",
                why: "Builds or carries the request of a `kr` command for sessions, grants, shares, pairing, transfers or a bridge; no text of `kr_cli` names one of the six, and none sets an application instance.",
            },
            Account {
                krate: "companion_tauri",
                name: "Desk::restart",
                kinds: &[SightKind::Target],
                now: "6b1c9cd6d343d01c079ca833fbf6f4c76c0907d838c85d616c6af7269cf5187a",
                why: "Builds or tags the request of a command that is none of the six (sessions, questions, pairing, sharing, transfers, the terminal); its text names none of the six and sets no application instance.",
            },
        ],
    },
];
