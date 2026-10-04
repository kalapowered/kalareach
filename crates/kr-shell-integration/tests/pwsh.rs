//! The qualified PSReadLine package, driven through the installed host in a real pseudo-terminal.
//!
//! Section 7 puts a reader-thread request queue and a signal behind this package rather than a
//! patched shell: PSReadLine is the editor the person already has, and the module binds into it.
//! The queue is answered on the reader's own thread, with the editor's real buffer and invocation
//! state, and the end-of-file decision is taken there too, under the configured gesture. Each test
//! below drives one of those through the host the qualification recorded, against the expectations
//! in `fixtures/shell-bridge/`.
//!
//! The cases that drive the package need this tree's qualified package, which an ordinary run does
//! not have, so they are left out of one. A run that published the qualification runs them with
//! `--include-ignored`, as continuous integration's shell-packages job does, and there a package
//! that is not this tree's fails the case that needed it.
//!
//! Running the module on Windows is qualified separately, with the host's own named pipe and the
//! configured chord; this file drives the Unix host, where the harness speaks over a Unix socket.

#![cfg(unix)]

mod shellpkg;

use kr_shell_integration::contract::qualification::ShellKind;

const PWSH: ShellKind = ShellKind::PowerShell;

/// KR-REQ-07.37, KR-REQ-07.85
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn the_handshake_declares_the_qualified_editor_and_the_module_tree_it_binds_into() {
    shellpkg::the_handshake_declares_the_packaged_reader(PWSH);
}

/// KR-REQ-07.37
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_child_of_the_managed_root_shell_inherits_no_activation() {
    shellpkg::a_child_shell_has_nothing_to_activate_from(PWSH);
}

/// KR-REQ-07.37
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn the_reader_reports_its_boundaries_and_proves_its_own_queues() {
    shellpkg::the_reader_reports_its_boundaries_and_proves_its_own_state(PWSH);
}

/// KR-REQ-07.37, KR-REQ-07.73
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn an_eligible_gesture_under_a_fence_becomes_an_attributable_detach() {
    shellpkg::an_eligible_gesture_under_a_fence_is_an_attributable_detach(PWSH);
}

/// KR-REQ-07.37, KR-REQ-07.73
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn an_unattributable_gesture_is_consumed_with_one_hint_per_prompt() {
    shellpkg::an_unattributable_gesture_is_consumed_with_one_hint_per_prompt(PWSH);
}

/// KR-REQ-07.37, KR-REQ-07.73
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_detach_the_worker_refuses_is_consumed_with_the_hint() {
    shellpkg::a_refused_detach_is_consumed_with_the_hint(PWSH);
}

/// KR-REQ-07.37, KR-REQ-07.73
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn outside_the_detach_condition_the_state_handler_keeps_the_key() {
    shellpkg::the_detach_condition_excludes_what_the_corpus_names(PWSH);
}

/// KR-REQ-07.37
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_launch_is_installed_and_accepted_on_the_reader_thread() {
    shellpkg::a_launch_is_installed_and_accepted_on_the_reader_thread(PWSH);
}

/// KR-REQ-07.37
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn the_reader_refuses_a_launch_its_own_state_does_not_match() {
    shellpkg::the_reader_refuses_a_launch_its_own_state_does_not_match(PWSH);
}

/// KR-REQ-07.37
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_revoked_launch_installs_nothing() {
    shellpkg::a_revoked_launch_installs_nothing(PWSH);
}

/// KR-REQ-07.37
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_revocation_in_the_same_read_binds_its_launch_whichever_order_it_arrives_in() {
    shellpkg::a_revocation_in_the_same_read_binds_the_launch(PWSH);
}

/// KR-REQ-07.37
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn the_reader_reports_itself_idle_so_a_withheld_fence_can_be_retried() {
    shellpkg::the_reader_reports_itself_idle(PWSH);
}

/// KR-REQ-07.37
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_shell_whose_bridge_has_gone_still_consumes_an_eligible_gesture() {
    shellpkg::a_lost_bridge_does_not_restore_a_native_empty_prompt_end_of_file(PWSH);
}

/// KR-REQ-07.37
///
/// This editor runs a nested read of its own for each operation that waits for another key, and
/// nothing of this package's runs on the reader's thread while one is running, so it has no key
/// wait a takeover or a cancellation can end. What a cancellation does to a reader with nothing in
/// progress is this case; the takeover case the other packages have is not one of this editor's.
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_cancellation_that_ends_nothing_leaves_the_next_sequence_alone() {
    shellpkg::a_cancellation_that_ends_nothing_leaves_the_next_sequence_alone(PWSH);
}

/// KR-REQ-07.37, KR-REQ-07.73, `psreadline-chord-gesture`
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn the_configured_chord_detaches_and_any_other_key_is_the_editors_own() {
    shellpkg::the_configured_chord_carries_the_detach_and_any_other_key_is_the_editors_own(PWSH);
}

/// KR-REQ-12.07, KR-REQ-07.45
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn an_interactive_command_asks_once_before_it_starts_and_a_bypass_runs_it_as_typed() {
    shellpkg::an_interactive_command_asks_once_and_runs_as_typed(PWSH);
}

/// KR-REQ-12.07
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_command_that_is_not_the_whole_of_its_line_never_asks_and_a_lone_native_command_does() {
    shellpkg::forms_the_root_shell_does_not_start_itself_never_ask(PWSH);
}

/// KR-REQ-12.07
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_path_as_the_name_runs_as_typed_and_asks_nothing() {
    shellpkg::an_absolute_path_invocation_runs_as_typed(PWSH);
}

/// KR-REQ-07.34, KR-REQ-07.35
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn frames_that_arrive_while_a_command_waits_reach_the_reader_once() {
    shellpkg::frames_that_arrive_while_a_command_waits_reach_the_reader_once(PWSH);
}

/// KR-REQ-12.07
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_worker_that_does_not_answer_leaves_the_command_as_typed_after_the_deadline() {
    shellpkg::an_unanswered_question_runs_the_command_as_typed_after_the_deadline(PWSH);
}

/// KR-REQ-12.07, KR-REQ-07.45
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_backend_runs_the_command_through_the_launcher_it_names() {
    shellpkg::a_backend_runs_the_command_through_the_launcher_it_names(PWSH);
}

/// KR-REQ-25.05
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn each_line_reports_its_command_block_with_status_duration_and_directory() {
    shellpkg::each_line_reports_its_block_with_status_duration_and_directory(PWSH);
}

/// KR-REQ-07.84
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_line_exports_the_capability_minted_for_it_and_no_other() {
    shellpkg::a_line_exports_the_capability_minted_for_it(PWSH);
}

/// KR-REQ-12.07
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn the_entry_points_answer_by_origin_and_never_fail() {
    shellpkg::the_entry_points_answer_by_origin_and_never_fail(PWSH);
}

/// KR-REQ-25.05
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_line_reports_the_status_the_shell_would_show() {
    shellpkg::a_line_reports_the_status_the_shell_would_show(PWSH);
}

/// KR-REQ-25.05
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_block_reports_the_file_system_directory() {
    shellpkg::a_block_reports_the_file_system_directory(PWSH);
}

/// KR-REQ-12.07, KR-REQ-25.05
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_launcher_leaves_its_exit_status_as_the_lines() {
    shellpkg::a_launcher_leaves_its_exit_status_as_the_lines(PWSH);
}

/// KR-REQ-07.84, KR-REQ-25.05
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_prompt_a_line_opens_keeps_the_lines_block_and_capability() {
    shellpkg::a_prompt_a_line_opens_keeps_the_lines_block_and_capability(PWSH);
}

/// KR-REQ-07.84
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_cancellation_during_an_unanswered_acceptance_leaves_the_prompt_working() {
    shellpkg::a_cancellation_during_an_unanswered_acceptance_leaves_the_prompt_working(PWSH);
}

/// The editors this suite stands in for the real one with: each is a .NET type with the two fields
/// the module reads its queue from, or something short of that.
///
/// `live` is what the qualified editor looks like from the module's side: a static instance whose
/// queue holds two keys. The others each leave out one thing a fence rests on, and each was
/// accepted by a check that only asked whether the two fields existed.
const STAND_IN_EDITORS: &str = r#"
using System.Collections.Generic;
public class KrEditorLive { private static KrEditorLive _singleton = new KrEditorLive(); private Queue<object> _queuedKeys = new Queue<object>(new object[] { 1, 2 }); }
public class KrEditorRenamed { private static KrEditorRenamed _singleton = new KrEditorRenamed(); private Queue<object> _pendingKeys = new Queue<object>(); }
public class KrEditorNoInstance { private static KrEditorNoInstance _singleton = null; private Queue<object> _queuedKeys = new Queue<object>(); }
public class KrEditorNoQueue { private static KrEditorNoQueue _singleton = new KrEditorNoQueue(); private Queue<object> _queuedKeys = null; }
public class KrEditorNotAQueue { private static KrEditorNotAQueue _singleton = new KrEditorNotAQueue(); private string _queuedKeys = "none"; }
"#;

/// KR-REQ-07.85: the package qualifies an editor only when the queue a fence rests on answers.
///
/// A check that the queue's two fields exist accepts an editor whose instance is not made yet,
/// whose queue is null or whose field holds something that is not a queue, and the reader would then
/// report every queue clear because it read nothing. The module reads the live queue instead, through
/// the function a fence reads it with. Each stand-in editor here is put in the module's place in
/// turn, and the control is the editor the package was qualified against, which the module read
/// before any of them was.
#[test]
#[ignore = "needs this tree's built shell packages; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_package_refuses_an_editor_whose_key_queue_it_cannot_read() {
    let package = shellpkg::Package::built(PWSH);
    let directory = package
        .executable
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the package directory");
    let module = directory
        .join("modules/KalaReach.ShellBridge/KalaReach.ShellBridge.psd1")
        .display()
        .to_string();
    let script = format!(
        "$ErrorActionPreference = 'Stop'; Import-Module '{module}'; \
         Add-Type -IgnoreWarnings -WarningAction SilentlyContinue -TypeDefinition @'{STAND_IN_EDITORS}'@; \
         $module = Get-Module KalaReach.ShellBridge; \
         $real = & $module {{ @{{ Reason = (Test-KrQualifiedEditor).Reason; Keys = Get-KrQueuedKeys }} }}; \
         Write-Output \"kr-queue[real]=[$($real.Reason)] keys=[$($real.Keys)]\"; \
         foreach ($name in 'KrEditorLive', 'KrEditorRenamed', 'KrEditorNoInstance', 'KrEditorNoQueue', 'KrEditorNotAQueue') {{ \
             $answer = & $module {{ param($editor) \
                 $script:SingletonField = $null; $script:QueuedKeysField = $null; $script:Rl = $editor; \
                 @{{ Reason = (Test-KrQualifiedEditor).Reason; Keys = Get-KrQueuedKeys }} }} ([type]$name); \
             Write-Output \"kr-queue[$name]=[$($answer.Reason)] keys=[$($answer.Keys)]\" \
         }}"
    );
    let asked = std::process::Command::new(&package.executable)
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .env_remove("KR_SHELL_BRIDGE")
        .env_remove("KR_SHELL_BRIDGE_SECRET")
        .env_remove("KR_SESSION")
        .output()
        .expect("the package's host runs");
    let said = String::from_utf8_lossy(&asked.stdout).into_owned();
    let told = String::from_utf8_lossy(&asked.stderr);
    let answer = |name: &str| -> (String, String) {
        let line = said
            .lines()
            .find_map(|line| line.strip_prefix(&format!("kr-queue[{name}]=[")))
            .unwrap_or_else(|| panic!("the module said nothing about {name}:\n{said}\n{told}"));
        let (reason, keys) = line.split_once("] keys=[").expect("the answer's shape");
        (reason.to_owned(), keys.trim_end_matches(']').to_owned())
    };

    assert_eq!(
        answer("real"),
        (String::new(), "0".to_owned()),
        "the editor the package was qualified against reads as an empty queue and is accepted"
    );
    assert_eq!(
        answer("KrEditorLive"),
        (String::new(), "2".to_owned()),
        "an editor whose queue answers is read for what it holds, not for whether it has fields"
    );
    for stand_in in [
        "KrEditorRenamed",
        "KrEditorNoInstance",
        "KrEditorNoQueue",
        "KrEditorNotAQueue",
    ] {
        assert_eq!(
            answer(stand_in),
            ("psreadline_queue_unreadable".to_owned(), "0".to_owned()),
            "{stand_in} keeps no queue the module can read, and the package qualified it anyway"
        );
    }
}

/// KR-REQ-07.85: what the module takes for the editor's own read-line function is decided against
/// the editor's own file, never against anything a profile that ran first could have changed.
///
/// Each case is a host of its own. The first function is the editor's as the module finds it, and
/// whether it is the editor's is asked of the text the editor's file defines it with. A person's
/// function put in its place inside the editor's module scope and exported before the module loads
/// is not the editor's, and is not made one by being what was there first; the editor imported
/// again puts the real one back, and that is. A function whose text differs from the editor's by a
/// character that is not seen, a soft hyphen, is not the editor's either: the comparison is
/// ordinal, where a culture-aware one passes it. The control is the editor itself.
#[test]
#[ignore = "needs this tree's built shell packages; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_editors_read_line_function_is_judged_against_the_editors_own_file() {
    let replace = r#"& (Get-Module PSReadLine) { Set-Item function:script:PSConsoleHostReadLine -Value { 'person' } };
           Import-Module PSReadLine;"#;
    let soft_hyphen = r#"$text = (Get-Module PSReadLine).ExportedFunctions['PSConsoleHostReadLine'].ScriptBlock.ToString();
           $at = $text.IndexOf('$lastRunStatus');
           if ($at -lt 0) { throw 'the editor keeps no $lastRunStatus to put a character before' };
           $text = $text.Insert($at, [string][char]0x00AD);
           & (Get-Module PSReadLine) { param($text) Set-Item function:script:PSConsoleHostReadLine -Value ([scriptblock]::Create($text)) } $text;
           Import-Module PSReadLine;"#;
    let package = shellpkg::Package::built(PWSH);
    let directory = package
        .executable
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the package directory");
    let module = directory
        .join("modules/KalaReach.ShellBridge/KalaReach.ShellBridge.psd1")
        .display()
        .to_string();
    let asked = |before: &str, after: &str| -> String {
        let script = format!(
            "$ErrorActionPreference = 'Stop'; Import-Module PSReadLine; {before} \
             Import-Module '{module}'; $module = Get-Module KalaReach.ShellBridge; \
             {after}"
        );
        let output = std::process::Command::new(&package.executable)
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .env_remove("KR_SHELL_BRIDGE")
            .env_remove("KR_SHELL_BRIDGE_SECRET")
            .env_remove("KR_SESSION")
            .output()
            .expect("the package's host runs");
        let said = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "the host ended with {:?}:\n{said}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        said
    };
    // Put in front of what is there, the way the module does when it loads, and ask whether what
    // it went in front of is the editor's.
    let inner = "& $module { Install-KrReadLineWrapper; Write-Output \"kr-key[inner]=[$(Test-KrInnerReadLine)]\" };";
    let current = "$f = (Get-Command PSConsoleHostReadLine -CommandType Function).ScriptBlock; \
         Write-Output \"kr-key[now]=[$(& $module { param($f) Test-KrEditorsReadLine $f } $f)]\"";

    let control = asked("", inner);
    assert_eq!(
        said(&control, "inner"),
        "True",
        "the editor itself is the editor's: {control}"
    );

    // Replaced before the module loads: what the module finds first is somebody else's.
    let replaced = asked(replace, inner);
    assert_eq!(
        said(&replaced, "inner"),
        "False",
        "a function put in the editor's place before the module loaded was taken for the editor's: {replaced}"
    );
    // The editor imported again puts the real function back, and the module goes in front of that.
    let restored = asked(
        replace,
        &format!(
            "{inner} Import-Module PSReadLine -Force; & $module {{ Install-KrReadLineWrapper; \
             Write-Output \"kr-key[again]=[$(Test-KrInnerReadLine)]\" }};"
        ),
    );
    assert_eq!(
        said(&restored, "again"),
        "True",
        "the editor's own function, put back, was refused: {restored}"
    );

    // A character nobody sees: the function the module went in front of was the editor's, and what
    // a profile puts in its place afterwards is not, whatever a culture-aware comparison says.
    let hyphen = asked("", &format!("{inner} {soft_hyphen} {current}"));
    assert_eq!(
        said(&hyphen, "now"),
        "False",
        "a function that differs from the editor's by a soft hyphen was taken for the editor's: {hyphen}"
    );
    // The control for it: the editor's own function, imported again, is still the editor's.
    let again = asked(
        "",
        &format!("{inner} Import-Module PSReadLine -Force; {current}"),
    );
    assert_eq!(
        said(&again, "now"),
        "True",
        "the editor imported again was refused: {again}"
    );
}

/// Runs a script in a host of its own with the package's module imported, and returns what it
/// printed.
///
/// The script is given the module as `$module`, and reaches the module's own functions through it.
/// The host is one the editor has no terminal for, so a script drives the module's binding
/// functions and reads the editor's own table back, which is all these cases need.
fn in_the_package_host(script: &str) -> String {
    let package = shellpkg::Package::built(PWSH);
    let directory = package
        .executable
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the package directory");
    let module = directory
        .join("modules/KalaReach.ShellBridge/KalaReach.ShellBridge.psd1")
        .display()
        .to_string();
    let script = format!(
        "$ErrorActionPreference = 'Stop'; Import-Module '{module}'; \
         $module = Get-Module KalaReach.ShellBridge; {script}"
    );
    let asked = std::process::Command::new(&package.executable)
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .env_remove("KR_SHELL_BRIDGE")
        .env_remove("KR_SHELL_BRIDGE_SECRET")
        .env_remove("KR_SESSION")
        .output()
        .expect("the package's host runs");
    let said = String::from_utf8_lossy(&asked.stdout).into_owned();
    let told = String::from_utf8_lossy(&asked.stderr);
    assert!(
        asked.status.success(),
        "the host ended with {:?}:\n{said}\n{told}",
        asked.status
    );
    said
}

/// Returns one line a script printed as `kr-key[name]=[value]`.
fn said(output: &str, name: &str) -> String {
    let prefix = format!("kr-key[{name}]=[");
    output
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("the script said nothing about {name}:\n{output}"))
        .strip_suffix(']')
        .expect("the line's shape")
        .to_owned()
}

/// KR-REQ-07.73: the module binds only a chord the editor stores under the spelling it was given,
/// so a key of the person's is never taken over by a chord that means the same key.
///
/// The editor keeps `Ctrl+Alt+?` under the plain question mark, which is how a terminal sends it:
/// the two are one key. A chord that spells a key differently from how the editor stores it would
/// bind the other key, and what was on that one would be replaced by an operation of the editor's
/// the module meant for a different chord. The person's own function on the plain question mark
/// keeps running through the module's wrapper for it, and the person's own script keeps its
/// descriptions. Each case is a host of its own, because what one binds is what the next reads.
#[test]
#[ignore = "needs this tree's built shell packages; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_chord_the_editor_spells_as_another_key_never_takes_that_key_over() {
    // A function of the editor's the person put on the plain question mark. The operation of the
    // same name on the spelled-out chord is processed after it, and would have replaced it.
    let function = in_the_package_host(
        r#"Set-PSReadLineKeyHandler -Chord '?' -Function AcceptAndGetNext;
           $null = & $module { Install-KrObservedHandlers };
           $held = Get-PSReadLineKeyHandler -Chord '?';
           Write-Output "kr-key[function]=[$($held.Description)]";
           $enter = Get-PSReadLineKeyHandler -Chord 'Enter';
           Write-Output "kr-key[control]=[$($enter.Description)]""#,
    );
    assert_eq!(
        said(&function, "function"),
        "KalaReach: AcceptAndGetNext",
        "the person's function on the plain question mark is what the module wrapped:\n{function}"
    );
    assert_eq!(
        said(&function, "control"),
        "KalaReach: AcceptLine",
        "a chord the editor stores as spelled is wrapped, so the check does not skip everything"
    );

    // A script of the person's, with descriptions of its own.
    let script = in_the_package_host(
        r#"Set-PSReadLineKeyHandler -Chord '?' -ScriptBlock { param($key, $arg) } `
               -BriefDescription 'theirs' -Description 'the person wrote this';
           $null = & $module { Install-KrObservedHandlers };
           $held = Get-PSReadLineKeyHandler -Chord '?';
           Write-Output "kr-key[script]=[$($held.Function)|$($held.Description)]""#,
    );
    assert_eq!(
        said(&script, "script"),
        "theirs|the person wrote this",
        "the person's script on the plain question mark kept its descriptions:\n{script}"
    );

    // The gesture's chord, which is bound by the module's own call and not by the loop.
    let gesture = in_the_package_host(
        r#"$answer = & $module { $script:Kr.GestureChord = 'Ctrl+Alt+?'; $script:Kr.GestureDisabled = $false; Install-KrGestureHandler };
           Write-Output "kr-key[unbindable]=[$($answer.Ok)|$($answer.Reason)]";
           $held = Get-PSReadLineKeyHandler -Chord '?';
           Write-Output "kr-key[question]=[$(@($held).Count)]";
           $answer = & $module { $script:Kr.GestureChord = 'Ctrl+d'; Install-KrGestureHandler };
           Write-Output "kr-key[bindable]=[$($answer.Ok)|$($answer.Reason)]";
           $held = Get-PSReadLineKeyHandler -Chord 'Ctrl+d';
           Write-Output "kr-key[detach]=[$($held.Description)]""#,
    );
    assert_eq!(
        said(&gesture, "unbindable"),
        "False|gesture_chord_unbindable",
        "a gesture chord the editor spells as another key is refused by name:\n{gesture}"
    );
    assert_eq!(
        said(&gesture, "question"),
        "0",
        "and the key it would have taken over is left unbound"
    );
    assert_eq!(
        said(&gesture, "bindable"),
        "True|",
        "a chord stored as spelled is bound"
    );
    assert_eq!(
        said(&gesture, "detach"),
        "KalaReach: detach at an empty root prompt"
    );
}

/// KR-REQ-07.85: the module can read how the editor spells a chord, or it is not the editor the
/// package was qualified against.
///
/// The spelling comes from the editor's own key type, so a stand-in editor that does not have it
/// answers nothing, and the control is the editor the package was qualified against.
#[test]
#[ignore = "needs this tree's built shell packages; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_module_reads_how_the_editor_spells_a_chord_and_refuses_one_that_does_not_say() {
    // The editor the package was qualified against is read first: what a case puts in the module's
    // place stays there for the rest of the host's run.
    let output = in_the_package_host(&format!(
        "Write-Output \"kr-key[real]=[$(& $module {{ Get-KrBoundSpelling 'Ctrl+Alt+?' }})]\"; \
         Write-Output \"kr-key[accepted]=[$(& $module {{ (Test-KrKeySpelling).Reason }})]\"; \
         Add-Type -IgnoreWarnings -WarningAction SilentlyContinue -TypeDefinition @'{STAND_IN_EDITORS}'@; \
         Write-Output \"kr-key[stand-in]=[$(& $module {{ param($editor) $script:Rl = $editor; Get-KrBoundSpelling 'Ctrl+d' }} ([type]'KrEditorLive'))]\"; \
         Write-Output \"kr-key[refused]=[$(& $module {{ (Test-KrKeySpelling).Reason }})]\""
    ));
    assert_eq!(
        said(&output, "real"),
        "?",
        "the editor says the spelled-out chord is the plain question mark:\n{output}"
    );
    assert_eq!(
        said(&output, "stand-in"),
        "",
        "a stand-in without the editor's key type says nothing"
    );
    assert_eq!(
        said(&output, "refused"),
        "psreadline_key_spelling_unreadable"
    );
    assert_eq!(
        said(&output, "accepted"),
        "",
        "the qualified editor is accepted"
    );
}

/// KR-REQ-07.23, KR-REQ-07.85: the read-line function the module goes in front of has to be the
/// editor's own, whoever defined what stood there before it, and what decides is whose function it is
/// and not what its text says.
///
/// A profile an administrator owns runs before the module loads, so a wrapper it defines is what the
/// module finds in front of the editor. One that calls the editor directly has the editor's call in
/// its text and is somebody else's reader all the same, and the module going around it would take a
/// tool's wrapper out of the host's path without a word. Each shape is a host of its own, because
/// the function is global and what one defines is what the next would find.
#[test]
#[ignore = "needs this tree's built shell packages; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_module_goes_in_front_of_the_editors_own_read_line_and_of_nothing_else() {
    let in_front_of = |definition: &str| {
        in_the_package_host(&format!(
            "{definition}; \
             Write-Output \"kr-key[inner]=[$(& $module {{ Install-KrReadLineWrapper; Test-KrInnerReadLine }})]\""
        ))
    };
    let own = in_front_of("$null = 1");
    assert_eq!(
        said(&own, "inner"),
        "True",
        "the editor's own function is what the module goes in front of:\n{own}"
    );
    let calls_the_editor = in_front_of(
        "function global:PSConsoleHostReadLine { [Microsoft.PowerShell.PSConsoleReadLine]::ReadLine($host.Runspace, $ExecutionContext, $true) }",
    );
    assert_eq!(
        said(&calls_the_editor, "inner"),
        "False",
        "a wrapper that calls the editor directly is somebody else's reader:\n{calls_the_editor}"
    );
    let reads_another_way =
        in_front_of("function global:PSConsoleHostReadLine { [Console]::ReadLine() }");
    assert_eq!(said(&reads_another_way, "inner"), "False");
    // A function made inside the editor's own module scope reports the editor as its module, so
    // the module's name is no proof it is the editor's function.
    let inside = in_front_of(
        "& (Get-Module PSReadLine) { function global:PSConsoleHostReadLine { [Console]::ReadLine() } }",
    );
    assert_eq!(
        said(&inside, "inner"),
        "False",
        "a function that only lives in the editor's module is not the editor's reader:\n{inside}"
    );
    // The editor imported again is the editor's own function, which is what the module compares
    // with and not with what it saw first.
    let again = in_front_of("Import-Module PSReadLine -Force");
    assert_eq!(said(&again, "inner"), "True");
}

/// KR-REQ-07.85, KR-REQ-26.11
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn the_package_declares_the_qualified_baseline_and_its_reproducible_identity() {
    shellpkg::the_package_declares_the_baseline_the_specification_names(PWSH);
}

/// KR-REQ-07.37, KR-REQ-07.73
#[test]
fn every_committed_scenario_naming_powershell_holds_against_the_contract() {
    shellpkg::every_scenario_naming_this_shell_holds(PWSH);
}

/// KR-REQ-07.23
#[test]
#[ignore = "drives this tree's built PSReadLine package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_startup_prompt_reads_its_answer_and_the_session_is_ready_only_after_the_profile() {
    shellpkg::a_startup_prompt_reads_its_answer_and_readiness_waits_for_the_profile(PWSH);
}

/// KR-REQ-07.23
#[test]
#[ignore = "drives this tree's built PSReadLine package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_startup_prompt_nobody_answers_holds_readiness_without_hanging_the_shell() {
    shellpkg::a_startup_prompt_nobody_answers_holds_readiness_and_does_not_hang_the_shell(PWSH);
}

/// KR-REQ-07.22, KR-REQ-07.23
#[test]
#[ignore = "drives this tree's built PSReadLine package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_profile_that_fails_after_startup_closes_the_creating_session_with_its_diagnostics() {
    shellpkg::a_profile_that_fails_after_startup_closes_the_creating_session_with_its_diagnostics(
        PWSH,
    );
}

/// KR-REQ-07.23, KR-REQ-07.85
#[test]
#[ignore = "drives this tree's built PSReadLine package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn an_editor_the_profile_replaced_is_diagnosed_when_the_hooks_activate() {
    shellpkg::an_editor_the_profile_replaced_is_diagnosed_when_the_hooks_activate(PWSH);
}

/// KR-REQ-07.23
#[test]
#[ignore = "drives this tree's built PSReadLine package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_question_in_the_profile_every_host_reads_takes_its_answer_through_the_worker() {
    shellpkg::a_question_in_the_profile_every_host_reads_takes_its_answer_through_the_worker(PWSH);
}

/// KR-REQ-07.23, KR-REQ-07.85
#[test]
#[ignore = "drives this tree's built PSReadLine package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_profile_that_changes_the_read_line_entry_point_is_diagnosed_by_name() {
    shellpkg::a_profile_that_changes_the_read_line_entry_point_is_diagnosed_by_name(PWSH);
}

/// The cursor position query the editor asks at every prompt reaches the terminal in pieces on a
/// loaded machine, and the editor waits for its answer before it reads a key.
#[test]
fn the_terminal_answers_a_cursor_query_whichever_way_the_output_is_cut() {
    shellpkg::a_terminal_query_the_output_splits_across_reads_is_answered_once(
        b"\x1b[6n",
        b"\x1b[1;1R",
    );
}

/// KR-REQ-01.06
#[test]
#[ignore = "drives this tree's built PSReadLine package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn ordinary_commands_and_agent_names_run_as_they_do_without_the_integration() {
    shellpkg::ordinary_commands_and_agent_names_run_as_in_an_unmanaged_shell(PWSH);
}

/// KR-REQ-01.06
#[test]
#[ignore = "drives this tree's built PSReadLine package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn an_alias_that_changes_an_agent_name_is_reported_by_the_comparison() {
    shellpkg::a_planted_alias_that_changes_an_agent_name_is_reported_not_hidden(PWSH);
}
