//! The queue, the cadence, the fairness bound, the reserve and the power policy.
//!
//! Section 22's scheduling and resource paragraphs are where a feature like this becomes unusable
//! quietly: a queue that starves a quiet session, a cadence fixed at its own floor, a reserve
//! checked against a file size. Each of those is a test here, and each is decided without a model.

mod support;

use kr_describe::budget::{Budgets, GIB, ProcessFigures};
use kr_describe::context::{ContextBuilder, ContextRevision, DescriptionContext};
use kr_describe::metrics::{LatencyLedger, PUBLISHED_SESSION_COUNTS};
use kr_describe::priority::enter_background;
use kr_describe::queue::{
    Enqueued, Freshness, NothingToDequeue, PRIORITY_RUN_LIMIT, Priority, Scheduler,
};
use kr_describe::resource::{
    HostConditions, PauseReason, PowerSource, ResourcePolicy, ResourceSettings, ResourceState,
    Signal, ThermalState,
};
use kr_protocol::ids::{SessionEpoch, SessionId};

use support::{at, binding, default_profile, environment_id, roomy, session};

/// A bounded context for one session at one revision.
fn context_for(session_id: &SessionId, revision: u64) -> DescriptionContext {
    ContextBuilder::new(
        environment_id(1),
        *session_id,
        SessionEpoch::V1,
        binding(),
        ContextRevision::new(revision),
    )
    .directory("kalareach")
    .build()
}

/// KR-REQ-22.12: the reserve is the larger of one gibibyte and a fifth of physical memory.
#[test]
fn the_reserve_is_the_larger_of_a_gibibyte_and_a_fifth_of_the_memory() {
    let policy = ResourcePolicy::new(ResourceSettings::default(), Budgets::DEFAULTS);
    assert_eq!(policy.required_reserve_bytes(4 * GIB), GIB);
    assert_eq!(policy.required_reserve_bytes(32 * GIB), 32 * GIB / 5);

    let stricter = ResourcePolicy::new(
        ResourceSettings {
            owner_reserve_bytes: Some(8 * GIB),
            ..ResourceSettings::default()
        },
        Budgets::DEFAULTS,
    );
    assert_eq!(stricter.required_reserve_bytes(16 * GIB), 8 * GIB);

    let looser = ResourcePolicy::new(
        ResourceSettings {
            owner_reserve_bytes: Some(64 * 1024 * 1024),
            ..ResourceSettings::default()
        },
        Budgets::DEFAULTS,
    );
    assert_eq!(looser.required_reserve_bytes(16 * GIB), 16 * GIB / 5);
}

/// KR-REQ-22.12: a reserve that cannot be held pauses rather than loads, and says `resource_paused`.
#[test]
fn a_reserve_that_cannot_be_held_pauses_rather_than_loads() {
    let mut policy = ResourcePolicy::new(ResourceSettings::default(), Budgets::DEFAULTS);
    let cost = default_profile().execution().resident_estimate;
    // An 8 GiB host with 2.5 GiB free: the model is 2 GiB, which would leave less than the 1.6 GiB
    // reserve.
    let tight = HostConditions::measured(
        8 * GIB,
        2 * GIB + GIB / 2,
        PowerSource::Mains,
        ThermalState::Nominal,
    );
    let transition = policy.evaluate(&tight, &cost, false);
    assert!(transition.paused());
    assert!(!transition.restarted_worker);
    assert_eq!(
        policy.state(),
        ResourceState::ResourcePaused {
            reason: PauseReason::MemoryReserve,
            unloaded: false
        }
    );
    assert_eq!(policy.state().as_str(), "resource_paused");
    assert!(!policy.state().dispatches());
}

/// KR-REQ-22.12: an unreadable memory signal is a refusal rather than an assumption.
#[test]
fn an_unreadable_memory_signal_is_a_refusal_rather_than_an_assumption() {
    let mut policy = ResourcePolicy::new(ResourceSettings::default(), Budgets::DEFAULTS);
    let cost = default_profile().execution().resident_estimate;
    let unknown = HostConditions {
        physical_memory_bytes: Signal::Unqualified {
            why: "a host that reports nothing",
        },
        available_memory_bytes: Signal::Qualified(12 * GIB),
        power: Signal::Qualified(PowerSource::Mains),
        thermal: Signal::Qualified(ThermalState::Nominal),
    };
    policy.evaluate(&unknown, &cost, false);
    assert!(matches!(
        policy.state(),
        ResourceState::ResourcePaused {
            reason: PauseReason::SignalUnqualified { .. },
            ..
        }
    ));
}

/// KR-REQ-22.13: battery pauses by default and runs when an owner enables it.
#[test]
fn battery_pauses_by_default_and_runs_when_an_owner_enables_it() {
    let cost = default_profile().execution().resident_estimate;
    let on_battery = HostConditions::measured(
        16 * GIB,
        12 * GIB,
        PowerSource::Battery,
        ThermalState::Nominal,
    );
    let mut default = ResourcePolicy::new(ResourceSettings::default(), Budgets::DEFAULTS);
    default.evaluate(&on_battery, &cost, false);
    assert_eq!(
        default.state(),
        ResourceState::ResourcePaused {
            reason: PauseReason::Battery,
            unloaded: false
        }
    );

    let mut enabled = ResourcePolicy::new(
        ResourceSettings {
            on_battery: true,
            ..ResourceSettings::default()
        },
        Budgets::DEFAULTS,
    );
    enabled.evaluate(&on_battery, &cost, false);
    assert_eq!(enabled.state(), ResourceState::Admitted);

    // A host that cannot read its power source has not been told it is on mains.
    let unknown = HostConditions {
        power: Signal::Unqualified {
            why: "no power source on this platform",
        },
        ..roomy()
    };
    let mut unreadable = ResourcePolicy::new(ResourceSettings::default(), Budgets::DEFAULTS);
    unreadable.evaluate(&unknown, &cost, false);
    assert!(matches!(
        unreadable.state(),
        ResourceState::ResourcePaused {
            reason: PauseReason::Battery,
            ..
        }
    ));
}

/// KR-REQ-22.13: what a power-supply class says of the host's power, read from trees laid out as
/// the kernel lays them out. A supply the host would not describe may be the battery, so with no
/// mains online it is not taken for a host on mains, which would admit inference on a battery.
#[test]
fn a_power_supply_the_host_would_not_describe_is_not_taken_for_mains() {
    use kr_describe::resource::platform::power_of_supplies;

    /// One supply directory with the files the kernel shows, and a directory where a file is
    /// `None`: reading a directory as a file fails the way a supply that went away mid-read does.
    fn supply(root: &std::path::Path, name: &str, files: &[(&str, Option<&str>)]) {
        let directory = root.join(name);
        std::fs::create_dir_all(&directory).expect("a supply directory");
        for (file, content) in files {
            match content {
                Some(text) => std::fs::write(directory.join(file), text).expect("a supply file"),
                None => std::fs::create_dir(directory.join(file)).expect("an unreadable file"),
            }
        }
    }
    type Files<'a> = &'a [(&'a str, Option<&'a str>)];
    let tree = |supplies: &[(&str, Files)]| {
        let root = tempfile::tempdir().expect("a power-supply class");
        for (name, files) in supplies {
            supply(root.path(), name, files);
        }
        power_of_supplies(root.path())
    };
    let battery: Files = &[("type", Some("Battery\n"))];
    let mains_online: Files = &[("type", Some("Mains\n")), ("online", Some("1\n"))];
    let mains_offline: Files = &[("type", Some("Mains\n")), ("online", Some("0\n"))];

    // The cases the reader always answered.
    assert_eq!(
        tree(&[("BAT0", battery), ("AC", mains_online)]),
        Signal::Qualified(PowerSource::Mains)
    );
    assert_eq!(
        tree(&[("BAT0", battery), ("AC", mains_offline)]),
        Signal::Qualified(PowerSource::Battery)
    );
    assert_eq!(tree(&[]), Signal::Qualified(PowerSource::Mains));
    assert_eq!(
        tree(&[("AC", mains_online)]),
        Signal::Qualified(PowerSource::Mains)
    );
    assert!(matches!(
        tree(&[("BAT0", battery)]),
        Signal::Unqualified { .. }
    ));
    let absent = tempfile::tempdir().expect("a directory");
    assert!(matches!(
        power_of_supplies(&absent.path().join("no-such-class")),
        Signal::Unqualified { .. }
    ));

    // A supply whose type the host would not tell, alone or beside a mains supply that is offline,
    // is a host that has not said it is on mains. Its type file was missing, unreadable or empty.
    let undescribed_supplies: [Files; 3] = [&[], &[("type", None)], &[("type", Some("\n"))]];
    for undescribed in undescribed_supplies {
        assert!(
            matches!(tree(&[("BAT0", undescribed)]), Signal::Unqualified { .. }),
            "an undescribed supply alone: {undescribed:?}"
        );
        assert!(
            matches!(
                tree(&[("BAT0", undescribed), ("AC", mains_offline)]),
                Signal::Unqualified { .. }
            ),
            "an undescribed supply beside a mains supply that is offline: {undescribed:?}"
        );
    }
    // A mains supply that would not say whether it is online is no more known to be plugged in.
    assert!(matches!(
        tree(&[("AC", &[("type", Some("Mains\n")), ("online", None)])]),
        Signal::Unqualified { .. }
    ));

    // The control: an adapter that says it is online settles it, whatever else the host would not
    // describe, so a laptop on its charger is not paused for a supply it cannot read.
    assert_eq!(
        tree(&[("BAT0", &[("type", None)]), ("AC", mains_online)]),
        Signal::Qualified(PowerSource::Mains)
    );
}

/// KR-REQ-22.13: thermal pressure pauses on mains too, and clearing resumes without a restart.
#[test]
fn pressure_that_clears_resumes_without_restarting_a_worker() {
    let cost = default_profile().execution().resident_estimate;
    let mut policy = ResourcePolicy::new(ResourceSettings::default(), Budgets::DEFAULTS);
    assert_eq!(
        policy.evaluate(&roomy(), &cost, false).to,
        ResourceState::Admitted
    );

    let hot = HostConditions::measured(
        16 * GIB,
        12 * GIB,
        PowerSource::Mains,
        ThermalState::Elevated,
    );
    let paused = policy.evaluate(&hot, &cost, true);
    assert!(paused.paused());
    assert!(!paused.restarted_worker);
    assert_eq!(
        policy.state(),
        ResourceState::ResourcePaused {
            reason: PauseReason::Thermal,
            unloaded: true
        }
    );

    let resumed = policy.evaluate(&roomy(), &cost, false);
    assert!(resumed.resumed());
    assert!(!resumed.restarted_worker);
    assert_eq!(policy.state(), ResourceState::Admitted);
}

/// KR-REQ-22.14: a session has one queued job, whose content updates without losing its position.
#[test]
fn a_session_has_one_queued_job_whose_content_updates_in_place() {
    let mut scheduler = Scheduler::new(Budgets::DEFAULTS);
    assert_eq!(
        scheduler.enqueue(Priority::Ordinary, context_for(&session(1), 1), at(1_000)),
        Enqueued::Admitted
    );
    let replaced = scheduler.enqueue(Priority::Ordinary, context_for(&session(1), 2), at(9_000));
    assert_eq!(
        replaced,
        Enqueued::Replaced {
            queued_at_ms: 1_000,
            coalesced: 1
        }
    );
    assert_eq!(scheduler.queued(), 1);
    let job = scheduler.dequeue(at(9_000)).expect("the one job");
    assert_eq!(
        job.work.description().expect("a description").revision(),
        ContextRevision::new(2)
    );
    assert_eq!(job.queued_at_ms, 1_000);
    assert_eq!(job.coalesced, 1);
}

/// KR-REQ-22.14: coalescing never puts a quiet session behind a busy one.
#[test]
fn coalescing_keeps_the_aging_position_so_a_quiet_session_is_not_left_behind() {
    let mut scheduler = Scheduler::new(Budgets::DEFAULTS);
    scheduler.enqueue(Priority::Ordinary, context_for(&session(1), 1), at(1_000));
    scheduler.enqueue(Priority::Ordinary, context_for(&session(2), 1), at(2_000));
    // The second session changes ten more times. Its position does not move.
    for revision in 2..=11 {
        scheduler.enqueue(
            Priority::Ordinary,
            context_for(&session(2), revision),
            at(2_000 + revision * 100),
        );
    }
    let first = scheduler.dequeue(at(20_000)).expect("the oldest position");
    assert_eq!(first.session_id, session(1));
}

/// KR-REQ-22.14: an oldest ordinary job runs after at most three priority jobs.
#[test]
fn an_oldest_ordinary_job_runs_after_three_priority_jobs() {
    let mut scheduler = Scheduler::new(Budgets::DEFAULTS);
    scheduler.enqueue(Priority::Ordinary, context_for(&session(9), 1), at(0));
    for seed in 1..=6_u8 {
        scheduler.enqueue(
            Priority::Foreground,
            context_for(&session(seed), 1),
            at(1_000 + u64::from(seed)),
        );
    }
    let mut served = Vec::new();
    for step in 0..4 {
        let job = scheduler.dequeue(at(10_000 + step * 1_000)).expect("a job");
        served.push(job.session_id);
    }
    assert_eq!(served.len(), 4);
    assert_eq!(
        served[3],
        session(9),
        "the oldest ordinary job runs after {PRIORITY_RUN_LIMIT} priority jobs, and got {served:?}"
    );
    assert_eq!(scheduler.priority_run(), 0);
}

/// KR-REQ-22.14: a session inside its cooldown is not dequeued, and the queue says which case it is.
#[test]
fn a_session_inside_its_cooldown_waits_and_the_queue_says_so() {
    let mut scheduler = Scheduler::new(Budgets::DEFAULTS);
    assert_eq!(scheduler.dequeue(at(0)), Err(NothingToDequeue::Empty));
    scheduler.enqueue(Priority::Ordinary, context_for(&session(1), 1), at(0));
    scheduler.dequeue(at(1_000)).expect("the first pass");
    scheduler.enqueue(Priority::Ordinary, context_for(&session(1), 2), at(2_000));
    assert_eq!(
        scheduler.dequeue(at(3_000)),
        Err(NothingToDequeue::EveryoneCoolingDown)
    );
    assert!(scheduler.dequeue(at(31_001)).is_ok());
}

/// KR-REQ-22.14: the cadence follows measured service time and the eligible session count.
#[test]
fn the_cadence_follows_measured_service_time_and_the_eligible_count() {
    let mut scheduler = Scheduler::new(Budgets::DEFAULTS);
    assert_eq!(
        scheduler.cadence_ms(at(60_000)),
        30_000,
        "the cooldown is the floor"
    );
    for seed in 1..=50_u8 {
        scheduler.enqueue(
            Priority::Ordinary,
            context_for(&session(seed), 1),
            at(u64::from(seed)),
        );
    }
    for _ in 0..8 {
        scheduler.record_service(4_000);
    }
    assert_eq!(scheduler.service_time().mean_ms(), Some(4_000));
    assert_eq!(scheduler.cadence_ms(at(60_000)), 4_000 * 50);
    assert!(scheduler.cadence_ms(at(60_000)) > Budgets::DEFAULTS.session_cooldown_ms);
}

/// KR-REQ-22.14: under mixed demand an ordinary session is described again only once the measured
/// cadence has passed, a priority session once the thirty-second cooldown has, and an ordinary job
/// that is due still waits behind at most three priority jobs.
///
/// One ordinary session and ten foreground sessions all change without pause, each queuing its next
/// job the moment its last one is taken, and every job takes ten seconds. A queue gated by the
/// cooldown alone serves the ordinary session every fourth job, forty seconds apart, while it
/// publishes a cadence of eighty: the cadence it shows is not the one it runs at.
#[test]
fn under_mixed_demand_an_ordinary_session_waits_for_the_measured_cadence() {
    let mut scheduler = Scheduler::new(Budgets::DEFAULTS);
    let ordinary = session(1);
    let foreground: Vec<SessionId> = (2..=11_u8).map(session).collect();
    scheduler.enqueue(Priority::Ordinary, context_for(&ordinary, 1), at(0));
    for session_id in &foreground {
        scheduler.enqueue(Priority::Foreground, context_for(session_id, 1), at(0));
    }
    let service_ms = 10_000;
    let cooldown_ms = Budgets::DEFAULTS.session_cooldown_ms;
    let mut now = 1_000;
    let mut revision = 1;
    let mut last_dispatch: std::collections::BTreeMap<SessionId, u64> =
        std::collections::BTreeMap::new();
    let mut priority_jobs_while_the_ordinary_one_was_due = 0;
    let mut ordinary_dispatches = 0;
    let mut gaps = Vec::new();
    for _ in 0..200 {
        let cadence = scheduler.cadence_ms(at(now));
        let ordinary_due = scheduler.is_eligible(&ordinary, at(now));
        let Ok(job) = scheduler.dequeue(at(now)) else {
            now += 1_000;
            continue;
        };
        let since = last_dispatch
            .get(&job.session_id)
            .map(|previous| now - previous);
        match job.priority {
            Priority::Ordinary => {
                if let Some(since) = since {
                    assert!(
                        since >= cadence,
                        "the ordinary session was described again after {since} ms, inside the \
                         cadence of {cadence} ms this queue publishes"
                    );
                    gaps.push(since);
                }
                ordinary_dispatches += 1;
                priority_jobs_while_the_ordinary_one_was_due = 0;
            }
            Priority::Foreground => {
                if let Some(since) = since {
                    assert!(
                        since >= cooldown_ms,
                        "a priority session inside its cooldown"
                    );
                }
                if ordinary_due {
                    priority_jobs_while_the_ordinary_one_was_due += 1;
                    assert!(
                        priority_jobs_while_the_ordinary_one_was_due <= PRIORITY_RUN_LIMIT,
                        "a due ordinary job waited behind more than {PRIORITY_RUN_LIMIT} priority jobs"
                    );
                }
            }
        }
        last_dispatch.insert(job.session_id, now);
        scheduler.record_service(service_ms);
        now += service_ms;
        revision += 1;
        scheduler.enqueue(
            job.priority,
            context_for(&job.session_id, revision),
            at(now),
        );
    }
    assert!(
        ordinary_dispatches >= 5,
        "the ordinary session is still described, {ordinary_dispatches} times"
    );
    // The control: the cadence is well above the cooldown here, so a queue that gated on the
    // cooldown alone would have served the ordinary session sooner than it did.
    assert!(
        gaps.iter().all(|gap| *gap > cooldown_ms + service_ms),
        "every gap is longer than the cooldown-only queue's forty seconds: {gaps:?}"
    );
}

/// KR-REQ-22.14: a client is shown queued age and the last success rather than a promise.
#[test]
fn a_client_is_shown_queued_age_and_the_last_success() {
    let mut scheduler = Scheduler::new(Budgets::DEFAULTS);
    scheduler.enqueue(Priority::Ordinary, context_for(&session(1), 1), at(1_000));
    let standing = scheduler.standing(&session(1), at(61_000));
    assert_eq!(standing.queued_age_ms, Some(60_000));
    assert_eq!(standing.last_success_wall_ms, None);

    scheduler.dequeue(at(61_000)).expect("the job");
    scheduler.record_success(&session(1), at(61_500));
    let after = scheduler.standing(&session(1), at(62_000));
    assert_eq!(after.queued_age_ms, None);
    assert_eq!(after.last_success_wall_ms, Some(at(61_500).wall_ms().get()));
}

/// KR-REQ-22.14: a description behind the revision in force is exposed as stale, never as current.
#[test]
fn a_description_behind_the_revision_is_exposed_as_stale() {
    assert_eq!(
        Freshness::of(ContextRevision::new(3), ContextRevision::new(3), None),
        Freshness::Current
    );
    assert_eq!(
        Freshness::of(
            ContextRevision::new(3),
            ContextRevision::new(3),
            Some(90_000)
        ),
        Freshness::Delayed {
            queued_age_ms: 90_000
        }
    );
    assert_eq!(
        Freshness::of(ContextRevision::new(3), ContextRevision::new(7), None),
        Freshness::Stale {
            produced_at: ContextRevision::new(3),
            current: ContextRevision::new(7)
        }
    );
}

/// KR-REQ-22.15: queue wait and execution latency are published apart at each session count.
#[test]
fn queue_wait_and_execution_latency_are_published_apart_at_each_session_count() {
    let mut ledger = LatencyLedger::new();
    assert_eq!(ledger.unmeasured(), PUBLISHED_SESSION_COUNTS.to_vec());
    for sessions in PUBLISHED_SESSION_COUNTS {
        for sample in 1..=100_u64 {
            ledger.record(sessions, sample * u64::from(sessions), 1_000 + sample);
        }
    }
    let published = ledger.published();
    assert_eq!(published.len(), 4);
    assert!(ledger.unmeasured().is_empty());
    for reading in &published {
        assert_eq!(reading.queue_wait.samples, 100);
        assert_eq!(reading.execution.samples, 100);
        assert_ne!(
            reading.queue_wait.p95_ms, reading.execution.p95_ms,
            "the two are published separately and never summed"
        );
    }
    let fifty = ledger.reading(50).expect("fifty sessions were measured");
    let one = ledger.reading(1).expect("one session was measured");
    assert!(
        fifty.queue_wait.p95_ms > one.queue_wait.p95_ms,
        "queue wait grows with the session count, which is what publishing it apart shows"
    );
    assert_eq!(fifty.execution.p95_ms, one.execution.p95_ms);
    assert_eq!(one.execution.p99_ms, 1_099);
}

/// KR-REQ-22.21: whole-product figures are reported beside the separated model ones.
#[test]
fn whole_product_figures_are_reported_beside_the_model_ones() {
    let figures = ProcessFigures {
        whole_product_rss_bytes: 3 * GIB,
        model_rss_bytes: 2 * GIB,
        whole_product_cpu_centis: 180,
        model_cpu_centis: 150,
    };
    assert_eq!(figures.product_without_model_rss_bytes(), GIB);
    assert_eq!(figures.product_without_model_cpu_centis(), 30);
}

/// KR-REQ-22.11: this host names the background class it actually applied, as the system reads it
/// back.
#[test]
fn this_host_names_the_background_mechanism_it_actually_applied() {
    // The class is the thread's on Linux and the process's on macOS and Windows, so the test notes
    // what it found and puts it back, on a thread of its own.
    let applied = std::thread::spawn(|| {
        let saved = kr_ipc::background::save();
        let applied = enter_background();
        saved.restore().expect("the classes are put back");
        applied
    })
    .join()
    .expect("the thread ends");

    // Whether the change is permitted depends on the host, so the assertion is about honesty
    // rather than about success: a class is named only when the system reports it, and a class
    // that is not applied says why.
    assert_eq!(applied.cpu, applied.mechanism.as_str() != "none");
    if applied.cpu && applied.io {
        assert!(applied.why.is_none());
    } else {
        assert!(applied.why.is_some());
    }
}

/// KR-REQ-22.13: what a platform's thermal zones say of the heat is the worst of them, by how far
/// the platform is holding the processors back, and a machine that lists no zone says nothing. A
/// zone the platform listed and gave no reading of cannot be taken for one that holds nothing back:
/// with no zone showing heat the host's heat is not known, and a zone that does show heat still
/// does. The first set is what the Windows test machine's performance counters returned.
#[test]
fn the_thermal_zones_a_platform_lists_say_how_hot_the_host_is() {
    use kr_describe::resource::{Signal, ThermalState, platform::thermal_of_zones};
    use kr_ipc::conditions::ThermalZone;

    let zones = |limits: &[Option<u32>]| -> Vec<ThermalZone> {
        limits
            .iter()
            .enumerate()
            .map(|(index, limit)| ThermalZone {
                name: format!(r"\_TZ.TZ{index:02}"),
                passive_limit_percent: *limit,
            })
            .collect()
    };
    let read = |limits: &[Option<u32>]| thermal_of_zones(&zones(limits));

    assert_eq!(read(&[Some(100)]), Signal::Qualified(ThermalState::Nominal));
    assert_eq!(
        read(&[Some(100), Some(99)]),
        Signal::Qualified(ThermalState::Elevated)
    );
    assert_eq!(read(&[Some(50)]), Signal::Qualified(ThermalState::Elevated));
    assert_eq!(read(&[Some(49)]), Signal::Qualified(ThermalState::Critical));
    assert_eq!(
        read(&[Some(100), Some(70), Some(20)]),
        Signal::Qualified(ThermalState::Critical),
        "the worst zone decides"
    );
    assert!(matches!(read(&[]), Signal::Unqualified { .. }));

    // A zone with no reading beside one at 100 is not a host with nothing held back.
    assert!(matches!(
        read(&[Some(100), None]),
        Signal::Unqualified { .. }
    ));
    assert!(matches!(read(&[None]), Signal::Unqualified { .. }));
    // Heat that was read is still heat.
    assert_eq!(
        read(&[None, Some(60)]),
        Signal::Qualified(ThermalState::Elevated)
    );
}

/// KR-REQ-22.13: what a Mac's thermal pressure level says of the heat. The levels are the ones the
/// system's `OSThermalNotification.h` names for macOS; a level beyond them is not taken for cool.
#[test]
fn the_pressure_levels_a_mac_reports_say_how_hot_the_host_is() {
    use kr_describe::resource::platform::thermal_of_pressure_level;

    assert_eq!(thermal_of_pressure_level(0), ThermalState::Nominal);
    assert_eq!(thermal_of_pressure_level(1), ThermalState::Elevated);
    for level in [2, 3, 4, 5, u64::MAX] {
        assert_eq!(
            thermal_of_pressure_level(level),
            ThermalState::Critical,
            "level {level}"
        );
    }
}

/// KR-REQ-22.13: a Mac of either processor family reads how hot it is. `pmset -g therm` records no
/// processor speed limit on Apple silicon, so a reading taken from it left heat unread there and
/// never paused inference for it.
#[cfg(target_os = "macos")]
#[test]
fn a_mac_reads_how_hot_it_is() {
    use kr_describe::resource::platform::read_conditions;

    let conditions = read_conditions();
    assert!(
        matches!(conditions.thermal, Signal::Qualified(_)),
        "{:?}",
        conditions.thermal
    );
}

/// KR-REQ-22.13: a Windows host reads its power source and, when it lists a thermal zone and reads
/// each one, how hot it is; a power source the system would not name, and a host that lists no
/// zone, stay unqualified.
#[cfg(windows)]
#[test]
fn a_windows_host_reads_its_power_source_and_its_thermal_zones() {
    use kr_describe::resource::Signal;
    use kr_describe::resource::platform::read_conditions;

    let conditions = read_conditions();
    let said = kr_ipc::conditions::supply();
    assert_eq!(
        matches!(conditions.power, Signal::Qualified(_)),
        said.is_some(),
        "{:?} against {said:?}",
        conditions.power
    );
    let zones = kr_ipc::conditions::thermal_zones();
    if zones.is_empty() {
        assert!(
            matches!(conditions.thermal, Signal::Unqualified { .. }),
            "{:?} against {zones:?}",
            conditions.thermal
        );
    } else if zones
        .iter()
        .all(|zone| zone.passive_limit_percent.is_some())
    {
        assert!(
            matches!(conditions.thermal, Signal::Qualified(_)),
            "{:?} against {zones:?}",
            conditions.thermal
        );
    }
}
