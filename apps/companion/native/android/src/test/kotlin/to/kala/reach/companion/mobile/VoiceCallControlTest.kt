package to.kala.reach.companion.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * A call's hold on the microphone, driven through the same control the application runs, with the
 * platform replaced by a record of what was asked of it.
 *
 * KR-REQ-15.34: nothing records before the host's answer, the foreground service and the recorder
 * all say so, and a refusal anywhere undoes the rest. KR-REQ-15.35: focus, routes, mute and the end
 * of a call each act on the switches. KR-REQ-15.36 and KR-ACC-014: the microphone carries speech
 * exactly when the screen says it does, and never after the deadline, whatever the timers do.
 */
class VoiceCallControlTest {
    /** What the control asked of the media, and whether the recorder or microphone was ever on. */
    private class Switches : VoiceMediaSwitches {
        var deviceOn = false
        var microphoneOn = false
        var playbackOn = false
        var deviceEverOn = false
        var microphoneEverOn = false

        override fun setAudioDevice(on: Boolean) {
            deviceOn = on
            deviceEverOn = deviceEverOn || on
        }

        override fun setMicrophone(on: Boolean) {
            microphoneOn = on
            microphoneEverOn = microphoneEverOn || on
        }

        override fun setPlayback(on: Boolean) {
            playbackOn = on
        }
    }

    /** A platform whose clocks, focus, service and timers the test decides. */
    private class Platform : VoiceCallPlatform {
        var now = 1_000L
        val epochAtStart = 1_700_000_000_000L
        var grantsFocus = true
        var startsService = true
        var serviceThrows = false
        var whileTakingFocus: () -> Unit = {}
        var focusHeld = false
        var serviceRunning = false
        var releases = 0
        var ends = 0
        val timers = mutableListOf<Pair<Long, () -> Unit>>()
        val shown = mutableListOf<VoiceCaptureState>()
        val notified = mutableListOf<VoiceCaptureState>()

        override fun nowMs() = now

        override fun epochMs() = epochAtStart + now

        override fun acquireFocus(): Boolean {
            whileTakingFocus()
            focusHeld = grantsFocus
            return grantsFocus
        }

        override fun releaseFocus() {
            focusHeld = false
            releases += 1
        }

        override fun startService(): Boolean {
            if (serviceThrows) throw IllegalStateException("not allowed to start a service now")
            serviceRunning = startsService
            return startsService
        }

        override fun stopService() {
            serviceRunning = false
        }

        override fun schedule(atMs: Long, task: () -> Unit): () -> Unit {
            val timer = atMs to task
            timers += timer
            return { timers.remove(timer) }
        }

        override fun publish(state: VoiceCaptureState) {
            shown += state
        }

        override fun publishToService(state: VoiceCaptureState) {
            notified += state
        }

        override fun ended() {
            ends += 1
        }

        /** Runs every timer that is due. A test that stalls the timers simply does not call this. */
        fun runDueTimers() {
            val due = timers.filter { it.first <= now }
            timers.removeAll(due)
            due.forEach { it.second() }
        }

        /** The moment the service closes a call `seconds` from now, in epoch milliseconds. */
        fun closesIn(seconds: Long) = epochMs() + seconds * 1_000
    }

    private fun running(
        platform: Platform = Platform(),
        switches: Switches = Switches(),
        seconds: Long = 60,
    ): Triple<VoiceCallControl, Platform, Switches> {
        val control = VoiceCallControl(platform, switches)
        assertTrue(control.permit("voice-session-1", platform.closesIn(seconds)))
        control.servicePromoted()
        control.recorder(true)
        return Triple(control, platform, switches)
    }

    /** KR-REQ-15.34: every switch starts off, and nothing but a promoted, permitted call turns one on. */
    @Test
    fun nothing_records_before_the_service_enters_the_foreground() {
        val platform = Platform()
        val switches = Switches()
        val control = VoiceCallControl(platform, switches)
        assertFalse(switches.deviceOn || switches.microphoneOn || switches.playbackOn)

        // Everything the platform can report, before any answer.
        control.setMutedByPerson(false)
        control.focus(lost = false)
        control.route(changing = false, inputAvailable = true)
        control.recorder(true)
        control.refresh()
        assertFalse("nothing before a permit", switches.deviceEverOn || switches.microphoneEverOn)

        assertTrue(control.permit("voice-session-1", platform.closesIn(60)))
        assertTrue(platform.focusHeld)
        assertTrue(platform.serviceRunning)
        control.recorder(true)
        control.setMutedByPerson(false)
        assertFalse(
            "a service that has not entered the foreground keeps the recorder off",
            switches.deviceEverOn || switches.microphoneEverOn,
        )

        control.servicePromoted()
        assertTrue("the device runs once the service holds the foreground", switches.deviceOn)
        assertFalse("a recorder start from before the device came on does not count", switches.microphoneOn)
        assertEquals(VoiceCaptureState.UNAVAILABLE, control.displayed())

        control.recorder(true)
        assertTrue(switches.microphoneOn)
        assertEquals(VoiceCaptureState.CAPTURING, control.displayed())
        assertEquals(VoiceCaptureState.CAPTURING, platform.notified.last())
    }

    /** KR-REQ-15.34: a refused service undoes focus and ends the call, and nothing reopens it. */
    @Test
    fun a_refused_service_undoes_everything_and_ends_the_call() {
        for (throws in listOf(false, true)) {
            val platform = Platform().apply {
                startsService = false
                serviceThrows = throws
            }
            val switches = Switches()
            val control = VoiceCallControl(platform, switches)
            assertFalse(control.permit("voice-session-1", platform.closesIn(60)))
            assertFalse("focus given back (throws=$throws)", platform.focusHeld)
            assertEquals(1, platform.ends)
            assertTrue(control.isStopped)

            control.servicePromoted()
            control.recorder(true)
            control.setMutedByPerson(false)
            control.focus(lost = false)
            assertFalse(switches.deviceEverOn || switches.microphoneEverOn)
            assertEquals(VoiceCaptureState.IDLE, platform.shown.last())
        }
    }

    /** KR-REQ-15.34: a service that is promoted and then taken away ends the call the same way. */
    @Test
    fun a_service_refused_after_the_answer_ends_the_call() {
        val (control, platform, switches) = running()
        assertTrue(switches.microphoneOn)
        control.serviceRefused()
        assertFalse(switches.deviceOn || switches.microphoneOn || switches.playbackOn)
        assertFalse(platform.focusHeld)
        assertFalse(platform.serviceRunning)
        assertTrue(control.isStopped)
    }

    /** KR-REQ-15.34: focus refused ends the call before any service is asked for. */
    @Test
    fun refused_focus_ends_the_call() {
        val platform = Platform().apply { grantsFocus = false }
        val switches = Switches()
        val control = VoiceCallControl(platform, switches)
        assertFalse(control.permit("voice-session-1", platform.closesIn(60)))
        assertFalse(platform.serviceRunning)
        assertTrue(control.isStopped)
        assertTrue(platform.notified.isEmpty())
    }

    /** KR-REQ-15.34: time the platform takes counts against the deadline and never extends it. */
    @Test
    fun activation_that_crosses_the_deadline_records_nothing() {
        val platform = Platform()
        platform.whileTakingFocus = { platform.now += 10_000 }
        val switches = Switches()
        val control = VoiceCallControl(platform, switches)
        assertFalse(control.permit("voice-session-1", platform.closesIn(5)))
        assertTrue(control.isStopped)
        assertFalse(platform.focusHeld)
        assertFalse(switches.deviceEverOn || switches.microphoneEverOn)

        // The same, with the delay in the service instead.
        val later = Platform()
        val switchesLater = Switches()
        val slow = VoiceCallControl(later, switchesLater)
        assertTrue(slow.permit("voice-session-1", later.closesIn(5)))
        later.now += 6_000
        slow.servicePromoted()
        assertTrue(slow.isStopped)
        assertFalse(switchesLater.deviceEverOn || switchesLater.microphoneEverOn)
    }

    /** KR-REQ-15.34: the call's end is scheduled at the deadline itself, and ends everything. */
    @Test
    fun the_call_ends_at_its_deadline() {
        val (control, platform, switches) = running(seconds = 30)
        val (at, _) = platform.timers.single()
        assertEquals("scheduled against the deadline, not the delay from a stale reading", 1_000L + 30_000L, at)
        platform.now = at - 1
        platform.runDueTimers()
        assertTrue(switches.microphoneOn)
        platform.now = at
        platform.runDueTimers()
        assertTrue(control.isStopped)
        assertFalse(switches.deviceOn || switches.microphoneOn || switches.playbackOn)
        assertFalse(platform.focusHeld)
        assertFalse(platform.serviceRunning)
        assertTrue(platform.timers.isEmpty())
    }

    /**
     * KR-REQ-15.34 and KR-ACC-014: a timer that never runs does not keep the microphone carrying
     * speech. Every frame is refused from the deadline on, and the next change of any kind ends the
     * call.
     */
    @Test
    fun a_stalled_timer_does_not_keep_the_microphone_on() {
        val (control, platform, switches) = running(seconds = 30)
        platform.now = 1_000 + 29_999
        assertTrue(control.carries())
        platform.now = 1_000 + 30_000
        assertFalse("a frame after the deadline is not carried", control.carries())
        assertFalse(control.couldHaveHeard(1_000 + 30_000))
        assertTrue(control.couldHaveHeard(1_000 + 29_999))

        control.setPlaybackMuted(false)
        assertTrue(control.isStopped)
        assertFalse(switches.deviceOn || switches.microphoneOn || switches.playbackOn)
    }

    /** One way into the control, named for the failure it would cause. */
    private fun entry(name: String, reach: (VoiceCallControl, Platform) -> Unit) = name to reach

    /**
     * KR-REQ-15.34 and KR-ACC-014: with the timer stalled, whatever takes the control's lock after
     * the deadline ends the call: every change, a second permit, the service's reports and the stop.
     * Each is tried on a call of its own, and what is held is read from the platform rather than
     * asked of the call.
     */
    @Test
    fun every_way_into_the_call_ends_it_after_the_deadline_when_the_timer_is_late() {
        val entries = listOf(
            entry("a second permit") { control, platform ->
                assertFalse(control.permit("voice-session-2", platform.closesIn(60)))
            },
            entry("the service entering the foreground") { control, _ -> control.servicePromoted() },
            entry("the service refused") { control, _ -> control.serviceRefused() },
            entry("the recorder starting") { control, _ -> control.recorder(true) },
            entry("the recorder stopping") { control, _ -> control.recorder(false) },
            entry("the person's mute") { control, _ -> control.setMutedByPerson(true) },
            entry("the playback mute") { control, _ -> control.setPlaybackMuted(true) },
            entry("focus lost") { control, _ -> control.focus(true) },
            entry("a route change") { control, _ -> control.route(true, true) },
            entry("a refresh") { control, _ -> control.refresh() },
            entry("the stop") { control, _ -> control.stop() },
        )
        for ((name, reach) in entries) {
            val (control, platform, switches) = running(seconds = 30)
            assertTrue(name, switches.microphoneOn)
            platform.now = 1_000 + 30_000
            reach(control, platform)
            assertFalse("$name left a switch on", switches.deviceOn || switches.microphoneOn || switches.playbackOn)
            assertFalse("$name left focus held", platform.focusHeld)
            assertFalse("$name left the service running", platform.serviceRunning)
            assertEquals("$name did not end the call", 1, platform.ends)
            assertTrue("$name left the end scheduled", platform.timers.isEmpty())
            assertEquals(name, VoiceCaptureState.IDLE, platform.shown.last())
        }
    }

    /**
     * KR-REQ-15.34: a call still waiting for its service when its deadline passes, with the timer
     * stalled, ends at the next thing that reaches it, and gives back the focus and the service.
     */
    @Test
    fun a_call_waiting_for_its_service_ends_when_reached_after_the_deadline() {
        val platform = Platform()
        val switches = Switches()
        val control = VoiceCallControl(platform, switches)
        assertTrue(control.permit("voice-session-1", platform.closesIn(30)))
        assertTrue(platform.focusHeld && platform.serviceRunning)
        platform.now = 1_000 + 30_000
        assertFalse(control.permit("voice-session-2", platform.closesIn(60)))
        assertFalse(platform.focusHeld)
        assertFalse(platform.serviceRunning)
        assertEquals(1, platform.ends)
        assertTrue(platform.timers.isEmpty())
        assertFalse(switches.deviceEverOn || switches.microphoneEverOn)
    }

    /** KR-REQ-15.36: the switches and the screen agree in every combination of what can happen. */
    @Test
    fun the_switches_follow_the_gate_in_every_combination() {
        for (muted in listOf(false, true)) {
            for (focusLost in listOf(false, true)) {
                for (changing in listOf(false, true)) {
                    for (input in listOf(false, true)) {
                        for (recording in listOf(false, true)) {
                            for (silenced in listOf(false, true)) {
                                val (control, platform, switches) = running()
                                control.setMutedByPerson(muted)
                                control.focus(focusLost)
                                control.route(changing, input)
                                control.recorder(recording)
                                control.setPlaybackMuted(silenced)
                                val shown = platform.shown.last()
                                val case = "muted=$muted focusLost=$focusLost changing=$changing " +
                                    "input=$input recording=$recording silenced=$silenced"
                                assertEquals(case, shown.speechCouldHaveBeenHeard, switches.microphoneOn)
                                assertEquals(case, shown, control.displayed())
                                assertEquals(case, shown, platform.notified.last())
                                assertTrue(case, switches.deviceOn)
                                assertEquals(case, !silenced && !focusLost, switches.playbackOn)
                            }
                        }
                    }
                }
            }
        }
    }

    /** KR-REQ-15.35: the end of a call is final, and the second end does nothing. */
    @Test
    fun an_ended_call_stays_ended() {
        val (control, platform, switches) = running()
        control.stop()
        control.stop()
        assertEquals(1, platform.ends)
        assertEquals(1, platform.releases)
        control.setMutedByPerson(false)
        control.recorder(true)
        control.servicePromoted()
        assertFalse(control.permit("voice-session-2", platform.closesIn(60)))
        assertFalse(switches.deviceOn || switches.microphoneOn || switches.playbackOn)
    }

    /** KR-REQ-15.34: one permit per call, and a second one while the first waits is refused. */
    @Test
    fun a_call_is_permitted_once() {
        val platform = Platform()
        val control = VoiceCallControl(platform, Switches())
        assertTrue(control.permit("voice-session-1", platform.closesIn(60)))
        assertFalse(control.permit("voice-session-2", platform.closesIn(60)))
        control.servicePromoted()
        assertFalse(control.permit("voice-session-3", platform.closesIn(60)))
        assertFalse(control.isStopped)
    }

    /**
     * The platform code reads the call's state while holding its own lock, and a change holds the
     * control's lock while it sets the platform's switches. So those reads must never wait for a
     * change in progress: here a change is held inside a switch, and every read still answers.
     */
    @Test(timeout = 10_000)
    fun reading_the_call_never_waits_for_a_change_in_progress() {
        val inside = CountDownLatch(1)
        val release = CountDownLatch(1)
        val switches = object : VoiceMediaSwitches {
            override fun setAudioDevice(on: Boolean) {
                if (on) {
                    inside.countDown()
                    release.await(5, TimeUnit.SECONDS)
                }
            }

            override fun setMicrophone(on: Boolean) = Unit

            override fun setPlayback(on: Boolean) = Unit
        }
        val platform = Platform()
        val control = VoiceCallControl(platform, switches)
        assertTrue(control.permit("voice-session-1", platform.closesIn(60)))
        val change = thread { control.servicePromoted() }
        assertTrue("the change reached the switch", inside.await(5, TimeUnit.SECONDS))

        val answered = CountDownLatch(1)
        val reader = thread {
            control.isStopped
            control.isPlaybackMuted
            control.isMutedByPerson
            control.carries()
            control.couldHaveHeard(1_000)
            control.displayed()
            answered.countDown()
        }
        assertTrue("every read answered while the change held the lock", answered.await(2, TimeUnit.SECONDS))
        release.countDown()
        change.join()
        reader.join()
    }

    /** An answer whose moment has already passed permits nothing and ends the call. */
    @Test
    fun an_answer_already_past_its_moment_ends_the_call() {
        val platform = Platform()
        val switches = Switches()
        val control = VoiceCallControl(platform, switches)
        assertFalse(control.permit("voice-session-1", platform.epochMs()))
        assertTrue(control.isStopped)
        assertFalse(platform.focusHeld)
        assertFalse(switches.deviceEverOn)
    }
}
