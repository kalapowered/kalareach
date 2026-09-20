/**
 * The one bound the browser tests keep, and what it is for.
 *
 * Every wait in these tests is a condition on something the interface says or shows, and a wait
 * that is met costs what it always did. A bound is here only so that a run which will never finish
 * stops and says what it was waiting for, rather than holding the machine until the whole suite
 * gives up.
 */

/**
 * How long a wait on the interface's own motion or layout is given before the run is called hung.
 *
 * It is not an estimate of how long any of it takes. A surface that travels is stepped once per
 * animation frame, and a step advances it by at most a frame's worth of its own time, so what the
 * motion costs is a *count* of frames; how long a frame lasts is the machine's answer rather than
 * this application's. The same is true of laying out a document a burst of events has just grown.
 * On a machine painting at its display's rate the sheet leaves in about half a second. On a shared
 * build runner that has just been asked for a full-page screenshot, painting drops to one frame
 * every few hundred milliseconds and the same motion takes five to nine seconds, which is what an
 * ordinary five-second bound loses to while nothing at all is wrong. Twenty seconds is the chosen
 * liveness limit against those measurements: it is four times the slowest case seen, and it leaves
 * the whole of a test inside the project's own thirty-second limit. A machine can always be slow
 * enough to pass any fixed figure, so this does not prove a page has stopped; it is the point past
 * which waiting any longer is worth less than being told what the wait was for.
 */
export const PRESENTATION_DEADLINE = 20_000
