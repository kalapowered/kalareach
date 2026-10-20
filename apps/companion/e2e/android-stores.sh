#!/bin/bash
# Holds, on the Android emulator, that the packaged application keeps what it stores on the phone:
# the drafts and the device that owns them, the removals still to be made, and the pairing records
# and their attempt budget, and that the lock of the answers kept on the device holds against a
# second process.
#
# It installs the debug application, opens the page's debugging socket, and calls the application's
# own commands the way the page does. It keeps no answer and no attempt, which need a host: a
# kept answer is reached through the lock a window takes before it changes one, and the attempts
# kept for a share's actions only through a connection to a host. A store the phone cannot use
# answers with the failure the command carries, and the run says which one. The lock between
# processes is checked with the system's own `flock` run under the application's identity: that
# process holds the kept answers' lock file, and the application's command for dismissing a kept
# answer, which takes that lock first, must refuse to go on while it is held and go on once it is
# let go.
#
# It must run inside the device lease, which also stops what it started:
#
#   pnpm -C apps/companion android --debug --target aarch64
#   bash <lease script> <label> apps/companion/e2e/android-stores.sh <path of the .apk>
#
# Environment: KR_ANDROID_AVD names the virtual device (default: KalaReach_API_36_Play);
# KR_ANDROID_EMULATOR_PORT is the port the emulator is started on (default 5580). Every command goes
# to the one emulator this script starts, named by its own serial: ANDROID_SERIAL is cleared, so a
# phone that is connected is never touched, and an emulator that was already running is refused.
# Exit status: 0 when every check held, 1 when one did not, 3 when there is nothing to run on.
set -u
unset ANDROID_SERIAL
apk=${1:-}
[ -f "$apk" ] || { echo "usage: android-stores.sh <path of the debug application's .apk>"; exit 3; }
sdk=${ANDROID_HOME:-$HOME/Library/Android/sdk}
adb=$sdk/platform-tools/adb
emulator=$sdk/emulator/emulator
[ -x "$adb" ] && [ -x "$emulator" ] || { echo "no Android platform tools or emulator"; exit 3; }
command -v timeout >/dev/null || { echo "the timeout command is needed (coreutils)"; exit 3; }
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scripts/lib/android-avd.sh"
avd=$(kr_android_avd "$emulator") || { echo "$avd"; exit 3; }
if timeout --foreground -k 10 60 "$adb" devices | grep -q '^emulator-'; then
  echo "an emulator is already running: it is not this script's to use"
  exit 3
fi
port=${KR_ANDROID_EMULATOR_PORT:-5580}
serial=emulator-$port
dev() { timeout --foreground -k 10 60 "$adb" -s "$serial" "$@"; }

"$emulator" -avd "$avd" -port "$port" -read-only -no-window -no-audio -no-snapshot-save -no-boot-anim \
  >"${TMPDIR:-/tmp}/kr-android-stores-emulator.log" 2>&1 &
emulator_pid=$!
checks_pid=""
installed=0
cleanup() {
  trap '' INT TERM HUP
  [ -n "$checks_pid" ] && kill "$checks_pid" 2>/dev/null
  [ "$installed" = 1 ] && dev uninstall to.kala.reach >/dev/null 2>&1
  kill "$emulator_pid" 2>/dev/null
  for _ in $(seq 1 30); do
    kill -0 "$emulator_pid" 2>/dev/null || return 0
    sleep 1
  done
  kill -9 "$emulator_pid" 2>/dev/null
}
trap cleanup EXIT

started=$(date +%s)
until [ "$(dev shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do
  if ! kill -0 "$emulator_pid" 2>/dev/null; then echo "the emulator stopped before it started"; exit 3; fi
  if [ $(( $(date +%s) - started )) -gt 300 ]; then echo "the emulator did not finish starting"; exit 3; fi
  sleep 2
done
[ "$(dev emu avd name 2>/dev/null | head -n 1 | tr -d '\r')" = "$avd" ] || { echo "$serial is not the emulator that was started"; exit 3; }
echo "emulator: $(dev shell getprop ro.product.model | tr -d '\r'), API $(dev shell getprop ro.build.version.sdk | tr -d '\r'), SELinux $(dev shell getenforce | tr -d '\r')"
dev uninstall to.kala.reach >/dev/null 2>&1
timeout --foreground -k 10 600 "$adb" -s "$serial" install -r "$apk" >/dev/null || { echo "the application did not install"; exit 1; }
installed=1
dev logcat -b all -c
dev shell am start -n to.kala.reach/.MainActivity >/dev/null

ADB=$adb SERIAL=$serial node --input-type=module - <<'JS' &
import { execFileSync, spawn } from 'node:child_process'
import process from 'node:process'

const adb = process.env.ADB
const serial = process.env.SERIAL
const PACKAGE = 'to.kala.reach'
const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000102'
const QUESTION = '8a7b6c50-22bb-4c3d-8e4f-000000000301'
// What the second process runs under the application's identity: the system's flock takes a
// descriptor, so the shell opens the lock file as descriptor 9 for a subshell, which keeps it open
// (and so keeps the lock) while it waits for its input to end.
const HOLD = '( flock -x 9 && echo held && read line ) 9<>kept-answers/.windows.lock'

const run = (...args) =>
  execFileSync(adb, ['-s', serial, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 60_000,
    maxBuffer: 64 * 1024 * 1024
  })
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const within = (what, limitMs, promise) =>
  Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`gave up waiting for ${what}`)), limitMs))
  ])
const waitFor = async (what, ready, limitMs = 120_000) => {
  const started = Date.now()
  let last = 'nothing yet'
  for (;;) {
    const answer = await ready().catch((failure) => {
      last = String(failure)
      return null
    })
    if (answer) return answer
    if (Date.now() - started > limitMs) throw new Error(`gave up waiting for ${what} (last: ${last})`)
    await wait(250)
  }
}

let failures = 0
const check = (condition, message) => {
  console.log(`${condition ? 'PASS' : 'FAIL'}: ${message}`)
  if (!condition) failures += 1
}

/** The page, over the web view's debugging socket. */
async function connect() {
  const pid = (await waitFor('the application to start', async () => run('shell', 'pidof', PACKAGE).trim() || null)).split(/\s+/)[0]
  const sockets = await waitFor('the web view to open its debugging socket', async () => {
    const found = run('shell', 'cat /proc/net/unix')
      .split('\n')
      .map((line) => line.trim().split(/\s+/).pop())
      .filter((name) => name?.startsWith(`@webview_devtools_remote_${pid}`))
    return found.length > 0 ? found : null
  })
  const port = 9400 + (Number(pid) % 500)
  run('forward', `tcp:${port}`, `localabstract:${sockets[0].slice(1)}`)
  const page = await waitFor('the page to be listed', async () => {
    const list = await (await fetch(`http://127.0.0.1:${port}/json`, { signal: AbortSignal.timeout(5_000) })).json()
    return list.find((entry) => entry.type === 'page') ?? null
  })
  const socket = new WebSocket(page.webSocketDebuggerUrl)
  await within('the debugging socket to open', 10_000, new Promise((resolve, reject) => {
    socket.onopen = resolve
    socket.onerror = reject
  }))
  let next = 0
  const waiting = new Map()
  socket.onclose = socket.onerror = () => {
    for (const entry of waiting.values()) entry.reject(new Error('the debugging socket closed'))
    waiting.clear()
  }
  socket.onmessage = (message) => {
    const data = JSON.parse(message.data)
    const answer = waiting.get(data.id)
    if (answer) {
      waiting.delete(data.id)
      answer.resolve(data)
    }
  }
  const evaluate = (expression, limitMs = 20_000) =>
    within(`${expression.slice(0, 60)} to be answered`, limitMs, new Promise((resolve, reject) => {
      next += 1
      waiting.set(next, { resolve, reject })
      socket.send(JSON.stringify({ id: next, method: 'Runtime.evaluate', params: { expression, awaitPromise: true, returnByValue: true } }))
    })).then((answer) => answer.result?.result?.value)
  return { evaluate, close: () => socket.close() }
}

const page = await connect()
await waitFor('the page to hold the application commands', async () =>
  (await page.evaluate('typeof window.__TAURI_INTERNALS__?.invoke')) === 'function' ? true : null
)

/** Calls one of the application's commands as the page does: what it answers, or why it refused. */
const call = async (command, args = {}, limitMs = 20_000) =>
  (await page.evaluate(
    `window.__TAURI_INTERNALS__.invoke(${JSON.stringify(command)}, ${JSON.stringify(args)}).then(
       (value) => ({ answered: value }),
       (error) => ({ refused: String((error && error.message) || JSON.stringify(error)) })
     )`,
    limitMs
  )) ?? { refused: 'no answer' }
const refusal = (answer) => (answer.refused === undefined ? '' : ` (refused: ${answer.refused})`)

try {
  // The drafts: the store of the device that owns them is made on the first call.
  const first = await call('device_drafts')
  check(first.answered !== undefined && Array.isArray(first.answered.drafts), `the drafts are read${refusal(first)}`)

  const save = (extra) =>
    call('device_draft_save', {
      params: {
        id: null,
        expectedRevision: null,
        sessionId: SESSION,
        applicationInstanceId: null,
        agentBindingRevision: null,
        state: 'open',
        text: 'a thought kept on the phone',
        attachments: [],
        ...extra
      }
    })
  const saved = await save({})
  const draft = saved.answered?.draft
  check(saved.answered?.outcome === 'stored' && typeof draft?.id === 'string', `a draft is saved${refusal(saved)}`)

  const listed = await call('device_drafts')
  check(
    listed.answered?.drafts?.some((held) => held.id === draft?.id && held.text === 'a thought kept on the phone') === true,
    `the draft is read back${refusal(listed)}`
  )

  const changed = draft
    ? await save({ id: draft.id, expectedRevision: draft.revision, text: 'the same thought, changed' })
    : { refused: 'there is no draft to change' }
  check(
    changed.answered?.outcome === 'stored' && changed.answered.draft.revision !== draft.revision,
    `the draft is changed at the version it was read at${refusal(changed)}`
  )

  // The ledger of removals still to be made has a lock of its own.
  const current = changed.answered?.draft ?? draft
  const marked = current ? await call('device_draft_mark_removal', { params: { id: current.id, expectedRevision: current.revision } }) : { refused: 'there is no draft' }
  check(marked.refused === undefined, `a removal still to be made is recorded${refusal(marked)}`)
  const pending = await call('device_drafts')
  check(
    pending.answered?.pendingRemovals?.some((removal) => removal.id === current?.id) === true,
    `the recorded removal is read back${refusal(pending)}`
  )
  const discarded = current ? await call('device_draft_discard', { params: { id: current.id, expectedRevision: current.revision } }) : { refused: 'there is no draft' }
  check(discarded.answered?.removed === true, `the draft is discarded${refusal(discarded)}`)
  const empty = await call('device_drafts')
  check(
    empty.answered?.drafts?.length === 0 && empty.answered?.pendingRemovals?.length === 0,
    `nothing is left of it, in the store or in the ledger${refusal(empty)}`
  )

  // The pairing records open at the start: the device's keys in the application's secure store,
  // and the attempt budget under its lock.
  const pairing = await call('pairing_view')
  check(
    typeof pairing.answered?.device_name === 'string' && Array.isArray(pairing.answered?.hosts),
    `the pairing records are open${refusal(pairing)}`
  )

  // A kept answer that is not there: dismissing it takes the lock every window holds, and finds
  // nothing to remove.
  const dismissed = await call('question_dismiss_kept', { params: { questionId: QUESTION, draftedAtMs: 1 } })
  check(dismissed.answered === false, `a kept answer that is not there is not dismissed${refusal(dismissed)}`)

  // A second process holds that lock: the dismissal must refuse to go on while it does, and go on
  // once it lets go. The holder is the system's flock under the application's identity; it reports
  // when it holds the lock and lets go when its input ends.
  const holder = spawn(
    adb,
    ['-s', serial, 'shell', `run-as ${PACKAGE} sh -c '${HOLD}'`],
    { stdio: ['pipe', 'pipe', 'inherit'] }
  )
  const ended = new Promise((resolve) => holder.on('exit', resolve))
  try {
    await within('the second process to hold the lock', 30_000, new Promise((resolve, reject) => {
      holder.stdout.on('data', (chunk) => String(chunk).includes('held') && resolve())
      ended.then(() => reject(new Error('the second process ended without holding the lock')))
    }))
    const blocked = await call('question_dismiss_kept', { params: { questionId: QUESTION, draftedAtMs: 1 } }, 150_000)
    check(
      blocked.refused !== undefined && /another window/.test(blocked.refused),
      `a lock another process holds keeps the dismissal out${blocked.answered === undefined ? '' : ` (it answered ${JSON.stringify(blocked.answered)})`}`
    )
  } catch (failure) {
    check(false, `a lock another process holds keeps the dismissal out (${failure.message})`)
  } finally {
    holder.stdin.end()
  }
  await within('the second process to let go', 30_000, ended)
  const after = await call('question_dismiss_kept', { params: { questionId: QUESTION, draftedAtMs: 1 } })
  check(after.answered === false, `and once it lets go the dismissal goes on${refusal(after)}`)

  // What the stores left in the application's directory: the owner of the drafts, and no file a
  // publication staged and did not give its name.
  const names = run('shell', `run-as ${PACKAGE} ls -a .`).split('\n').map((line) => line.trim())
  check(names.includes('drafts-owner'), 'the file that names the device owning the drafts is there')
  check(!names.some((name) => name.startsWith('.') && name.endsWith('.tmp')), 'and no staged file is left beside it')
  // The policy's refusals of the application: on its own files there must be none. A refusal of
  // the flush of a directory that belongs to the system (the root, `/data`) is the walk to the
  // store's directory being told it may not open it, which it passes over; those are listed.
  const refused = run('logcat', '-b', 'all', '-d').split('\n').filter((line) => /avc: +denied/.test(line) && line.includes(`app=${PACKAGE}`))
  const own = refused.filter((line) => line.includes('tcontext=u:object_r:app_data_file'))
  check(own.length === 0, `the security policy refused the application nothing on its own files${own.length === 0 ? '' : `: ${own[0].slice(0, 300)}`}`)
  for (const line of refused.filter((line) => !own.includes(line))) console.log(`INFO: ${line.replace(/^.*avc: +/, 'avc: ').slice(0, 220)}`)
} catch (failure) {
  console.log(`FAIL: ${failure.message}`)
  failures += 1
} finally {
  page.close()
}
console.log(failures === 0 ? 'every store held' : `${failures} did not hold`)
process.exit(failures === 0 ? 0 : 1)
JS
checks_pid=$!
wait "$checks_pid"
status=$?
checks_pid=""
exit $status
