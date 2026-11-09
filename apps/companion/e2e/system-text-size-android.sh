#!/bin/bash
# Holds, on the Android emulator, that the packaged application's text follows the system's font
# scale, and follows a change made while the application is open.
#
# It installs a build of the harness page (the interface against a scripted host, which has a
# conversation to read) and sets the system's font scale to each value in turn while the
# application is open. The system restarts the activity for the change, which reloads the page at
# the new size; the script reads the page over the web view's debugging socket, waits until it
# reports the size the scale calls for, then opens a session's conversation and measures a line of
# it. It waits on those conditions and on no delay, with a limit only so that a run that never gets
# there stops and says what it was waiting for.
#
# It must run inside the device lease, which also stops what it started:
#
#   pnpm -C apps/companion android --debug --target aarch64 --config <the harness build's settings>
#   bash <lease script> <label> apps/companion/e2e/system-text-size-android.sh <path of the .apk>
#
# Environment: the virtual device is always KalaReach_API_36_Play, and a KR_ANDROID_AVD that names another is refused;
# KR_TEXT_SIZE_SHOTS is where its screenshots go (default /tmp). Every command goes to the one
# emulator this script starts, named by its own serial: ANDROID_SERIAL is cleared, so a phone that
# is connected is never touched, and an emulator that was already running is refused, because its
# settings are not this script's to change. The font scale is put back as it was found.
# Exit status: 0 when every scale held, 1 when one did not, 3 when there is nothing to run on.
set -u
unset ANDROID_SERIAL
apk=${1:-}
[ -f "$apk" ] || { echo "usage: system-text-size-android.sh <path of the harness build's .apk>"; exit 3; }
sdk=${ANDROID_HOME:-$HOME/Library/Android/sdk}
adb=$sdk/platform-tools/adb
emulator=$sdk/emulator/emulator
[ -x "$adb" ] && [ -x "$emulator" ] || { echo "no Android platform tools or emulator"; exit 3; }
command -v timeout >/dev/null || { echo "the timeout command is needed (coreutils)"; exit 3; }
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scripts/lib/android-avd.sh"
avd=$(kr_android_avd "$emulator") || { echo "$avd"; exit 3; }
if timeout --foreground -k 10 60 "$adb" devices | grep -q '^emulator-'; then
  echo "an emulator is already running: its font scale is not this script's to change"
  exit 3
fi

# The emulator is started on a port of its own, so its serial is known before it answers, and every
# command below names it.
port=${KR_ANDROID_EMULATOR_PORT:-5580}
serial=emulator-$port
if timeout --foreground -k 10 60 "$adb" devices | grep -q "^$serial"; then
  echo "$serial is already in use"
  exit 3
fi
# Every command to the device has a limit, so one that is never answered stops and does not hold the
# run, or the clean-up that stops the emulator, for ever.
# `--foreground` keeps the command in the terminal's own process group, so an interruption reaches it.
dev() { timeout --foreground -k 10 60 "$adb" -s "$serial" "$@"; }

"$emulator" -avd "$avd" -port "$port" -read-only -no-window -no-audio -no-snapshot-save -no-boot-anim \
  >"${TMPDIR:-/tmp}/kr-text-size-emulator.log" 2>&1 &
emulator_pid=$!
scale_before=""
checks_pid=""
cleanup() {
  # A second interruption does not cut the clean-up short: it runs to its end, and every step in it
  # has a limit of its own.
  trap '' INT TERM HUP
  # The checks stop first, then what they changed is put back, then the emulator is stopped. Only a
  # device this script has seen answer as its own emulator is written to.
  [ -n "$checks_pid" ] && kill "$checks_pid" 2>/dev/null
  if [ -n "$scale_before" ]; then
    dev shell settings put system font_scale "$scale_before" >/dev/null 2>&1
    dev uninstall to.kala.reach >/dev/null 2>&1
  fi
  kill "$emulator_pid" 2>/dev/null
  # It stops in a few seconds; one that does not is stopped by force, so none is left running.
  for _ in $(seq 1 30); do
    kill -0 "$emulator_pid" 2>/dev/null || return 0
    sleep 1
  done
  kill -9 "$emulator_pid" 2>/dev/null
}
# The emulator is stopped however the script ends: the shell runs this on an interruption as well.
trap cleanup EXIT

# Waits for the emulator to say it has finished starting, for as long as it is running and for a
# limit that only stops a start that will never finish.
started=$(date +%s)
until [ "$(dev shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do
  if ! kill -0 "$emulator_pid" 2>/dev/null; then echo "the emulator stopped before it started"; exit 3; fi
  if [ $(( $(date +%s) - started )) -gt 300 ]; then echo "the emulator did not finish starting"; exit 3; fi
  sleep 2
done
# It is this script's emulator: the process it started is still running, the serial is the one asked
# for, and it answers as the virtual device that was started.
kill -0 "$emulator_pid" 2>/dev/null || { echo "the emulator stopped before it started"; exit 3; }
[ "$(dev emu avd name 2>/dev/null | head -n 1 | tr -d '\r')" = "$avd" ] || { echo "$serial is not the emulator that was started"; exit 3; }
scale_before=$(dev shell settings get system font_scale | tr -d '\r')
[ "$scale_before" = null ] && scale_before=1.0
echo "emulator: $(dev shell getprop ro.product.model | tr -d '\r'), API $(dev shell getprop ro.build.version.sdk | tr -d '\r'), font scale $scale_before"
dev shell "settings put system font_scale 1.0; settings put global window_animation_scale 0; settings put global transition_animation_scale 0; settings put global animator_duration_scale 0"
dev uninstall to.kala.reach >/dev/null 2>&1
# The package is large, so the install has a limit of its own.
timeout --foreground -k 10 600 "$adb" -s "$serial" install -r "$apk" >/dev/null
case $? in
  0) ;;
  124) echo "the application did not install within ten minutes"; exit 1 ;;
  *) echo "the application did not install"; exit 1 ;;
esac
dev shell am start -n to.kala.reach/.MainActivity >/dev/null

# Not `exec`: the shell stays to stop the emulator when the checks end, and the checks run beside it so
# that an interruption stops them as well.
ADB=$adb SERIAL=$serial SHOTS=${KR_TEXT_SIZE_SHOTS:-/tmp} node --input-type=module - <<'JS' &
import { execFileSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import process from 'node:process'

const adb = process.env.ADB
const serial = process.env.SERIAL
const shots = process.env.SHOTS
const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const LINE = 'Find why the reconnect test is flaky.'
const BASE_ROOT = 16

const run = (...args) =>
  execFileSync(adb, ['-s', serial, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 60_000 })
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
/** Gives a wait on a device a limit, so that one that is never answered stops and says so. */
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

/** Whether two boxes share any area, to within half a pixel. */
const overlap = (a, b) => a.left < b.right - 0.5 && b.left < a.right - 0.5 && a.top < b.bottom - 0.5 && b.top < a.bottom - 0.5

/**
 * What the tab bar must hold at a font scale. Every label keeps a gap from both edges of the screen
 * and from the label beside it on its row. The badge holds its digits, and all four of its edges are
 * inside the bar and the screen; where the bar has left its first form, it is clear of the glyph.
 */
function checkBar(scale, bar) {
  const near = bar.gap - 0.5
  const edges = bar.tabs.flatMap((tab) => [
    { what: `${tab.name} from the left edge`, room: tab.word.left },
    { what: `${tab.name} from the right edge`, room: bar.screen - tab.word.right }
  ])
  const short = edges.filter((edge) => edge.room < near)
  check(
    short.length === 0,
    `font scale ${scale}: every tab label is a gap (${bar.gap}px) from the screen's edges (${edges.map((edge) => `${edge.what} ${edge.room.toFixed(1)}px`).join(', ')})`
  )
  const beside = []
  for (const [at, tab] of bar.tabs.entries()) {
    for (const other of bar.tabs.slice(at + 1)) {
      const sameRow = tab.word.top < other.word.bottom - 0.5 && other.word.top < tab.word.bottom - 0.5
      if (!sameRow) continue
      // Whichever starts first is the one on the left; two that start together are as close as can be.
      const [left, right] = tab.word.left <= other.word.left ? [tab, other] : [other, tab]
      beside.push({ what: `${left.name} and ${right.name}`, room: right.word.left - left.word.right })
    }
  }
  check(
    beside.every((pair) => pair.room >= near),
    `font scale ${scale}: the tab labels on one row are a gap (${bar.gap}px) apart (${beside.length === 0 ? 'none share a row' : beside.map((pair) => `${pair.what} ${pair.room.toFixed(1)}px`).join(', ')})`
  )
  check(
    bar.tabs.length === 4 && bar.badgeTab === 0,
    `font scale ${scale}: the bar was read whole: ${bar.tabs.length} tab labels, and the badge on tab ${bar.badgeTab + 1} of them`
  )
  check(bar.holds, `font scale ${scale}: the badge holds its digits`)
  if (bar.badge !== null) {
    const count = bar.badge
    const sides = [
      { side: 'top', room: count.top - bar.bar.top },
      { side: 'bottom', room: bar.bar.bottom - count.bottom },
      { side: 'left', room: count.left - Math.max(bar.bar.left, 0) },
      { side: 'right', room: Math.min(bar.bar.right, bar.screen) - count.right }
    ]
    check(
      sides.every((each) => each.room >= -0.5),
      `font scale ${scale}: the badge's four edges are inside the bar (${sides.map((each) => `${each.side} ${each.room.toFixed(1)}px`).join(', ')})`
    )
    if (bar.form !== null && bar.glyph !== null) {
      check(!overlap(count, bar.glyph), `font scale ${scale}: the badge is clear of the glyph in the ${bar.form} form`)
    }
  }
}

/** The page, over the web view's debugging socket. */
async function connect() {
  const pid = (await waitFor('the application to start', async () => run('shell', 'pidof', 'to.kala.reach').trim() || null)).split(/\s+/)[0]
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
  const ended = (reason) => {
    for (const entry of waiting.values()) entry.reject(new Error(reason))
    waiting.clear()
  }
  socket.onclose = () => {
    ended('the debugging socket closed')
  }
  socket.onerror = () => {
    ended('the debugging socket failed')
  }
  socket.onmessage = (message) => {
    const data = JSON.parse(message.data)
    const answer = waiting.get(data.id)
    if (answer) {
      waiting.delete(data.id)
      answer.resolve(data)
    }
  }
  const send = (method, params = {}) =>
    within(`${method} to be answered`, 10_000, new Promise((resolve, reject) => {
      next += 1
      waiting.set(next, { resolve, reject })
      socket.send(JSON.stringify({ id: next, method, params }))
    }))
  const evaluate = async (expression) => {
    const answer = await send('Runtime.evaluate', { expression, returnByValue: true })
    return answer.result?.result?.value
  }
  return {
    send,
    evaluate,
    close: () => {
      socket.close()
    }
  }
}

const READ = `(() => {
  const line = [...document.querySelectorAll('p')].find((element) => element.textContent === ${JSON.stringify(LINE)})
  const bar = (selector) => document.querySelector(selector)?.getBoundingClientRect().height ?? 0
  return JSON.stringify({
    root: parseFloat(getComputedStyle(document.documentElement).fontSize),
    line: line ? line.getBoundingClientRect().height : 0,
    top: bar('.m-topbar'),
    bottom: bar('.m-tabbar'),
    wide: document.documentElement.scrollWidth,
    screen: window.innerWidth
  })
})()`

/**
 * The tab bar of the page as the application opens it, which has a count on its first tab: where each
 * label's word is, where the bar is, and where the count and its glyph are. The web view scales the
 * text and leaves a length in em where it was, which a browser's text size does not, so this is read
 * on the device.
 */
const BAR = `(() => {
  const bar = document.querySelector('.m-tabbar')
  if (!bar) return null
  const probe = document.createElement('div')
  probe.style.paddingLeft = 'var(--gap-2)'
  document.body.append(probe)
  const gap = parseFloat(getComputedStyle(probe).paddingLeft)
  probe.remove()
  const edges = (box) => ({ left: box.left, right: box.right, top: box.top, bottom: box.bottom })
  const tabs = [...bar.querySelectorAll('.m-tab-label')].map((label) => {
    const range = document.createRange()
    range.selectNodeContents(label)
    return { name: label.textContent, word: edges(range.getBoundingClientRect()) }
  })
  const badge = bar.querySelector('.m-tab-badge')
  const glyph = badge?.closest('.m-tab-glyph')?.querySelector('svg')
  return JSON.stringify({
    gap,
    form: bar.getAttribute('data-form'),
    screen: window.innerWidth,
    bar: edges(bar.getBoundingClientRect()),
    tabs,
    badge: badge ? edges(badge.getBoundingClientRect()) : null,
    badgeTab: badge ? [...bar.querySelectorAll('.m-tab')].findIndex((tab) => tab.contains(badge)) : -1,
    glyph: glyph ? edges(glyph.getBoundingClientRect()) : null,
    holds: !badge || (badge.scrollWidth <= badge.clientWidth + 0.5 && badge.scrollHeight <= badge.clientHeight + 0.5)
  })
})()`

const CONVERSATION = `http://tauri.localhost/harness.html?session=${SESSION}`

/**
 * The page at `scale`: reached afresh each time, since the system restarts the activity for the
 * change and the page of the one before is gone. Waits for the root text to be the size the scale
 * calls for, opens the conversation, and measures a line of it.
 */
async function measure(scale) {
  const expected = BASE_ROOT * Number(scale)
  return JSON.parse(
    await waitFor(`the root text to reach ${expected}px at font scale ${scale}`, async () => {
      const page = await connect()
      try {
        const root = Number(await page.evaluate('parseFloat(getComputedStyle(document.documentElement).fontSize)'))
        if (!(Math.abs(root - expected) < 0.05)) throw new Error(`the root text is ${root}px`)
        const bar = await waitFor('the first tab to show its count', async () => {
          const found = JSON.parse((await page.evaluate(BAR)) ?? 'null')
          return found?.badge ? found : null
        }, 20_000)
        await page.send('Page.navigate', { url: CONVERSATION })
        return await waitFor('the conversation to show', async () => {
          const said = await page.evaluate(READ)
          const value = JSON.parse(said ?? 'null')
          if (!(value && Math.abs(value.root - expected) < 0.05 && value.line > 0)) throw new Error(`the page said ${said}`)
          return JSON.stringify({ ...value, bar })
        }, 20_000)
      } finally {
        page.close()
      }
    })
  )
}

try {
  const atDefault = await measure('1.0')
  check(true, `font scale 1.0: the root text is ${atDefault.root}px, and a line of the conversation is ${atDefault.line.toFixed(1)}px tall`)
  checkBar('1.0', atDefault.bar)
  for (const scale of ['1.5', '2.0', '1.0']) {
    run('shell', 'settings', 'put', 'system', 'font_scale', scale)
    const seen = await measure(scale).catch((failure) => {
      console.log(`FAIL: ${failure.message}`)
      failures += 1
      return null
    })
    if (seen === null) continue
    check(true, `font scale ${scale}: the root text is ${seen.root}px, ${scale} times the base size`)
    check(seen.wide <= seen.screen, `font scale ${scale}: the page is no wider than the screen (${seen.wide} of ${seen.screen})`)
    checkBar(scale, seen.bar)
    if (Number(scale) > 1) {
      check(
        seen.line > atDefault.line * 1.3,
        `font scale ${scale}: a line of the conversation is ${seen.line.toFixed(1)}px tall, against ${atDefault.line.toFixed(1)}px at the default scale`
      )
    }
    console.log(`INFO: font scale ${scale}: the top bar is ${seen.top.toFixed(1)}px and the tab bar ${seen.bottom.toFixed(1)}px`)
    const png = execFileSync(adb, ['-s', serial, 'exec-out', 'screencap', '-p'], {
      maxBuffer: 64 * 1024 * 1024,
      timeout: 60_000
    })
    writeFileSync(join(shots, `kr-text-size-android-${scale}.png`), png)
  }
} catch (failure) {
  console.log(`FAIL: ${failure.message}`)
  failures += 1
}
console.log(failures === 0 ? 'every scale held' : `${failures} did not hold`)
process.exit(failures === 0 ? 0 : 1)
JS
checks_pid=$!
wait "$checks_pid"
status=$?
checks_pid=""
exit $status
