#!/bin/bash
# Holds, on the Android emulator's Chrome, that a session screen whose opening the host ended says so
# inside the screen at the default font scale and at a large one, with its buttons a finger tall.
#
# The harness bundle is served on this machine and opened in Chrome on the emulator, through a reverse of
# the server's port, inside a frame of a wrapper page. The wrapper makes the scripted host end
# the share the screen runs under and reports what the page shows of it: the banner's words, where its
# edges are, how tall its buttons are, what the status region says. The system's font scale is set to
# each value in turn, with the page left open. It waits on those conditions and on no delay; a limit
# exists only so that a run that never gets there stops and says what it was waiting for.
#
# It must run inside the device lease, which also stops what it started:
#
#   pnpm -C apps/companion build:harness
#   bash <lease script> <label> apps/companion/e2e/standing-emulator.sh
#
# Environment: KR_ANDROID_AVD names the virtual device (default: the first one listed);
# KR_STANDING_SHOTS is where its screenshots go (default /tmp). Every command goes to the one emulator
# this script starts, named by its own serial: ANDROID_SERIAL is cleared, so a phone that is connected
# is never touched, and an emulator that was already running is refused, because its settings are not
# this script's to change. The font scale is put back as it was found. Exit status: 0 when every scale
# held, 1 when one did not, 3 when there is nothing to run on.
set -u
unset ANDROID_SERIAL
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dist=${KR_HARNESS_DIST:-$here/dist-harness}
[ -f "$dist/harness.html" ] || { echo "no built harness at $dist: run pnpm -C apps/companion build:harness"; exit 3; }
sdk=${ANDROID_HOME:-$HOME/Library/Android/sdk}
adb=$sdk/platform-tools/adb
emulator=$sdk/emulator/emulator
[ -x "$adb" ] && [ -x "$emulator" ] || { echo "no Android platform tools or emulator"; exit 3; }
command -v timeout >/dev/null || { echo "the timeout command is needed (coreutils)"; exit 3; }
avd=${KR_ANDROID_AVD:-$("$emulator" -list-avds | head -n 1)}
[ -n "$avd" ] || { echo "no Android virtual device"; exit 3; }
if timeout --foreground -k 10 60 "$adb" devices | grep -q '^emulator-'; then
  echo "an emulator is already running: its font scale is not this script's to change"
  exit 3
fi
port=${KR_ANDROID_EMULATOR_PORT:-5580}
serial=emulator-$port
dev() { timeout --foreground -k 10 60 "$adb" -s "$serial" "$@"; }

"$emulator" -avd "$avd" -port "$port" -read-only -no-window -no-audio -no-snapshot-save -no-boot-anim \
  >"${TMPDIR:-/tmp}/kr-standing-emulator.log" 2>&1 &
emulator_pid=$!
scale_before=""
checks_pid=""
cleanup() {
  trap '' INT TERM HUP
  [ -n "$checks_pid" ] && kill "$checks_pid" 2>/dev/null
  if [ -n "$scale_before" ]; then
    dev shell settings put system font_scale "$scale_before" >/dev/null 2>&1
  fi
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
kill -0 "$emulator_pid" 2>/dev/null || { echo "the emulator stopped before it started"; exit 3; }
[ "$(dev emu avd name 2>/dev/null | head -n 1 | tr -d '\r')" = "$avd" ] || { echo "$serial is not the emulator that was started"; exit 3; }
scale_before=$(dev shell settings get system font_scale | tr -d '\r')
[ "$scale_before" = null ] && scale_before=1.0
echo "emulator: $(dev shell getprop ro.product.model | tr -d '\r'), API $(dev shell getprop ro.build.version.sdk | tr -d '\r'), font scale $scale_before"
dev shell "settings put system font_scale 1.0; settings put global window_animation_scale 0; settings put global transition_animation_scale 0; settings put global animator_duration_scale 0"

ADB=$adb SERIAL=$serial DIST=$dist node --input-type=module - <<'JS' &
import { execFileSync } from 'node:child_process'
import { createReadStream, existsSync, statSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { extname, join, normalize } from 'node:path'

const root = process.env.DIST
const adb = process.env.ADB
const serial = process.env.SERIAL
const shots = process.env.KR_STANDING_SHOTS ?? '/tmp'
const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** The font scales held: the default and a large one. */
const SCALES = ['1.0', '2.0']
const FINGER = 44

const wrapper = `<!doctype html><meta name="viewport" content="width=device-width, initial-scale=1">
<style>html,body{margin:0;height:100%}iframe{border:0;width:100%;height:100%}</style>
<iframe id="page" src="/harness.html?surface=android&session=${SESSION}"></iframe>
<script>
const frame = document.getElementById('page')
let ended = false
let applied = '1'
const send = () => {
  const view = frame.contentWindow
  const doc = frame.contentDocument
  const host = view && view.krTestHost
  if (!doc || !doc.documentElement || !host) return
  if (!ended && host.standings.tokenOf(${JSON.stringify(SESSION)})) {
    ended = true
    host.standings.say(${JSON.stringify(SESSION)}, { state: 'ended', reason: 'revoked' })
  }
  fetch('/scale').then((answer) => answer.text()).then((wanted) => {
    // Chrome carries no system font scale to a page; the Android web view multiplies the page's root by
    // it, which the page's own text scale does, so the wrapper sets that, as the harness's tests do.
    if (wanted !== applied) {
      applied = wanted
      doc.documentElement.style.setProperty('--text-scale', wanted)
    }
  })
  const banner = doc.querySelector('[data-testid="standing-banner"]')
  const edge = banner ? banner.getBoundingClientRect() : null
  const body = {
    root: parseFloat(view.getComputedStyle(doc.documentElement).fontSize),
    banner: banner ? banner.textContent : null,
    shown: banner ? banner.getAttribute('data-shown') : null,
    left: edge ? edge.left : 0,
    right: edge ? edge.right : 0,
    buttons: banner ? [...banner.querySelectorAll('button')].map((each) => each.getBoundingClientRect().height) : [],
    status: (doc.querySelector('[data-testid="standing-status"]') || {}).textContent || '',
    send: (() => { const b = [...doc.querySelectorAll('button')].find((each) => each.textContent === 'Send'); return b ? b.disabled : null })(),
    wide: doc.documentElement.scrollWidth,
    screen: view.innerWidth
  }
  fetch('/report', { method: 'POST', body: JSON.stringify(body) })
}
setInterval(send, 400)
</script>`

const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.woff': 'font/woff', '.woff2': 'font/woff2' }
let latest = null
let wantedScale = '1'
const server = createServer((request, response) => {
  const path = new URL(request.url ?? '/', 'http://localhost').pathname
  if (path === '/scale') {
    response.end(wantedScale)
    return
  }
  if (path === '/report') {
    let text = ''
    request.on('data', (chunk) => (text += chunk))
    request.on('end', () => {
      latest = JSON.parse(text)
      response.end('ok')
    })
    return
  }
  if (path === '/wrapper.html') {
    response.setHeader('content-type', 'text/html')
    response.end(wrapper)
    return
  }
  const file = join(root, normalize(path).replace(/^(\.\.[/\\])+/, ''))
  if (!file.startsWith(root) || !existsSync(file) || !statSync(file).isFile()) {
    response.statusCode = 404
    response.end('not found')
    return
  }
  response.setHeader('content-type', types[extname(file)] ?? 'application/octet-stream')
  createReadStream(file).pipe(response)
})
await new Promise((resolve) => server.listen(0, resolve))
const port = server.address().port

const run = (...args) => execFileSync(adb, ['-s', serial, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 60_000 })
const waitFor = async (what, ready, limitMs = 180_000) => {
  const started = Date.now()
  while (!ready()) {
    if (Date.now() - started > limitMs) throw new Error(`gave up waiting for ${what}`)
    await new Promise((resolve) => setTimeout(resolve, 250))
  }
}

let failures = 0
const check = (condition, message) => {
  console.log(`${condition ? 'PASS' : 'FAIL'}: ${message}`)
  if (!condition) failures += 1
}

try {
  // Chrome, at this machine's server through a reverse of the port, which the emulator's own
  // `localhost` then reaches.
  run('reverse', `tcp:${port}`, `tcp:${port}`)
  run('shell', 'pm', 'clear', 'com.android.chrome')
  run('shell', 'am', 'start', '-a', 'android.intent.action.VIEW', '-d', `http://localhost:${port}/wrapper.html`, 'com.android.chrome')
  // Chrome's first start asks questions before it shows a page: the answers that decline an account,
  // sync and notifications are tapped until the page speaks.
  const DECLINE = ['Use without an account', 'No thanks', 'Not now', 'Got it', 'Accept & continue']
  const decline = () => {
    try {
      run('shell', 'uiautomator', 'dump', '/sdcard/kr-ui.xml')
      const xml = run('shell', 'cat', '/sdcard/kr-ui.xml')
      for (const label of DECLINE) {
        const node = xml.match(new RegExp(`text="${label}"[^>]*bounds="\\[(\\d+),(\\d+)\\]\\[(\\d+),(\\d+)\\]"`))
        if (node) {
          const [x1, y1, x2, y2] = node.slice(1).map(Number)
          run('shell', 'input', 'tap', String(Math.round((x1 + x2) / 2)), String(Math.round((y1 + y2) / 2)))
          return
        }
      }
    } catch {
      // The screen was not ready to be read; it is read again.
    }
  }
  await waitFor('the page to say the share ended', () => {
    if (latest !== null && latest.banner !== null && latest.shown === 'true') return true
    decline()
    return false
  })
  for (const scale of SCALES) {
    run('shell', 'settings', 'put', 'system', 'font_scale', scale)
    wantedScale = String(Number(scale))
    // The page, still open, is what is asked: it lays out again at the new scale.
    await waitFor(
      `the page to lay out at font scale ${scale}`,
      () => latest !== null && latest.banner !== null && Math.abs(latest.root - 16 * Number(scale)) < 0.05
    ).catch((failure) => {
      console.log(`FAIL: ${failure.message}; the page said ${JSON.stringify(latest)}`)
      failures += 1
    })
    const seen = latest
    console.log(`INFO: font scale ${scale}: the root text is ${seen?.root}px (the system's scale is carried to the page by the wrapper, as the Android web view carries it)`)
    check(seen !== null && (seen.banner ?? '').includes('This share ended'), `font scale ${scale}: the banner says the share ended`)
    check(seen !== null && seen.status.includes('This share ended'), `font scale ${scale}: the status region says it once`)
    check(seen !== null && seen.send === true, `font scale ${scale}: Send is turned off`)
    check(seen !== null && seen.left >= 0 && seen.right <= seen.screen + 0.5, `font scale ${scale}: the banner is inside the screen (${seen?.left}..${seen?.right} of ${seen?.screen})`)
    check(seen !== null && seen.wide <= seen.screen, `font scale ${scale}: the page is no wider than the screen (${seen?.wide} of ${seen?.screen})`)
    check(
      seen !== null && seen.buttons.length > 0 && seen.buttons.every((height) => height + 0.5 >= FINGER),
      `font scale ${scale}: the banner's buttons are ${seen?.buttons.map((height) => height.toFixed(1)).join(', ')}px tall, at least ${FINGER}`
    )
    const png = execFileSync(adb, ['-s', serial, 'exec-out', 'screencap', '-p'], { maxBuffer: 64 * 1024 * 1024, timeout: 60_000 })
    writeFileSync(join(shots, `kr-standing-android-${scale}.png`), png)
  }
} catch (failure) {
  console.log(`FAIL: ${failure.message}`)
  failures += 1
  // What the device shows when the page never said anything, to see what Chrome is waiting on.
  try {
    writeFileSync(join(shots, 'kr-standing-android-stuck.png'), execFileSync(adb, ['-s', serial, 'exec-out', 'screencap', '-p'], { maxBuffer: 64 * 1024 * 1024, timeout: 60_000 }))
    const resumed = run('shell', 'dumpsys', 'activity', 'activities').split('\n').find((line) => line.includes('ResumedActivity'))
    console.log(`INFO: the foreground activity is ${resumed?.trim()}`)
  } catch (diagnosis) {
    console.log(`INFO: no picture of the device: ${diagnosis.message}`)
  }
} finally {
  server.close()
}
console.log(failures === 0 ? 'every scale held' : `${failures} did not hold`)
process.exit(failures === 0 ? 0 : 1)
JS
checks_pid=$!
wait "$checks_pid"
status=$?
checks_pid=""
exit $status
