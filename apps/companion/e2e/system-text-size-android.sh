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
# Environment: KR_ANDROID_AVD names the virtual device (default: the first one listed);
# KR_TEXT_SIZE_SHOTS is where its screenshots go (default /tmp). It refuses an emulator that was
# already running, whose settings are not its to change, and leaves the font scale as it found it.
# Exit status: 0 when every scale held, 1 when one did not, 3 when there is nothing to run on.
set -u
apk=${1:-}
[ -f "$apk" ] || { echo "usage: system-text-size-android.sh <path of the harness build's .apk>"; exit 3; }
sdk=${ANDROID_HOME:-$HOME/Library/Android/sdk}
adb=$sdk/platform-tools/adb
emulator=$sdk/emulator/emulator
[ -x "$adb" ] && [ -x "$emulator" ] || { echo "no Android platform tools or emulator"; exit 3; }
avd=${KR_ANDROID_AVD:-$("$emulator" -list-avds | head -n 1)}
[ -n "$avd" ] || { echo "no Android virtual device"; exit 3; }
if "$adb" devices | grep -q '^emulator-'; then
  echo "an emulator is already running: its font scale is not this script's to change"
  exit 3
fi

"$emulator" -avd "$avd" -read-only -no-window -no-audio -no-snapshot-save -no-boot-anim \
  >"${TMPDIR:-/tmp}/kr-text-size-emulator.log" 2>&1 &
emulator_pid=$!
cleanup() {
  "$adb" shell settings put system font_scale 1.0 >/dev/null 2>&1
  "$adb" uninstall to.kala.reach >/dev/null 2>&1
  kill "$emulator_pid" 2>/dev/null
}
trap cleanup EXIT
"$adb" wait-for-device
for _ in $(seq 1 150); do
  [ "$("$adb" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && break
  sleep 2
done
echo "emulator: $("$adb" shell getprop ro.product.model | tr -d '\r'), API $("$adb" shell getprop ro.build.version.sdk | tr -d '\r')"
"$adb" shell "settings put system font_scale 1.0; settings put global window_animation_scale 0; settings put global transition_animation_scale 0; settings put global animator_duration_scale 0"
"$adb" uninstall to.kala.reach >/dev/null 2>&1
"$adb" install -r "$apk" >/dev/null || { echo "the application did not install"; exit 1; }
"$adb" shell am start -n to.kala.reach/.MainActivity >/dev/null

# Not `exec`: the shell stays to stop the emulator when the checks end.
ADB=$adb SHOTS=${KR_TEXT_SIZE_SHOTS:-/tmp} node --input-type=module - <<'JS'
import { execFileSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import process from 'node:process'

const adb = process.env.ADB
const shots = process.env.SHOTS
const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const LINE = 'Find why the reconnect test is flaky.'
const BASE_ROOT = 16

const run = (...args) => execFileSync(adb, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
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
    const list = await (await fetch(`http://127.0.0.1:${port}/json`)).json()
    return list.find((entry) => entry.type === 'page') ?? null
  })
  const socket = new WebSocket(page.webSocketDebuggerUrl)
  await new Promise((resolve, reject) => {
    socket.onopen = resolve
    socket.onerror = reject
  })
  let next = 0
  const waiting = new Map()
  socket.onmessage = (message) => {
    const data = JSON.parse(message.data)
    if (waiting.has(data.id)) waiting.get(data.id)(data)
  }
  const send = (method, params = {}) =>
    new Promise((resolve) => {
      next += 1
      waiting.set(next, resolve)
      socket.send(JSON.stringify({ id: next, method, params }))
    })
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
        await page.send('Page.navigate', { url: CONVERSATION })
        return await waitFor('the conversation to show', async () => {
          const said = await page.evaluate(READ)
          const value = JSON.parse(said ?? 'null')
          if (!(value && Math.abs(value.root - expected) < 0.05 && value.line > 0)) throw new Error(`the page said ${said}`)
          return JSON.stringify(value)
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
    if (Number(scale) > 1) {
      check(
        seen.line > atDefault.line * 1.3,
        `font scale ${scale}: a line of the conversation is ${seen.line.toFixed(1)}px tall, against ${atDefault.line.toFixed(1)}px at the default scale`
      )
    }
    console.log(`INFO: font scale ${scale}: the top bar is ${seen.top.toFixed(1)}px and the tab bar ${seen.bottom.toFixed(1)}px`)
    const png = execFileSync(adb, ['exec-out', 'screencap', '-p'], { maxBuffer: 64 * 1024 * 1024 })
    writeFileSync(join(shots, `kr-text-size-android-${scale}.png`), png)
  }
} catch (failure) {
  console.log(`FAIL: ${failure.message}`)
  failures += 1
}
console.log(failures === 0 ? 'every scale held' : `${failures} did not hold`)
process.exit(failures === 0 ? 0 : 1)
JS
exit $?
