/**
 * The words for a failure (KR-REQ-23.57), through the boundary.
 *
 * Section 23: the interface translates a code into a direct action and does not display raw
 * protocol internals by default. Native code attaches the key of the action a code maps to to each
 * failure it answers with. The desktop port is the one place that takes that in (`src/host/tauri.ts`):
 * it turns the failure at once into the line the page shows, the host's own words and, after them,
 * what the person can do about it where the words do not say it. The page's failure has no member
 * for the action, so no other module can read it or say it a second time.
 *
 * Every case below gives the boundary the raw shape native code sends, through the bridge's own
 * `invoke`, and asserts the whole line that the page shows.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'

import {
  failureCode,
  failureMessage,
  failureRetry,
  failureWords,
  type HostError,
  type VoiceClosure
} from '../src/host/port'
import { receivedFailure, tauriPort } from '../src/host/tauri'

import retrySource from '../../../crates/kr-client/src/retry.rs?raw'
import capacityRefusals from './fixtures/capacity-refusals.json'

const bridge = vi.hoisted(() => ({
  /** What a command answers, by its name: a value, or a rejection. One not named answers null. */
  answers: new Map<string, { readonly rejects: boolean; readonly value: unknown }>(),
  invoked: [] as { command: string; options?: unknown }[]
}))

vi.mock('@tauri-apps/api/core', () => ({
  invoke: (command: string, _args: unknown, options?: unknown) => {
    bridge.invoked.push(options === undefined ? { command } : { command, options })
    const answer = bridge.answers.get(command)
    if (answer?.rejects === true) return Promise.reject(answer.value)
    return Promise.resolve(answer === undefined ? null : answer.value)
  },
  Channel: class {
    onmessage: (message: unknown) => void = () => undefined
  }
}))

vi.mock('@tauri-apps/api/event', () => ({
  listen: () => Promise.resolve(() => undefined)
}))

beforeEach(() => {
  bridge.answers.clear()
  bridge.invoked.length = 0
})

/** What a command that native code rejects with `native` rejects with once it is through the boundary. */
async function rejectedWith(native: unknown, command = 'account_status'): Promise<unknown> {
  bridge.answers.set(command, { rejects: true, value: native })
  try {
    await tauriPort().accountStatus()
  } catch (failure) {
    return failure
  }
  throw new Error('the command did not reject')
}

/** A native failure as the golden file holds it. */
const native = (code: string, message: string, user_action: string) => ({
  code,
  message,
  user_action,
  retry: 'transient' as const
})

/** The library's own sentence for each action key, read from its source. */
function libraryActions(): Record<string, string> {
  // The arms of `UserAction::as_str` name the keys and the arms of `UserAction::message` the words.
  const arms = (from: string, to: string) => {
    const start = retrySource.indexOf(from)
    const end = retrySource.indexOf(to, start)
    const body = retrySource.slice(start, end)
    return Array.from(body.matchAll(/Self::(\w+) => "((?:[^"\\]|\\.)*)"/g), (arm) => [arm[1], arm[2]] as const)
  }
  const keys = new Map(arms('pub const fn as_str(self)', 'pub const fn message(self)'))
  const described: Record<string, string> = {}
  for (const [variant, sentence] of arms('pub const fn message(self)', '\n}\n')) {
    const key = keys.get(variant)
    if (key === undefined) throw new Error(`${variant} has no key`)
    if (sentence !== '') described[key] = sentence
  }
  return described
}

describe('the words for a failure, through the boundary', () => {
  it('offer the direct action its code translates to, and never the code', async () => {
    const said = failureMessage(
      await rejectedWith(native('OUTCOME_UNKNOWN', 'The host lost the answer.', 'check_the_outcome'))
    )
    expect(said).toBe('The host lost the answer. Check whether this went through before trying it again.')
    expect(said).not.toContain('OUTCOME_UNKNOWN')
  })

  it('say the host’s own words first and the action after them, for each action the library has', async () => {
    const actions = libraryActions()
    expect(Object.keys(actions)).toHaveLength(7)
    for (const [key, words] of Object.entries(actions)) {
      expect(
        failureMessage(await rejectedWith(native('PERMISSION_DENIED', 'The host said no.', key))),
        key
      ).toBe(`The host said no. ${words}`)
    }
  })

  it('end the host’s words before the action when they do not end a sentence themselves', async () => {
    expect(
      failureMessage(
        await rejectedWith(native('UPSTREAM_UNAVAILABLE', 'this application is not connected to a host', 'wait'))
      )
    ).toBe('this application is not connected to a host. Wait a moment and try again.')
    expect(failureMessage(await rejectedWith(native('RATE_LIMITED', 'slow down', 'wait')))).toBe(
      'slow down. Wait a moment and try again.'
    )
  })

  it('leave out the code the client library puts in front of a host’s words, as native code sends it', async () => {
    expect(
      failureMessage(
        await rejectedWith(native('UNKNOWN_SESSION', 'UNKNOWN_SESSION: no session has that number.', 'resync'))
      )
    ).toBe('no session has that number. Refresh: this view has fallen behind.')
    expect(
      failureMessage(
        await rejectedWith(native('SESSION_CLOSED', 'SESSION_CLOSED: the session closed.', 'nothing'))
      )
    ).toBe('the session closed.')
    // Only its own code goes: another code in the words is the host's to say.
    expect(
      failureMessage(
        await rejectedWith(native('SESSION_CLOSED', 'STALE_SESSION: the session closed.', 'nothing'))
      )
    ).toBe('STALE_SESSION: the session closed.')
    // A refusal with no words after the code is a failure with no words.
    expect(
      failureMessage(await rejectedWith(native('SESSION_CLOSED', 'SESSION_CLOSED: ', 'nothing')))
    ).toBe('Something went wrong.')
  })

  it('offer the action of a failure that came with no words of its own too', async () => {
    expect(
      failureMessage(await rejectedWith(native('PAIRING_EXPIRED', ' ', 'pair_again')))
    ).toBe('Something went wrong. Pair this device with the host again.')
  })

  it('keep the words alone for an action that asks nothing of the person, and for one it does not know', async () => {
    expect(
      failureMessage(await rejectedWith(native('SESSION_CLOSED', 'The session closed.', 'nothing')))
    ).toBe('The session closed.')
    expect(failureMessage(await rejectedWith(native('X', 'The host said no.', 'retry')))).toBe(
      'The host said no.'
    )
    expect(failureMessage(await rejectedWith({ code: 'X', message: 'The host said no.' }))).toBe(
      'The host said no.'
    )
    // The names of the table's own keys are not looked up on the prototype.
    expect(failureMessage(await rejectedWith(native('X', 'The host said no.', 'constructor')))).toBe(
      'The host said no.'
    )
  })

  it('hand on a rejection that is not a host failure as it came', async () => {
    const error = new Error('The call failed.')
    expect(await rejectedWith(error)).toBe(error)
    expect(failureMessage(error)).toBe('The call failed.')
    expect(await rejectedWith('the bridge said no')).toBe('the bridge said no')
    expect(await rejectedWith(null)).toBeNull()
    expect(failureMessage(await rejectedWith('the bridge said no'))).toBe('Something went wrong.')
  })

  it('hand on the code, the retry category and the words, and nothing else of what native code sent', async () => {
    const failure = await rejectedWith({
      ...native('RATE_LIMITED', 'RATE_LIMITED: slow down', 'wait'),
      retry: 'transient',
      extra: 'not the page’s'
    })
    expect(failure).toEqual({
      code: 'RATE_LIMITED',
      message: 'RATE_LIMITED: slow down',
      retry: 'transient',
      line: 'slow down. Wait a moment and try again.'
    })
    expect(Object.keys(failure as object).sort()).toEqual(['code', 'line', 'message', 'retry'])
    expect(failureCode(failure)).toBe('RATE_LIMITED')
    expect(failureRetry(failure)).toBe('transient')
    // The words alone, for a place that says what the person can do in its own words.
    expect(failureWords(failure)).toBe('slow down')
  })

  it('give the page a failure with no member for the action, by its type and by its keys', () => {
    const held: HostError = { code: 'X', message: 'm', retry: 'transient' }
    // @ts-expect-error the page's failure has no member for the action: this fails to compile if it gains one
    void held.user_action
    expect('user_action' in receivedFailure(native('X', 'm', 'wait'))).toBe(false)
  })

  it('say the line once, whatever the page makes of a failure afterwards', async () => {
    const failure = await rejectedWith(native('RATE_LIMITED', 'RATE_LIMITED: slow down', 'wait'))
    const line = 'slow down. Wait a moment and try again.'
    expect(failureMessage(failure)).toBe(line)
    // Four places rebuild a failure from the line they already have (`Conversation`, `MobileSession`,
    // `draft-book` and `opening`): nothing in what they keep adds an action's words a second time.
    const rebuilt = { code: failureCode(failure) ?? 'X', message: failureMessage(failure), retry: failureRetry(failure) }
    expect(failureMessage(rebuilt)).toBe(line)
    expect(failureMessage({ code: 'RATE_LIMITED', message: failureWords(failure) })).toBe('slow down')
  })
})

describe('a refusal that says its own wait, and every stop of the lease', () => {
  /** Every refusal native code sends, as the golden file holds it. */
  const sent = Object.entries(capacityRefusals).flatMap(([surface, kinds]) =>
    Object.entries(kinds).map(([kind, one]) => ({ name: `${surface} ${kind}`, surface, kind, ...one }))
  )

  it('is read as the whole text that native code composed, with no line of the page’s own after it', async () => {
    expect(sent.length).toBeGreaterThanOrEqual(5)
    for (const one of sent) {
      const said = failureMessage(await rejectedWith(native(one.code, one.message, one.user_action)))
      expect(said, one.name).toBe(one.page)
      if (one.user_action === 'nothing') {
        expect(said, one.name).not.toContain('Wait a moment and try again.')
      } else {
        expect(said, one.name).toMatch(/ Wait a moment and try again\.$/)
      }
    }
  })

  it('is read the same inside the inbox’s answer, where a host’s refusal is a failure in a result', async () => {
    const rows = sent.filter((one) => one.surface === 'inbox')
    expect(rows.length).toBeGreaterThanOrEqual(5)
    for (const one of rows) {
      bridge.answers.set('inbox_hosts', {
        rejects: false,
        value: [
          {
            name: 'laptop',
            state: 'refused',
            read_at_ms: null,
            lost_since_ms: null,
            refusal: native(one.code, one.message, one.user_action),
            refused_request: null,
            result: null,
            sessions: []
          }
        ]
      })
      const [host] = await tauriPort().inboxHosts()
      expect(host?.name, one.name).toBe('laptop')
      expect(failureMessage(host?.refusal), one.name).toBe(one.page)
      expect(Object.keys(host?.refusal ?? {}).sort(), one.name).toEqual(['code', 'line', 'message', 'retry'])
    }
    // A host that did not refuse has no failure to convert.
    bridge.answers.set('inbox_hosts', {
      rejects: false,
      value: [{ name: 'laptop', state: 'read', refusal: null, sessions: [] }]
    })
    expect((await tauriPort().inboxHosts())[0]?.refusal).toBeNull()
  })

  it('is read the same inside a call’s closure, where the host’s failure to take the stop is a result', async () => {
    const rows = sent.filter((one) => one.surface === 'voice_stop')
    expect(rows).toHaveLength(2)
    for (const one of rows) {
      bridge.answers.set('voice_stop', {
        rejects: false,
        value: {
          closed_locally: true,
          fence: null,
          host_failure: native(one.code, one.message, one.user_action),
          not_held: false
        }
      })
      const closure: VoiceClosure = await tauriPort().voiceStop('voice-1', {})
      expect(failureMessage(closure.host_failure), one.name).toBe(one.page)
      expect(Object.keys(closure.host_failure ?? {}).sort(), one.name).toEqual(['code', 'line', 'message', 'retry'])
      expect(closure.closed_locally).toBe(true)
    }
    bridge.answers.set('voice_stop', {
      rejects: false,
      value: { closed_locally: true, fence: null, host_failure: null, not_held: false }
    })
    expect((await tauriPort().voiceStop('voice-1', {})).host_failure).toBeNull()
  })

  it('is read the same when the bridge is called with the bytes of a file', async () => {
    const one = sent.find((each) => each.surface === 'agent_page' && each.kind === 'lease_wait')
    expect(one).toBeDefined()
    bridge.answers.set('attachment_upload_bytes', {
      rejects: true,
      value: native(one!.code, one!.message, one!.user_action)
    })
    const failure = await tauriPort()
      .attachmentUploadBytes({ name: 'a.png', bytes: new Uint8Array([1]) }, {})
      .then(
        () => undefined,
        (rejected: unknown) => rejected
      )
    expect(bridge.invoked.some((each) => each.command === 'attachment_upload_bytes')).toBe(true)
    expect(failureMessage(failure)).toBe(one!.page)
    expect(Object.keys(failure as object).sort()).toEqual(['code', 'line', 'message', 'retry'])
  })
})
