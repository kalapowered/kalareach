/**
 * What the sharing screens and the scripted host tell a person when a device's pairing ends before
 * a share would, or within a minute: the host refuses a new pairing of a device it still lists, so
 * a sentence that says to pair the device again says when that works, and the scripted host says
 * what the host says.
 */

import { describe, expect, it } from 'vitest'

import type { DeviceSummary, GrantCreateParams } from '@kalareach/protocol'

import { fakeHost } from '../src/host/fake'
import { SHORT_TABLET } from '../src/host/fake-state'
import { SHORTEST_LEFT_MS, whyNot } from '../src/model/sharing'

const NOW = 1_800_000_000_000
const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** A paired device that is not an owner and has a pairing that ends. */
function device(over: Partial<DeviceSummary>): DeviceSummary {
  return {
    device_id: 'd4d4d4d4-0000-4000-8000-0000000000aa',
    display_name: 'Test phone',
    grant_id: 'e5e5e5e5-0000-4000-8000-0000000000aa',
    paired_at_ms: String(NOW - 86_400_000),
    revoked: false,
    keys: null,
    manages_host: false,
    platform: 'ios',
    grant_expires_at_ms: String(NOW + 3_600_000),
    grant_expired: false,
    all_sessions: false,
    ...over
  }
}

describe('a device whose pairing ends within a minute', () => {
  it('is paired again only after its pairing has ended, and the person is told the host refuses until then', () => {
    const ending = whyNot(
      device({ grant_expires_at_ms: String(NOW + SHORTEST_LEFT_MS - 1) }),
      NOW
    )
    expect(ending).toBe(
      'Its pairing ends within a minute. Pair it again after the pairing has ended; the host refuses a new pairing while it stands.'
    )
    // Wherever the sentence says to pair the device again, it says when.
    expect(ending?.match(/Pair it again(?! after the pairing has ended)/)).toBeNull()
  })

  it('says a pairing that is out of force cannot be used now, and is paired again only after it has ended', () => {
    // The list marks the pairing as unusable while its end is still ahead: the host may hold the
    // record as live, so the end that lets a new pairing in has not been reached.
    const outOfForce = whyNot(
      device({ grant_expired: true, grant_expires_at_ms: String(NOW + 3_600_000) }),
      NOW
    )
    expect(outOfForce).toBe(
      'Its pairing cannot be used now. Pair it again after the pairing has ended; the host refuses a new pairing while it stands.'
    )
    expect(outOfForce?.match(/Pair it again(?! after the pairing has ended)/)).toBeNull()
  })
})

const hostSource = import.meta.glob('../../../crates/kr-controller/src/service/authority_changes.rs', {
  query: '?raw',
  import: 'default',
  eager: true
})

describe('the scripted host refusing a share that would outlast a pairing', () => {
  /** The host's whole refusal, read from the host's own source, with `{}` where the time left goes. */
  function hostSentence(): string {
    const [source] = Object.values(hostSource)
    if (typeof source !== 'string') throw new Error("the host's source is not there")
    const found = /"(that device's pairing ends in \{\}, before this share would; (?:[^"\\]|\\\n\s*|\\.)*)"/.exec(
      source
    )
    if (found?.[1] === undefined) throw new Error("the host's refusal is not in its source")
    // A Rust string continues over a line end that follows a backslash and drops the next indent.
    return found[1].replace(/\\\n\s*/g, '')
  }

  it('says what the host says, the time left apart, and offers a second pairing only after the pairing has ended', async () => {
    const { port } = fakeHost()
    // The scripted host's own record of a short pairing: moving its end gives each time the host
    // says. The pairing ends 40 minutes from the host's own clock until it is moved.
    const listed = await port.deviceList({ include_revoked: true })
    const tablet = listed.devices.find((each) => each.device_id === SHORT_TABLET)
    if (tablet?.grant_expires_at_ms === null || tablet?.grant_expires_at_ms === undefined) {
      throw new Error('the scripted host has no short pairing')
    }
    const hostNow = Number(tablet.grant_expires_at_ms) - 40 * 60_000
    const sentence = hostSentence()
    for (const [left, said] of [
      [40 * 60_000, '40 minutes'],
      [30_000, 'less than a minute'],
      [90_000, '1 minute'],
      [3 * 3_600_000, '3 hours'],
      [2 * 86_400_000 + 3_600_000, '2 days']
    ] as const) {
      tablet.grant_expires_at_ms = String(hostNow + left)
      const invitation: GrantCreateParams = {
        session_id: SESSION_MAIN,
        recipient_device_id: SHORT_TABLET,
        parent_grant_id: null,
        selection: {
          role: 'viewer',
          history_from_cursor_ms: null,
          include_live_screen: false,
          include_question_respond: false,
          named_questions: [],
          named_approvals: []
        },
        lifetime_ms: String(left + 3_600_000),
        accepted_notices: [],
        owner_confirmation: null
      }
      const refused: unknown = await port.grantCreate(invitation, {}).then(
        () => null,
        (error: unknown) => error
      )
      const message = (refused as { message?: string } | null)?.message ?? ''
      expect(message, `the scripted host refuses with ${said} left`).toContain('before this share would; ')
      // Every fixed word is compared; the time left is the one thing that is not, and it is one of
      // the five forms the host says it in.
      const time = new RegExp(
        "(?<=^that device's pairing ends in )(less than a minute|1 minute|\\d+ minutes|\\d+ hours|\\d+ days)(?=, before this share would; )"
      )
      expect(time.exec(message)?.[1], `${said} left`).toBe(said)
      expect(message.replace(time, '{}'), `${said} left`).toBe(sentence)
    }
    expect(sentence).toContain('pair the device again after the pairing has ended')
    expect(sentence).toContain('the host refuses a new pairing while this one stands')
  })
})
