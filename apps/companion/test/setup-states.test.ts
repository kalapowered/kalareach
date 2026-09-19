/**
 * How a capability record becomes a state a person reads.
 *
 * These are the rules that decide what somebody is told about their own machine, so they are
 * tested on their own rather than through a screen: an answer that says "ready" where nothing was
 * established is the failure this whole flow exists to avoid.
 */

import { describe, expect, it } from 'vitest'

import type { CapabilityRecord } from '@kalareach/protocol'

import {
  capabilityLabel,
  displayState,
  STATE_LABEL,
  stateMeaning,
  tally,
  tallyLine,
  type DisplayState
} from '../src/setup/states'
import { categoriesFor, CEILING, coreCategories, featureCategories } from '../src/setup/permissions'

function record(
  capability: string,
  state: CapabilityRecord['state'],
  evidence: CapabilityRecord['evidence_source'] = 'disclosed_probe'
): CapabilityRecord {
  return {
    capability,
    version: '1',
    subject: {
      environment_id: 'e-1',
      desktop_session_id: 'd-1',
      session_id: null,
      application: null,
      terminal: null
    },
    revision: '4',
    state,
    evidence_source: evidence,
    identity: {
      binary: '/usr/sbin/screencapture',
      version: '1 bytes, digest 0',
      package: null,
      schema: null,
      profile: 'desktop_bound'
    },
    invalidation: ['binary_identity', 'os_permission', 'desktop_generation', 'worker_profile'],
    disabled_reason: null,
    observed_at_ms: '1763000000000'
  }
}

const NOT_OFFERED = { grantWasOffered: false } as const

describe('the state one capability is shown as', () => {
  it('calls a performed operation ready and nothing else', () => {
    const states: Record<CapabilityRecord['state'], DisplayState> = {
      qualified_available: 'ready',
      permission_required: 'permission_required',
      missing_installation: 'not_installed',
      incompatible: 'desktop_unavailable',
      // A check that performed the operation and got nowhere is not a desktop that is missing.
      temporarily_unavailable: 'not_established',
      not_tested: 'not_checked'
    }
    for (const [reported, shown] of Object.entries(states)) {
      expect(
        displayState(record('desktop.screen_capture', reported as CapabilityRecord['state']), NOT_OFFERED)
      ).toBe(shown)
    }
    // The same state from a question put to the platform is the desktop being unavailable.
    expect(
      displayState(
        record('desktop.screen_capture', 'temporarily_unavailable', 'platform_query'),
        NOT_OFFERED
      )
    ).toBe('desktop_unavailable')
  })

  it('never upgrades an answer the host did not establish', () => {
    for (const reported of ['not_tested', 'temporarily_unavailable', 'permission_required'] as const) {
      expect(displayState(record('desktop.screen_capture', reported), NOT_OFFERED)).not.toBe('ready')
    }
  })

  it('asks for a restart once the grant was given and the answer did not change', () => {
    const waiting = record('desktop.screen_capture', 'permission_required')
    expect(displayState(waiting, { grantWasOffered: true })).toBe('restart_required')
    expect(stateMeaning('restart_required', 'disclosed_probe')).toMatch(
      /opening KalaReach again is the next thing to try/i
    )
  })

  it('says what an answer means differently when nothing performed the operation', () => {
    expect(stateMeaning('ready', 'disclosed_probe')).toMatch(/did the thing and it worked/)
    expect(stateMeaning('ready', 'platform_query')).toMatch(/Nothing has done it yet/)
    expect(stateMeaning('desktop_unavailable', 'platform_query')).toMatch(/no desktop/)
    expect(stateMeaning('not_established', 'disclosed_probe')).toMatch(
      /did not get far enough/i
    )
  })

  it('does not ask for a restart once the operation works', () => {
    const working = record('desktop.screen_capture', 'qualified_available')
    expect(displayState(working, { grantWasOffered: true })).toBe('ready')
  })

  it('shows a capability by what it lets a person do', () => {
    expect(capabilityLabel('desktop.screen_capture')).toBe('Take a screen image')
    expect(capabilityLabel('desktop.authorised_file_read')).toBe('Read a file you authorised')
    // A capability this build has no name for is shown as the host named it rather than hidden.
    expect(capabilityLabel('desktop.something_new')).toBe('desktop.something_new')
  })

  it('has a label for every state it can produce', () => {
    for (const state of Object.keys(STATE_LABEL) as DisplayState[]) {
      expect(STATE_LABEL[state]).toBeTruthy()
      expect(stateMeaning(state, 'disclosed_probe')).toBeTruthy()
      expect(stateMeaning(state, 'platform_query')).toBeTruthy()
    }
  })
})

describe('what the progress line counts', () => {
  it('counts an established answer and never an unchecked one', () => {
    const counted = tally(
      [
        record('desktop.application_launch', 'qualified_available'),
        record('desktop.screen_capture', 'permission_required'),
        record('desktop.input_injection', 'not_tested', 'not_probed'),
        record('desktop.display_server', 'qualified_available')
      ],
      NOT_OFFERED
    )
    expect(counted).toEqual({ ready: 2, waiting: 1, unchecked: 1, total: 4 })
    expect(tallyLine(counted)).toBe('2 of 4 established · 1 waiting on you · 1 not checked')
  })

  it('never reports everything done on a machine where nothing was established', () => {
    const counted = tally(
      [
        record('desktop.screen_capture', 'not_tested', 'not_probed'),
        record('desktop.input_injection', 'not_tested', 'not_probed')
      ],
      NOT_OFFERED
    )
    expect(counted.ready).toBe(0)
    expect(tallyLine(counted)).toBe('0 of 2 established · 2 not checked')
  })
})

describe('the macOS permission categories', () => {
  it('keeps the four separate and says Full Disk Access is not a substitute', () => {
    const core = coreCategories().map((category) => category.name)
    expect(core).toEqual([
      'Accessibility',
      'Screen & System Audio Recording',
      'Full Disk Access',
      'Automation'
    ])
    const fullDisk = coreCategories().find((category) => category.pane === 'full_disk_access')
    expect(fullDisk?.caveat).toMatch(/does not stand in for the others/i)
    expect(fullDisk?.caveat).toMatch(/still cannot/i)
  })

  it('keeps the feature categories out of the four', () => {
    const features = featureCategories().map((category) => category.onlyFor)
    expect(features).toEqual(['voice', 'reaching this desktop from elsewhere'])
  })

  it('says a permission cannot be enabled from here and why a check has to perform the operation', () => {
    expect(CEILING).toMatch(/cannot grant/i)
    expect(CEILING).toMatch(/the switch is yours/i)
    expect(CEILING).toMatch(/doing the thing the permission guards/i)
  })

  it('knows which grants stand behind one capability', () => {
    expect(categoriesFor('desktop.screen_capture').map((each) => each.name)).toEqual([
      'Screen & System Audio Recording'
    ])
    expect(categoriesFor('desktop.input_injection').map((each) => each.name)).toEqual([
      'Accessibility',
      'Automation'
    ])
    expect(categoriesFor('desktop.display_server')).toEqual([])
  })
})
