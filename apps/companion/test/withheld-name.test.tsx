/**
 * An environment's account name, as the companion prints it (KR-REQ-23.25).
 *
 * A host answers its owner, at their own machine, with the account each environment runs as. It
 * answers every other reader, a paired device included, with the export form of the same answer,
 * where the name is only its class and its length: `[name withheld, 2 bytes]`. That text is the
 * host's record that it kept the name back. It is not a name, so neither view prints it as one.
 */

import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import type { EnvironmentListResult } from '@kalareach/protocol'

import { AppProvider } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { MobileHosts } from '../src/mobile/views/Places'
import { accountName } from '../src/views/account-name'
import { Hosts } from '../src/views/Sessions'

/** How long a value is, as the host counts it: the bytes of its UTF-8 encoding. */
function bytes(value: string): number {
  return new TextEncoder().encode(value).length
}

/** An environment list in the form a host sends a paired device. */
function exported(list: EnvironmentListResult): EnvironmentListResult {
  return {
    environments: list.environments.map((environment) => ({
      ...environment,
      os_user: `[name withheld, ${bytes(environment.os_user)} bytes]`,
      runtime_directory: `[path withheld, ${bytes(environment.runtime_directory)} bytes]`,
      state_directory: `[path withheld, ${bytes(environment.state_directory)} bytes]`
    }))
  }
}

/** The scripted host, read the way a paired device reads a host. */
function asPairedDevice(): HostPort {
  const { port } = fakeHost()
  return {
    ...port,
    environmentList: () => port.environmentList().then(exported)
  }
}

/** The scripted host, read the way its owner reads it at their own machine. */
function asOwner(): HostPort {
  return fakeHost().port
}

/** The scripted host, read by its owner, with an account whose login calls it `name`. */
function asOwnerNamed(name: string): HostPort {
  const { port } = fakeHost()
  return {
    ...port,
    environmentList: () =>
      port.environmentList().then((list) => ({
        environments: list.environments.map((each) => ({ ...each, os_user: name }))
      }))
  }
}

/** The line that says what an environment runs on and as whom. */
async function environmentLine(): Promise<string> {
  const line = await screen.findByText(/^macos · aarch64 · /)
  return line.textContent ?? ''
}

describe('an account name the host withholds (KR-REQ-23.25)', () => {
  it('is said to be withheld on the desktop, and the host record is not shown', async () => {
    render(
      <AppProvider port={asPairedDevice()}>
        <Hosts />
      </AppProvider>
    )
    const line = await environmentLine()
    expect(line).toBe('macos · aarch64 · account name withheld')
    expect(line).not.toContain('bytes')
  })

  it('is said to be withheld on a phone, and the host record is not shown', async () => {
    render(
      <AppProvider port={asPairedDevice()}>
        <MobileHosts surface="ios" />
      </AppProvider>
    )
    const line = await environmentLine()
    expect(line).toBe('macos · aarch64 · account name withheld')
    expect(line).not.toContain('bytes')
  })
})

/** One environment with the given account name and directories, and nothing else of note. */
function environment(
  osUser: string,
  runtime = '/Users/rs/Library/Application Support/KalaReach/run',
  state = '/Users/rs/Library/Application Support/KalaReach/state'
): EnvironmentListResult['environments'][number] {
  return {
    arch: 'aarch64',
    environment_id: '3f1a2c40-11aa-4b2c-9d3e-000000000001',
    label: 'studio · macOS',
    live_sessions: '3',
    os: 'macos',
    os_user: osUser,
    runtime_directory: runtime,
    state_directory: state
  }
}

describe('the words for an account name', () => {
  const withheldRuntime = '[path withheld, 51 bytes]'
  const withheldState = '[path withheld, 53 bytes]'

  it('replace the record of a withheld name in an exported environment, whatever its length', () => {
    for (const record of ['[name withheld, 0 bytes]', '[name withheld, 26 bytes]']) {
      expect(accountName(environment(record, withheldRuntime, withheldState))).toBe(
        'account name withheld'
      )
    }
  })

  it("leave an owner's account alone, even one called by the record's text", () => {
    expect(accountName(environment('rs'))).toBe('rs')
    expect(accountName(environment('[name withheld, 2 bytes]'))).toBe('[name withheld, 2 bytes]')
  })

  it('leave a name alone that only quotes the record', () => {
    expect(accountName(environment('rs [name withheld, 2 bytes]', withheldRuntime, withheldState))).toBe(
      'rs [name withheld, 2 bytes]'
    )
  })
})

describe("the owner's own reading (KR-REQ-23.25)", () => {
  it('shows the account name in full on the desktop', async () => {
    render(
      <AppProvider port={asOwner()}>
        <Hosts />
      </AppProvider>
    )
    expect(await environmentLine()).toBe('macos · aarch64 · rs')
  })

  it('shows the account name in full on a phone', async () => {
    render(
      <AppProvider port={asOwner()}>
        <MobileHosts surface="android" />
      </AppProvider>
    )
    expect(await environmentLine()).toBe('macos · aarch64 · rs')
  })

  it("shows an owner's account as it came, even one called by the record's text", async () => {
    render(
      <AppProvider port={asOwnerNamed('[name withheld, 2 bytes]')}>
        <Hosts />
      </AppProvider>
    )
    expect(await environmentLine()).toBe('macos · aarch64 · [name withheld, 2 bytes]')
  })
})
