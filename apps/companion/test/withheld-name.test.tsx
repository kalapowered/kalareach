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

describe('the words for an account name', () => {
  it('replace the whole record of a withheld name, whatever its length', () => {
    expect(accountName('[name withheld, 0 bytes]')).toBe('account name withheld')
    expect(accountName('[name withheld, 26 bytes]')).toBe('account name withheld')
  })

  it('leave a name alone, even one that quotes the record', () => {
    expect(accountName('rs')).toBe('rs')
    expect(accountName('rs [name withheld, 2 bytes]')).toBe('rs [name withheld, 2 bytes]')
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
})
