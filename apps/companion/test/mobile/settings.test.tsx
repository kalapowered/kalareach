/**
 * The phone's settings, opened over a live session (KR-REQ-13.09).
 *
 * Settings are not a destination: a person changing how the application looks has not left what
 * they were doing. They open over the session as a sheet, the session stays behind them with its
 * draft, and closing them, by any route, is back in the session and nowhere else.
 */

import { describe, expect, it } from 'vitest'
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AppProvider } from '../../src/app/state'
import { fakeHost } from '../../src/host/fake'
import { MobileApp } from '../../src/mobile/MobileApp'
import type { MobilePlatform } from '../../src/mobile/platform'

const SURFACES: readonly MobilePlatform[] = ['ios', 'android']

/** The shell on `surface`, with a person ready to drive it. */
function start(surface: MobilePlatform) {
  const { port, controls } = fakeHost()
  const person = userEvent.setup()
  render(
    <AppProvider port={port}>
      <MobileApp surface={surface} storage={null} />
    </AppProvider>
  )
  return { person, controls }
}

/** Opens the first session, as a person does from the list. */
async function inSession(person: ReturnType<typeof userEvent.setup>): Promise<void> {
  await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
  await person.click(await screen.findByRole('button', { name: /Session 1/ }))
  await screen.findByLabelText('Message this session')
}

describe('settings without leaving a live session', () => {
  it('opens settings from inside a session, and the session stays open behind them', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await screen.findByLabelText('Message this session')
    await person.click(await screen.findByRole('button', { name: /Settings/ }, { timeout: 2000 }))
    expect(screen.getByLabelText('Message this session')).toBeInTheDocument()
  })

  for (const surface of SURFACES) {
    it(`says what it is and offers the appearance, over the session, on ${surface}`, async () => {
      const { person } = start(surface)
      await inSession(person)
      const field = screen.getByLabelText<HTMLTextAreaElement>('Message this session')
      await person.type(field, 'a draft the sheet must not take')
      await person.click(screen.getByRole('button', { name: 'Settings' }))
      const sheet = await screen.findByRole('dialog', { name: 'Settings' })
      expect(sheet).toHaveTextContent('The session behind this keeps running.')
      const chooser = within(sheet).getByRole('group', { name: 'Appearance' })
      expect(within(chooser).getAllByRole('radio').map((radio) => radio.parentElement?.textContent)).toEqual([
        'Light',
        'Dark',
        'System'
      ])
      // Behind the sheet the session is as it was, with what was typed.
      expect(field).toBeInTheDocument()
      expect(field.value).toBe('a draft the sheet must not take')
      expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Session')
    })
  }

  it('applies the appearance a person chooses, and keeps the session', async () => {
    const { person } = start('android')
    await inSession(person)
    await person.click(screen.getByRole('button', { name: 'Settings' }))
    const sheet = await screen.findByRole('dialog', { name: 'Settings' })
    await person.click(within(sheet).getByRole('radio', { name: 'Dark' }))
    expect(document.documentElement.dataset.preference).toBe('dark')
    expect(screen.getByLabelText('Message this session')).toBeInTheDocument()
    await person.click(within(sheet).getByRole('radio', { name: 'System' }))
  })

  it('closes with its own button, Escape or the scrim, each back in the same session', async () => {
    for (const route of ['button', 'escape', 'scrim'] as const) {
      const { person } = start('ios')
      await inSession(person)
      await person.click(screen.getByRole('button', { name: 'Settings' }))
      const sheet = await screen.findByRole('dialog', { name: 'Settings' })
      await waitFor(() => {
        expect(sheet).toHaveAttribute('data-presentation', 'here')
      })
      if (route === 'button') await person.click(within(sheet).getByRole('button', { name: 'Close settings' }))
      else if (route === 'escape') await person.keyboard('{Escape}')
      else await person.click(screen.getByTestId('sheet-scrim'))
      await waitFor(() => {
        expect(screen.queryByRole('dialog', { name: 'Settings' })).toBeNull()
      })
      expect(screen.getByLabelText('Message this session'), route).toBeInTheDocument()
      expect(screen.getByRole('heading', { level: 1 }), route).toHaveTextContent('Session')
      // The next press of the system's back leaves the session, as it always did.
      act(() => {
        window.history.back()
      })
      await waitFor(() => {
        expect(screen.queryByLabelText('Message this session'), route).toBeNull()
      })
      cleanup()
    }
  })

  it('takes the system back to close the settings first, and leaves the session only on the next', async () => {
    const { person } = start('android')
    await inSession(person)
    await person.click(screen.getByRole('button', { name: 'Settings' }))
    await screen.findByRole('dialog', { name: 'Settings' })
    act(() => {
      window.history.back()
    })
    await waitFor(() => {
      expect(screen.queryByRole('dialog', { name: 'Settings' })).toBeNull()
    })
    expect(screen.getByLabelText('Message this session')).toBeInTheDocument()
    act(() => {
      window.history.back()
    })
    await waitFor(() => {
      expect(screen.queryByLabelText('Message this session')).toBeNull()
    })
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Sessions')
  })

  it('leaves every other destination as it was: no settings on the lists, the inbox, the hosts or the account', async () => {
    for (const surface of SURFACES) {
      const { person } = start(surface)
      for (const destination of [/^Attention/, /^Sessions/, /^Hosts/, /^Account/]) {
        await person.click(await screen.findByRole('button', { name: destination }))
        expect(screen.queryByRole('button', { name: 'Settings' }), `${surface} ${String(destination)}`).toBeNull()
      }
      expect(
        Array.from(screen.getByRole('navigation', { name: 'Sections' }).querySelectorAll('.m-tab-label')).map(
          (label) => label.textContent
        )
      ).toEqual(['Attention', 'Sessions', 'Hosts', 'Account'])
      cleanup()
    }
  })
})
