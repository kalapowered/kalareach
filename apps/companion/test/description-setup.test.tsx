/**
 * The setup card for session descriptions.
 *
 * It shows what the host offers, with the size before anything is fetched, and asks the host to
 * start or stop the fetch and to change the two settings; it never chooses a model or an address.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import type { HostPort } from '../src/host/port'

function open(port: HostPort, initialPlace: Place): void {
  render(
    <AppProvider port={port} initialPlace={initialPlace}>
      <App />
    </AppProvider>
  )
}

// KR-REQ-22.01: descriptions are offered during setup, with the asset's size, a way to cancel the
// fetch and a way to turn them off, and no hosted account behind any of it.
describe('the setup card for session descriptions', () => {
  async function toHostStep() {
    await screen.findByTestId('setup-identity')
    await userEvent.click(screen.getByTestId('setup-step-host'))
    await screen.findByTestId('setup-panel-host')
  }

  it('shows the size and the sources before anything is fetched, asks for no account, and fetches nothing until asked', async () => {
    const { port, controls } = fakeHost()
    open(port, { view: 'setup' })
    await toHostStep()
    expect((await screen.findByTestId('setup-model-size')).textContent).toBe(
      '1.6 GB to download, from huggingface.co.'
    )
    expect(screen.getByTestId('setup-model')).toHaveTextContent('it needs no account')
    expect(controls.descriptionDownloads).toEqual([])
    expect(controls.descriptionConfigures).toEqual([])
  })

  it('starts the fetch when asked, shows its progress, and cancels it', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port, { view: 'setup' })
    await toHostStep()
    await person.click(await screen.findByTestId('setup-model-download'))
    const progress = await screen.findByTestId('setup-model-progress')
    expect(controls.descriptionDownloads).toEqual([{ action: 'start' }])
    expect(screen.getByTestId('setup-model-status')).toHaveTextContent('Downloading')
    expect(within(progress).getByRole('progressbar', { name: 'Download progress' })).toBeInTheDocument()

    // What the host reports has arrived is what the card shows.
    act(() => {
      controls.changeDescriptionSetup({ fetched_bytes: '780659184' })
    })
    await waitFor(
      () => {
        expect(screen.getByTestId('setup-model-progress')).toHaveTextContent('50%')
      },
      { timeout: 3000 }
    )

    await person.click(screen.getByTestId('setup-model-cancel'))
    await waitFor(() => {
      expect(controls.descriptionDownloads).toEqual([{ action: 'start' }, { action: 'cancel' }])
    })
    await waitFor(() => {
      expect(screen.getByTestId('setup-model-status')).toHaveTextContent('Not downloaded')
    })
    expect(screen.queryByTestId('setup-model-cancel')).toBeNull()
    expect(screen.getByTestId('setup-model')).toHaveTextContent('nothing was kept')
  })

  it('turns descriptions on and off, and on battery, as two settings that leave each other alone', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port, { view: 'setup' })
    await toHostStep()
    const enabled = await screen.findByRole('switch', { name: 'Describe my sessions' })
    const battery = screen.getByRole('switch', { name: 'Keep going on battery power' })
    expect(enabled).toHaveAttribute('aria-checked', 'false')

    await person.click(enabled)
    await waitFor(() => {
      expect(screen.getByRole('switch', { name: 'Describe my sessions' })).toHaveAttribute(
        'aria-checked',
        'true'
      )
    })
    await person.click(battery)
    await waitFor(() => {
      expect(screen.getByRole('switch', { name: 'Keep going on battery power' })).toHaveAttribute(
        'aria-checked',
        'true'
      )
    })
    await person.click(screen.getByRole('switch', { name: 'Describe my sessions' }))
    await waitFor(() => {
      expect(screen.getByRole('switch', { name: 'Describe my sessions' })).toHaveAttribute(
        'aria-checked',
        'false'
      )
    })
    expect(controls.descriptionConfigures).toEqual([
      { enabled: true, on_battery: null },
      { enabled: null, on_battery: true },
      { enabled: false, on_battery: null }
    ])
    // Turning them off left the battery setting as it was.
    expect(screen.getByRole('switch', { name: 'Keep going on battery power' })).toHaveAttribute(
      'aria-checked',
      'true'
    )
  })

  it('says why a host offers nothing, and offers no control for it', async () => {
    const { port, controls } = fakeHost()
    controls.changeDescriptionSetup({
      offered: false,
      profile_id: null,
      asset_bytes: '0',
      sources: [],
      unavailable: 'this processor lacks AVX2, which the description process needs'
    })
    open(port, { view: 'setup' })
    await toHostStep()
    const reason = await screen.findByTestId('setup-model-unavailable')
    expect(reason).toHaveTextContent('This host offers no model.')
    expect(reason).toHaveTextContent('this processor lacks AVX2')
    expect(screen.queryByTestId('setup-model-download')).toBeNull()
    expect(screen.queryByTestId('setup-model-size')).toBeNull()
    expect(screen.queryByRole('switch', { name: 'Describe my sessions' })).toBeNull()
    expect(screen.getByTestId('setup-model-status')).toHaveTextContent('Not offered here')
  })

  it('says a fetch failed and offers it again', async () => {
    const { port, controls } = fakeHost()
    controls.changeDescriptionSetup({ download: 'failed', failure: 'the connection was reset' })
    open(port, { view: 'setup' })
    await toHostStep()
    expect(await screen.findByTestId('setup-model-failure')).toHaveTextContent(
      'The download failed. the connection was reset'
    )
    expect(screen.getByTestId('setup-model-download')).toHaveTextContent('Try the download again')
  })

  it('shows a refused write in the host’s words and keeps what the host offers on the card', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    const refusing: HostPort = {
      ...port,
      descriptionDownload: () =>
        Promise.reject(
          Object.assign(new Error('this host has no model to fetch'), {
            code: 'RESOURCE_UNAVAILABLE'
          })
        )
    }
    open(refusing, { view: 'setup' })
    await toHostStep()
    await person.click(await screen.findByTestId('setup-model-download'))
    await waitFor(() => {
      expect(screen.getByTestId('setup-model-refused')).toHaveTextContent(
        'this host has no model to fetch'
      )
    })
    expect(screen.getByTestId('setup-model-size')).toBeInTheDocument()
  })

  it('shows a host that refuses a device its setup in the host’s words', async () => {
    const { port, controls } = fakeHost()
    controls.setRights(['session.create'])
    open(port, { view: 'setup' })
    await toHostStep()
    expect(await screen.findByTestId('setup-model-unread')).toHaveTextContent(
      'This device may not manage this host.'
    )
  })

  it('says the offer could not be read when the host cannot be reached, and asks again on request', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.setConnected(false)
    open(port, { view: 'setup' })
    await toHostStep()
    expect(await screen.findByTestId('setup-model-unread')).toHaveTextContent(
      'What this host offers could not be read.'
    )
    expect(screen.queryByTestId('setup-model-size')).toBeNull()
    act(() => {
      controls.setConnected(true)
    })
    await person.click(screen.getByTestId('setup-model-retry'))
    expect(await screen.findByTestId('setup-model-size')).toBeInTheDocument()
  })
})
