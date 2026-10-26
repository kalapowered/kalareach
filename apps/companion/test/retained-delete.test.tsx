/**
 * Deleting a copy that left the host, from the page that lists it (KR-REQ-24.29).
 *
 * The page names a copy and asks for the dialog; the dialog is native code's, and the person is the
 * only one who answers it. These render the real application against the scripted host, where the
 * test is the person and the service: it answers the dialog, makes the service confirm or not, and
 * reads what native code was asked. What the backend does with a request is checked against a real
 * daemon in the backend's own tests; this file is about what the page offers, what it shows while
 * it waits, and that it sends nothing the person did not confirm.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost } from '../src/host/fake'

const ARCHIVE = 'archive 4c1f0b5e generation 12'
const SYNC_COPY = 'drafts, which the service holds as copy 2f6d0c1e-8a3b-4c57-9d10-6b1e5a7c9f42'

/** Opens the screen that lists what has left the host, over a scripted host. */
async function open(host = fakeHost(), rows = 4) {
  const { port, controls } = host
  const view = render(
    <AppProvider port={port} initialPlace={{ view: 'changesets' }}>
      <App />
    </AppProvider>
  )
  const retained = await screen.findByTestId('retained-artefacts')
  await waitFor(() => {
    expect(within(retained).getAllByTestId('left-copy')).toHaveLength(rows)
  })
  return { controls, retained, person: userEvent.setup(), unmount: view.unmount }
}

/** The row that lists the copy named `reference`. */
function rowOf(retained: HTMLElement, reference: string): HTMLElement {
  const row = within(retained)
    .getAllByTestId('left-copy')
    .find((each) => each.textContent.includes(reference))
  if (row === undefined) throw new Error(`no row lists ${reference}`)
  return row
}

/** Answers the dialog as the person does, and lets what that sets off run. */
async function answerDialog(controls: Awaited<ReturnType<typeof open>>['controls'], yes: boolean) {
  await waitFor(() => {
    expect(controls.retained.dialogsWaiting).toBe(1)
  })
  await act(async () => {
    controls.retained.answerDialog(yes)
    await Promise.resolve()
  })
}

describe('a copy the host can ask the removal of', () => {
  it('is deleted by the person answering a dialog, and not by the page', async () => {
    const { controls, retained, person } = await open()
    const row = rowOf(retained, ARCHIVE)
    await person.click(within(row).getByRole('button', { name: /Delete backup archive/ }))

    // While the dialog is up the page can only wait: the note beside the button says so, the button
    // cannot be pressed again, and nothing was sent.
    const waiting = within(rowOf(retained, ARCHIVE)).getByRole('button')
    expect(within(rowOf(retained, ARCHIVE)).getByTestId('removal')).toHaveTextContent(
      'Waiting for your answer in the dialog.'
    )
    expect(waiting).toBeDisabled()
    expect(controls.retained.asked).toEqual([ARCHIVE])
    expect(controls.retained.finished).toEqual([])

    await answerDialog(controls, true)
    expect(await screen.findByText('Deleted. The service confirmed it.')).toBeInTheDocument()
    expect(controls.retained.finished).toEqual([ARCHIVE])
    await waitFor(() => {
      expect(within(retained).queryByText(ARCHIVE, { exact: false })).toBeNull()
    })
  })

  it('is left alone when the person says no', async () => {
    const { controls, retained, person } = await open()
    await person.click(
      within(rowOf(retained, ARCHIVE)).getByRole('button', { name: /Delete backup archive/ })
    )
    await answerDialog(controls, false)

    await waitFor(() => {
      expect(within(rowOf(retained, ARCHIVE)).getByRole('button')).toHaveTextContent('Delete…')
    })
    expect(controls.retained.finished).toEqual([])
    expect(within(rowOf(retained, ARCHIVE)).queryByRole('alert')).toBeNull()
  })

  it('stays listed, and can be asked again, when the service has not confirmed the deletion', async () => {
    const { controls, retained, person } = await open()
    controls.retained.serviceDoesNotConfirm(true)
    await person.click(
      within(rowOf(retained, ARCHIVE)).getByRole('button', { name: /Delete backup archive/ })
    )
    await answerDialog(controls, true)

    const row = await waitFor(() => {
      const found = rowOf(retained, ARCHIVE)
      expect(within(found).getByTestId('removal')).toHaveTextContent(
        'the service has not confirmed it'
      )
      return found
    })
    expect(within(row).getByRole('button')).toHaveTextContent('Ask again…')
    expect(controls.retained.finished).toEqual([ARCHIVE])

    // The service is back: asking again confirms, and the copy is gone.
    controls.retained.serviceDoesNotConfirm(false)
    await person.click(within(row).getByRole('button'))
    await answerDialog(controls, true)
    await waitFor(() => {
      expect(within(retained).queryByText(ARCHIVE, { exact: false })).toBeNull()
    })
    expect(controls.retained.finished).toEqual([ARCHIVE, ARCHIVE])
  })

  it('says why when native code refuses, and sends nothing', async () => {
    const { controls, retained, person } = await open()
    controls.retained.refuseNextAsk('the host lists no copy under that reference')
    await person.click(
      within(rowOf(retained, ARCHIVE)).getByRole('button', { name: /Delete backup archive/ })
    )

    const refusal = await within(rowOf(retained, ARCHIVE)).findByRole('alert')
    expect(refusal).toHaveTextContent('the host lists no copy under that reference')
    expect(controls.retained.dialogsWaiting).toBe(0)
    expect(controls.retained.finished).toEqual([])
    expect(within(rowOf(retained, ARCHIVE)).getByRole('button')).toHaveTextContent('Delete…')
  })

  it('is offered no deletion once the screen has gone: a token the dialog minted late is dropped', async () => {
    const { controls, retained, person, unmount } = await open()
    await person.click(
      within(rowOf(retained, ARCHIVE)).getByRole('button', { name: /Delete backup archive/ })
    )
    await waitFor(() => {
      expect(controls.retained.dialogsWaiting).toBe(1)
    })
    unmount()
    await act(async () => {
      controls.retained.answerDialog(true)
      await Promise.resolve()
    })
    await waitFor(() => {
      expect(controls.retained.cancelled).toBe(1)
    })
    expect(controls.retained.finished).toEqual([])
  })
})

describe('a copy the host cannot ask the removal of', () => {
  it('has no button, and says nobody here can remove it', async () => {
    const { retained } = await open()
    for (const reference of [
      'a turn summary, delivered through the push service',
      'device 0d5e1a7c-31aa-4f09-9c47-5f7a7d3f6a10'
    ]) {
      const row = rowOf(retained, reference)
      expect(within(row).queryByRole('button')).toBeNull()
      expect(within(row).getByTestId('removal')).toHaveTextContent(
        'This host cannot ask for its removal.'
      )
    }
  })
})

describe('a host this device is paired with', () => {
  it('lists its copies and offers their deletion nowhere, and still drops this computer’s own', async () => {
    const { controls, retained, person } = await open()
    act(() => {
      controls.reachAsPairedDevice()
    })

    await waitFor(() => {
      expect(within(rowOf(retained, ARCHIVE)).queryByRole('button')).toBeNull()
    })
    expect(within(rowOf(retained, ARCHIVE)).getByTestId('removal')).toHaveTextContent(
      'at the computer it runs on'
    )
    // The copy this computer's own sync kept is dropped from here whichever host is connected.
    expect(
      within(rowOf(retained, SYNC_COPY)).getByRole('button', { name: /Delete synchronised/ })
    ).toBeEnabled()
    await person.click(within(rowOf(retained, SYNC_COPY)).getByRole('button'))
    await answerDialog(controls, true)
    await waitFor(() => {
      expect(within(retained).queryByText(SYNC_COPY, { exact: false })).toBeNull()
    })
    expect(controls.retained.finished).toEqual([SYNC_COPY])
  })
})

describe('the copies this computer’s own sync kept', () => {
  it('are not shown as an empty list when its records cannot be read', async () => {
    const host = fakeHost()
    host.controls.retained.syncListFails('a record of the sync could not be read')
    const { controls, retained, person } = await open(host, 3)

    const unread = within(retained).getByTestId('sync-copies-unread')
    expect(within(unread).getByRole('alert')).toHaveTextContent(
      'could not be read, so this list may be missing some: a record of the sync could not be read'
    )
    expect(within(retained).queryByText(SYNC_COPY, { exact: false })).toBeNull()

    // The records are readable again: asking again lists the copy and the warning goes.
    controls.retained.syncListFails(null)
    await person.click(within(unread).getByRole('button', { name: 'Try again' }))
    await waitFor(() => {
      expect(within(retained).getAllByTestId('left-copy')).toHaveLength(4)
    })
    expect(within(retained).queryByTestId('sync-copies-unread')).toBeNull()
    // The button that was pressed is gone, and the focus goes to the section's heading.
    expect(
      within(retained).getByRole('heading', { name: 'What has left this host' })
    ).toHaveFocus()
  })

  it('says so again when reading them again fails again', async () => {
    const host = fakeHost()
    host.controls.retained.syncListFails('a record of the sync could not be read')
    const { retained, person } = await open(host, 3)

    const unread = within(retained).getByTestId('sync-copies-unread')
    await person.click(within(unread).getByRole('button', { name: 'Try again' }))
    // The warning has the same words as before, so the failure is also said where a screen reader
    // is told of what happened.
    expect(await screen.findByText('a record of the sync could not be read')).toBeInTheDocument()
    expect(within(retained).getByTestId('sync-copies-unread')).toBeInTheDocument()
  })

  it('lists a record that cannot be read as a copy nothing can be asked of, at no known time', async () => {
    const host = fakeHost()
    host.controls.retained.keepSyncCopy({
      kind: 'work sent without an answer, which this device cannot describe',
      reference: 'a record this build cannot read, kept at /sync/record',
      left_at_ms: '0',
      deletable: false
    })
    const { retained } = await open(host, 5)

    const row = rowOf(retained, 'a record this build cannot read')
    expect(within(row).queryByRole('button')).toBeNull()
    expect(within(row).getByTestId('removal')).toHaveTextContent(
      'This computer cannot ask the sync service to drop it now: its sync is off, or the record of it cannot be read.'
    )
    expect(row).toHaveTextContent('left at a time not known')
  })
})

describe('a deletion the service did not confirm', () => {
  it('says nothing more once the list shows the service has deleted the copy', async () => {
    const { controls, retained, person } = await open()
    controls.retained.serviceDoesNotConfirm(true)
    await person.click(
      within(rowOf(retained, ARCHIVE)).getByRole('button', { name: /Delete backup archive/ })
    )
    await answerDialog(controls, true)
    await waitFor(() => {
      expect(within(rowOf(retained, ARCHIVE)).getByRole('button')).toHaveTextContent('Ask again…')
    })
    // The button's name begins with what it shows.
    expect(
      within(rowOf(retained, ARCHIVE)).getByRole('button', { name: /^Ask again to delete/ })
    ).toBeInTheDocument()

    // The service deletes it, and the list is read again when the person deletes another copy.
    controls.retained.serviceHasDeleted(ARCHIVE)
    await person.click(within(rowOf(retained, SYNC_COPY)).getByRole('button'))
    await answerDialog(controls, true)

    await waitFor(() => {
      expect(within(rowOf(retained, ARCHIVE)).getByTestId('removal')).toHaveTextContent(
        'This host cannot ask for its removal.'
      )
    })
    expect(within(rowOf(retained, ARCHIVE)).queryByRole('button')).toBeNull()
  })
})
