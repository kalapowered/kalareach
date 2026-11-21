/**
 * A control that commits on its second press (KR-REQ-12.26): the first press arms it and commits
 * nothing, the second commits, and a press that is left alone disarms.
 */

import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ARMED_FOR_MS, TwoPressButton } from '../src/components/ui'

afterEach(() => {
  cleanup()
  vi.useRealTimers()
})

function shown(onCommit: () => void) {
  return render(
    <div>
      <TwoPressButton data-testid="control" armedLabel="Press again to remove" onCommit={onCommit}>
        Remove
      </TwoPressButton>
      <button type="button" data-testid="elsewhere">
        elsewhere
      </button>
    </div>
  )
}

describe('a control that commits on its second press', () => {
  it('commits nothing at the first press and once at the second, by pointer', async () => {
    const commits = vi.fn()
    shown(commits)
    const person = userEvent.setup()
    await person.click(screen.getByTestId('control'))
    expect(commits).not.toHaveBeenCalled()
    expect(screen.getByTestId('control')).toHaveTextContent('Press again to remove')
    expect(screen.getByTestId('control')).toHaveAttribute('data-armed', 'true')
    await person.click(screen.getByTestId('control'))
    expect(commits).toHaveBeenCalledTimes(1)
    expect(screen.getByTestId('control')).toHaveTextContent('Remove')
    expect(screen.getByTestId('control')).not.toHaveAttribute('data-armed')
  })

  it('commits nothing at the first key and once at the second, and says the armed label to a screen reader', async () => {
    const commits = vi.fn()
    shown(commits)
    const person = userEvent.setup()
    screen.getByTestId('control').focus()
    await person.keyboard('{Enter}')
    expect(commits).not.toHaveBeenCalled()
    expect(screen.getByRole('status')).toHaveTextContent('Press again to remove')
    await person.keyboard('{Enter}')
    expect(commits).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('status')).toHaveTextContent('')
  })

  it('disarms when Escape is pressed, when focus leaves it, and after a while, and commits nothing', async () => {
    const commits = vi.fn()
    shown(commits)
    const person = userEvent.setup()
    await person.click(screen.getByTestId('control'))
    await person.keyboard('{Escape}')
    expect(screen.getByTestId('control')).not.toHaveAttribute('data-armed')
    await person.click(screen.getByTestId('control'))
    expect(screen.getByTestId('control')).toHaveAttribute('data-armed', 'true')
    await person.click(screen.getByTestId('elsewhere'))
    expect(screen.getByTestId('control')).not.toHaveAttribute('data-armed')
    expect(commits).not.toHaveBeenCalled()
    cleanup()

    vi.useFakeTimers()
    shown(commits)
    const control = screen.getByTestId('control')
    fireEvent.keyDown(control, { key: 'Enter' })
    fireEvent.keyUp(control, { key: 'Enter' })
    expect(screen.getByTestId('control')).toHaveAttribute('data-armed', 'true')
    act(() => {
      vi.advanceTimersByTime(ARMED_FOR_MS - 1)
    })
    expect(screen.getByTestId('control')).toHaveAttribute('data-armed', 'true')
    act(() => {
      vi.advanceTimersByTime(2)
    })
    expect(screen.getByTestId('control')).not.toHaveAttribute('data-armed')
    expect(commits).not.toHaveBeenCalled()
  })

  it('disarms at a press elsewhere and at Escape though the control never took focus, as in Safari, and not at a press on itself', () => {
    const commits = vi.fn()
    shown(commits)
    const control = screen.getByTestId('control')
    const arm = () => {
      fireEvent.keyDown(control, { key: 'Enter' })
      fireEvent.keyUp(control, { key: 'Enter' })
      expect(control).toHaveAttribute('data-armed', 'true')
    }
    arm()
    expect(document.activeElement).not.toBe(control)
    fireEvent.pointerDown(control)
    expect(control).toHaveAttribute('data-armed', 'true')
    fireEvent.pointerDown(screen.getByTestId('elsewhere'))
    expect(control).not.toHaveAttribute('data-armed')
    arm()
    fireEvent.keyDown(document.body, { key: 'Escape' })
    expect(control).not.toHaveAttribute('data-armed')
    expect(commits).not.toHaveBeenCalled()
  })
})
