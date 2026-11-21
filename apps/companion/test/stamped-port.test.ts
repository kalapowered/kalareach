/**
 * The account's mark and the commands that carry it (KR-REQ-13.12). Native code refuses a command
 * whose mark is not the account signed in, on a host that answers to an organisation, so the page
 * stamps each command that acts for an account with the mark of the last signed-in view, and the next
 * command after a change carries the new mark.
 */

import { describe, expect, it, vi } from 'vitest'

import type { HostPort } from '../src/host/port'
import { AccountMark, stampedPort } from '../src/host/stamped'
import type { AccountView } from '../src/model/account'

const signedIn = (mark: string): AccountView => ({
  state: 'signed_in',
  email: null,
  name: null,
  usage_readable: false,
  generation: 'g',
  mark,
  outcome: null
})

/** A port that keeps the arguments of each call, and the account's listeners. */
function stubPort(first: AccountView | Promise<AccountView>) {
  const listeners: ((view: AccountView) => void)[] = []
  const calls: Record<string, unknown[][]> = {}
  const record = (name: string) =>
    vi.fn((...args: unknown[]) => {
      ;(calls[name] ??= []).push(args)
      return Promise.resolve(undefined)
    })
  const port = {
    accountStatus: () => Promise.resolve(first),
    onAccount: (listener: (view: AccountView) => void) => {
      listeners.push(listener)
      return Promise.resolve(() => undefined)
    },
    draftCreate: record('draftCreate'),
    attachmentUpload: record('attachmentUpload'),
    attachmentUploadBytes: record('attachmentUploadBytes'),
    draftAddAttachment: record('draftAddAttachment'),
    uploadsOpen: record('uploadsOpen'),
    uploadCancel: record('uploadCancel'),
    draftEnd: record('draftEnd'),
    draftSetText: record('draftSetText'),
    composerSubmit: record('composerSubmit'),
    composerQueue: record('composerQueue'),
    composerSteer: record('composerSteer')
  } as unknown as HostPort
  return { port, calls, emit: (view: AccountView) => listeners.forEach((listener) => listener(view)) }
}

describe('the commands that act for an account carry its mark', () => {
  it('stamps each command, last, with the mark of the last signed-in view', async () => {
    const { port, calls, emit } = stubPort(signedIn('aa'))
    const mark = new AccountMark()
    mark.follow(port)
    await vi.waitFor(() => expect(mark.current).toBe('aa'))
    const stamped = stampedPort(port, () => mark.current)

    void stamped.uploadsOpen()
    void stamped.uploadCancel('key')
    void stamped.draftEnd({ sessionId: 's' }, 'session')
    void stamped.draftSetText({ sessionId: 's' }, 'session', 'text')
    void stamped.attachmentUploadBytes({ name: 'a', bytes: new Uint8Array() }, {})
    expect(calls.uploadsOpen[0]).toEqual(['aa'])
    expect(calls.uploadCancel[0]).toEqual(['key', 'aa'])
    expect(calls.draftEnd[0]?.at(-1)).toBe('aa')
    expect(calls.draftSetText[0]?.at(-1)).toBe('aa')
    expect(calls.attachmentUploadBytes[0]).toHaveLength(4)
    expect(calls.attachmentUploadBytes[0]?.at(-1)).toBe('aa')

    // The next command after a change carries the new mark; a sign-out leaves none.
    emit(signedIn('bb'))
    void stamped.uploadsOpen()
    expect(calls.uploadsOpen[1]).toEqual(['bb'])
    emit({ state: 'signed_out', outcome: null })
    void stamped.uploadsOpen()
    expect(calls.uploadsOpen[2]).toEqual([undefined])
  })

  it('leaves the other commands alone', async () => {
    const { port, calls } = stubPort(signedIn('aa'))
    const stamped = stampedPort(port, () => 'aa')
    void stamped.composerSteer({} as never)
    expect(calls.composerSteer[0]).toEqual([{}])
  })

  it('keeps the mark through a status it cannot read, a browser that is open and a renewal', async () => {
    const { port, emit } = stubPort(signedIn('aa'))
    const mark = new AccountMark()
    mark.follow(port)
    await vi.waitFor(() => expect(mark.current).toBe('aa'))
    emit({ state: 'unreadable' })
    emit({ state: 'browser_open' })
    emit({ state: 'finishing' })
    expect(mark.current).toBe('aa')
    emit(signedIn('aa'))
    expect(mark.current).toBe('aa')
  })

  it('takes the newest read of the status and drops an older one that answers after it', async () => {
    let answer: (view: AccountView) => void = () => undefined
    const late = new Promise<AccountView>((resolve) => {
      answer = resolve
    })
    const { port, emit } = stubPort(late)
    // The first read is slow. The event that follows it makes a second read, which says bb.
    const reads: Promise<AccountView>[] = [late, Promise.resolve(signedIn('bb'))]
    ;(port as unknown as { accountStatus: () => Promise<AccountView> }).accountStatus = () => reads.shift() ?? late
    const mark = new AccountMark()
    mark.follow(port)
    await vi.waitFor(() => undefined)
    emit(signedIn('bb'))
    await vi.waitFor(() => expect(mark.current).toBe('bb'))
    answer(signedIn('aa'))
    await late
    await Promise.resolve()
    expect(mark.current).toBe('bb')
  })
})
