/**
 * The companion's third-party notice: the file the desktop installers carry and the text the interface
 * opens in the account panel.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { Notices } from '../src/components/Notices'
import {
  NOTICES_FAILED,
  NOTICES_HIDE,
  NOTICES_READING,
  NOTICES_SHOW,
  NOTICES_TITLE
} from '../src/model/notices'
import committed from '../../../docs/releases/companion-third-party-notices.txt?raw'
import linux from '../src-tauri/tauri.linux.conf.json'
import macos from '../src-tauri/tauri.macos.conf.json'
import shared from '../src-tauri/tauri.conf.json'
import windows from '../src-tauri/tauri.windows.conf.json'

// Where the desktop configurations point, from the folder of the Tauri project.
const NOTICE_SOURCE = '../../../docs/releases/companion-third-party-notices.txt'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('the notice the desktop installers carry', () => {
  it('maps the committed text as THIRD-PARTY-NOTICES.txt in each desktop bundle', () => {
    const configurations = { macos, linux, windows }
    for (const [platform, configuration] of Object.entries(configurations)) {
      expect(configuration.bundle.resources, platform).toEqual({
        [NOTICE_SOURCE]: 'THIRD-PARTY-NOTICES.txt'
      })
    }
    expect(committed).toContain('THIRD-PARTY NOTICES')
  })

  it('leaves the configuration the mobile builds read without resources', () => {
    expect('resources' in shared.bundle).toBe(false)
  })
})

describe('the third-party notices row', () => {
  function answer(text: string, ok = true) {
    return vi.fn(() => Promise.resolve({ ok, status: ok ? 200 : 500, text: () => Promise.resolve(text) }))
  }

  it('opens the text in a region that the keyboard reaches, and hides it again', async () => {
    const person = userEvent.setup()
    const fetched = answer('Licence: MIT\n')
    vi.stubGlobal('fetch', fetched)
    render(<Notices target={44} />)
    expect(screen.getByText(NOTICES_TITLE)).toBeInTheDocument()
    const button = screen.getByRole('button', { name: NOTICES_SHOW })
    expect(button).toHaveAttribute('aria-expanded', 'false')
    expect(fetched).not.toHaveBeenCalled()

    await person.click(button)
    const region = await screen.findByRole('region', { name: NOTICES_TITLE })
    expect(region).toHaveTextContent('Licence: MIT')
    expect(region).toHaveAttribute('tabindex', '0')
    expect(String((fetched.mock.calls as unknown[][])[0]?.[0])).toContain('companion-third-party-notices')
    expect(screen.getByRole('button', { name: NOTICES_HIDE })).toHaveAttribute('aria-expanded', 'true')

    await person.click(screen.getByRole('button', { name: NOTICES_HIDE }))
    expect(screen.getByRole('button', { name: NOTICES_SHOW })).toHaveAttribute('aria-expanded', 'false')
    await person.click(screen.getByRole('button', { name: NOTICES_SHOW }))
    expect(await screen.findByRole('region', { name: NOTICES_TITLE })).toBeInTheDocument()
    expect(fetched).toHaveBeenCalledTimes(1)
  })

  it('says that the text cannot be read, and asks again the next time it is opened', async () => {
    const person = userEvent.setup()
    const broken = answer('', false)
    vi.stubGlobal('fetch', broken)
    render(<Notices target={44} />)
    await person.click(screen.getByRole('button', { name: NOTICES_SHOW }))
    expect(await screen.findByText(NOTICES_FAILED)).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: NOTICES_TITLE })).toBeNull()

    vi.stubGlobal('fetch', answer('Licence: ISC\n'))
    await person.click(screen.getByRole('button', { name: NOTICES_HIDE }))
    await person.click(screen.getByRole('button', { name: NOTICES_SHOW }))
    expect(await screen.findByRole('region', { name: NOTICES_TITLE })).toHaveTextContent('Licence: ISC')
    await waitFor(() => expect(screen.queryByText(NOTICES_FAILED)).toBeNull())
  })

  it('says that it is reading while the text is on its way', async () => {
    const person = userEvent.setup()
    let finish: (value: unknown) => void = () => undefined
    vi.stubGlobal('fetch', vi.fn(() => new Promise((done) => { finish = done })))
    render(<Notices target={44} />)
    await person.click(screen.getByRole('button', { name: NOTICES_SHOW }))
    expect(screen.getByText(NOTICES_READING)).toBeInTheDocument()
    finish({ ok: true, status: 200, text: () => Promise.resolve('Licence: Zlib\n') })
    expect(await screen.findByRole('region', { name: NOTICES_TITLE })).toHaveTextContent('Zlib')
    expect(screen.queryByText(NOTICES_READING)).toBeNull()
  })
})
