/**
 * What the page says of a launch the session refused (KR-REQ-13.11): the words are decided by the
 * refusal's code and by the shell the surface names, never by guessing at why.
 */

import { describe, expect, it } from 'vitest'

import { pressRefusal } from '../src/model/launch'

describe('what a refused press says', () => {
  it('a_refused_press_on_a_powershell_surface_says_the_powershell_words', () => {
    expect(pressRefusal('DRAFT_CONFLICT', 'ignored', false, 'powershell')).toBe(
      'The launch was not installed, and nothing was typed. The prompt may have changed, or PowerShell cannot run this command.'
    )
  })

  it('a_refused_press_on_another_shell_keeps_the_prompt_changed_words', () => {
    for (const shell of ['bash', 'zsh', 'fish', 'sh', null] as const) {
      expect(pressRefusal('DRAFT_CONFLICT', 'ignored', false, shell)).toBe(
        'The prompt changed before the launch was installed. Nothing was typed.'
      )
    }
  })

  it('says the PowerShell words only for the refusal that a missing line shares with a moved prompt', () => {
    expect(pressRefusal('EDITOR_BUSY', 'ignored', false, 'powershell')).toBe(
      'The terminal was busy, so the launch was not installed. Nothing was typed.'
    )
    expect(pressRefusal('DRAFT_CONFLICT', 'ignored', true, 'powershell')).toContain(
      'could not confirm whether the launch was installed'
    )
  })
})
