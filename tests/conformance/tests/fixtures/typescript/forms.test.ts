/**
 * KR-REQ-06.01: every test in this file.
 */
import { describe, it } from 'vitest'

// KR-REQ-06.02: a suite, and every test inside it.
describe('the forms', () => {
  // KR-REQ-06.03: a comment directly above a test,
  // over two lines.
  it('is attached', () => {})

  it('has a comment inside', () => {
    // KR-REQ-06.04: inside the body.
  })

  it('KR-REQ-06.05 is named in its title', () => {})

  // KR-REQ-06.06: a comment with a blank line after it keys no test.

  it('is not keyed by the note above', () => {})
})
