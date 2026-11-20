import { describe, it, test } from 'vitest'

const named = 'a title held in a constant'
const mobile = true

describe('every form of a call', () => {
  it('a string title', () => {})
  it(`a template title`, () => {})
  it(`${named} and more`, () => {})
  it(named, () => {})
  test.skip(mobile, 'a condition named by an identifier')
  test.skip(process.platform === 'win32', 'a condition that compares')
  test.step('a step inside a test', async () => {})
  test.use({ locale: 'en' })
  test.extend({})
  test.beforeAll(async () => {})
  test.beforeEach(async () => {})
  test.afterAll(async () => {})
  test.afterEach(async () => {})
  test.beforeAll('a hook before all', async () => {})
  test.beforeEach('a hook before each', async () => {})
  test.afterAll('a hook after all', async () => {})
  test.afterEach('a hook after each', async () => {})
})
