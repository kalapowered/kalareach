/**
 * The one way the browser tests make the bytes of a file to hand to a file chooser.
 *
 * Declared for the test that imports it and no other file: the browser tests are type-checked with
 * the interface's own settings, which carry no Node types, and a global `Buffer` would make the
 * interface's own source accept a name its web view does not have.
 */
declare module 'node:buffer' {
  export class Buffer extends Uint8Array {
    static from(text: string): Buffer
  }
}
