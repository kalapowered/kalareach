/**
 * The one way the browser tests make the bytes of a file to hand to a file chooser.
 *
 * Declared here for the same reason as the declarations beside it: the browser tests are
 * type-checked with the interface's own settings, which carry no Node types.
 */
declare class Buffer extends Uint8Array {
  static from(text: string): Buffer
}
