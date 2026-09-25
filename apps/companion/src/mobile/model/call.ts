/**
 * Asking the host for something, with one `catch` for every way it can refuse.
 *
 * A command is a promise, and a refusal is its rejection. With arguments that are plain data,
 * neither port throws before it returns one. Every method of the desktop port answers with a call
 * to `invoke` or `listen`, which the shell's API declares `async`, so even a shell that is not
 * there arrives as a rejection; an operation with no agreed shape answers with a promise already
 * rejected. Four of its methods read fields of their arguments before that call
 * (`attachmentUpload`, `voiceStart`, `exportSemanticJson` and `exportAsciicast`), so an argument
 * whose field throws when it is read, such as a getter, throws there first. The scripted host
 * refuses by throwing inside its handlers, and wraps every method so that each throw, one from
 * reading an argument included, becomes the rejection of the promise the method returns, as a
 * refusal from native code does.
 *
 * `ask` stays for what is not one of those ports: a port a test builds, an argument whose reading
 * throws, and whatever else the function it is given does before its call reaches the port. A
 * throw there would walk straight past the `catch` attached to a promise that was never made, and
 * inside a subscription callback become an unhandled error in the page. Here it arrives as a
 * rejection like any other.
 */

/**
 * Calls the host, turning anything thrown before the call returns its promise into a rejection.
 *
 * `async` is what makes it one line: a throw inside an async function is the rejection of the
 * promise it returns, whether it happened before or after the first await.
 */
export async function ask<T>(call: () => Promise<T>): Promise<T> {
  return await call()
}
