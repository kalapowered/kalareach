/**
 * Asking the host for something, with one `catch` for every way it can refuse.
 *
 * A command is a promise, and a refusal is its rejection. Given the parameters its interface
 * declares, neither port throws before it returns one. Every method of the desktop port answers
 * with a call to `invoke` or `listen`, which the shell's API declares `async`, so even a shell that
 * is not there arrives as a rejection; an operation with no agreed shape answers with a promise
 * already rejected. The scripted host refuses by throwing inside its handlers, and wraps every
 * method so that each throw becomes the rejection of the promise the method returns, as a refusal
 * from native code does.
 *
 * `ask` stays for the code around a port call, which is not a port: a port a test builds, and
 * whatever a caller does before its call reaches the port. A throw there would walk straight past
 * the `catch` attached to a promise that was never made, and inside a subscription callback become
 * an unhandled error in the page. Here it arrives as a rejection like any other.
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
