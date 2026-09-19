/**
 * Asking the host for something, without a throw escaping the caller.
 *
 * A command is a promise, and a caller handles its rejection. But a command can also fail before
 * it returns one — a host that is not in contact is refused by the port itself, synchronously —
 * and a synchronous throw walks straight past the `catch` attached to the promise that was never
 * made. Inside a subscription callback that becomes an unhandled error in the page.
 *
 * So every call from the phone's screens goes through here, where both shapes of failure arrive
 * as a rejection and one `catch` is enough.
 */

/**
 * Calls the host, turning a synchronous refusal into a rejection.
 *
 * `async` is what makes it one line: a throw inside an async function is the rejection of the
 * promise it returns, whether it happened before or after the first await.
 */
export async function ask<T>(call: () => Promise<T>): Promise<T> {
  return await call()
}
