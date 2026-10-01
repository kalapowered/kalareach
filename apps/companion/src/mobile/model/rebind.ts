/**
 * Where each detached draft's conversation stands, read from the host once contact is back.
 *
 * The rebind decides its three outcomes by comparing what a draft was written for with what the
 * host reports now, so what is reported has to be a fact. A session the host does not know is gone.
 * A session that is there reports the conversation its agent is in. A read that failed reports
 * nothing at all, and a draft nothing was reported for stays exactly as it was: failing to ask is
 * not the same as being told the session ended or the conversation moved.
 */

import type { HostPort } from '../../host/port'
import { failureCode } from '../../host/port'
import type { Draft, DraftTarget } from '../../model/drafts'
import { liveInstance, subjectOf } from '../../model/agent'
import type { ObservedTarget } from './lifecycle'

/** The code the host answers a read of a session it does not hold with. */
const UNKNOWN_SESSION = 'UNKNOWN_SESSION'

/** The attachment that presents a draft in its session again: the connection's, one per session. */
export function attachmentFor(sessionId: string): string {
  return `att-${sessionId}`
}

/**
 * Asks the host about every detached draft's session, once for each session.
 *
 * Only a detached draft is read for: a bound draft has lost nothing, and a conflicted or an
 * orphaned one is the person's to settle. One session's failed read leaves its drafts out of the
 * answer and does not stop the others.
 */
export async function observeTargets(
  port: HostPort,
  drafts: readonly Draft[]
): Promise<readonly ObservedTarget[]> {
  const detached = drafts.filter((draft) => draft.state === 'detached')
  const sessions = [...new Set(detached.map((draft) => draft.target.sessionId))]
  const found = new Map<string, DraftTarget | null | 'unchanged'>()
  await Promise.all(
    sessions.map(async (sessionId) => {
      const stands = await standing(port, sessionId)
      if (stands !== undefined) found.set(sessionId, stands)
    })
  )
  const observed: ObservedTarget[] = []
  for (const draft of detached) {
    const stands = found.get(draft.target.sessionId)
    if (stands === undefined) continue
    observed.push({
      draftId: draft.draftId,
      // A session with no agent running contradicts nothing a draft was written for.
      target: stands === 'unchanged' ? draft.target : stands,
      attachmentId: attachmentFor(draft.target.sessionId)
    })
  }
  return observed
}

/**
 * Where one session stands: its conversation now, null when the host does not know it, 'unchanged'
 * when it is there with no agent to compare, and undefined when the read failed.
 */
async function standing(
  port: HostPort,
  sessionId: string
): Promise<DraftTarget | null | 'unchanged' | undefined> {
  try {
    await port.sessionRead({ session_id: sessionId })
  } catch (failure) {
    return failureCode(failure) === UNKNOWN_SESSION ? null : undefined
  }
  try {
    const agents = await port.sessionAgents(sessionId)
    const live = liveInstance(agents.instances.instances)
    if (live === null) return 'unchanged'
    const facts = await port.agentCapabilities({
      subject: subjectOf(sessionId, live.application_instance_id)
    })
    return {
      sessionId,
      applicationInstanceId: live.application_instance_id,
      agentBindingRevision: facts.binding.binding_revision
    }
  } catch {
    return undefined
  }
}
