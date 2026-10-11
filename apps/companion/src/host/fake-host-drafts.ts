/**
 * The drafts the host holds for the files a person attaches, as the scripted host keeps them.
 *
 * A file attached to a draft is bound on the host to a draft of its own, made for the window, and
 * the host answers a binding with the path the file can be read at and when that stops being so.
 * This is that exchange, with the host's rules that a page can meet: a binding names the revision
 * of the draft it expects, a refusal changes nothing, and an answer the page never hears can still
 * have been applied.
 */

import type { AttachmentHandle } from '@kalareach/protocol'

import type { Settled } from './port'

/** A refusal in the shape native code rejects with. */
export interface FakeRefusal {
  readonly code: string
  readonly message: string
}

/** What a test can read of, and do to, the host's drafts for files. */
export interface FakeHostDrafts {
  /** Every draft the interface made on the host, in order. */
  readonly made: readonly {
    readonly draft_id: string
    readonly session_id: string | null
    readonly application_instance_id: string | null
  }[]
  /** Every binding the interface asked for, in order, as it asked. */
  readonly bound: readonly {
    readonly draft_id: string
    readonly transfer_id: string
    readonly expected_revision: string
    readonly insertion_method: string
  }[]
  /** Makes every binding refuse with `refusal` until it is cleared with null. */
  refuseBinds(refusal: FakeRefusal | null): void
  /** Makes every draft creation refuse with `refusal` until it is cleared with null. */
  refuseCreates(refusal: FakeRefusal | null): void
  /**
   * Makes the host apply the next creation or binding and say nothing the page can read, as a
   * connection lost after the request was sent does.
   */
  leaveNextUnconfirmed(what: 'create' | 'bind'): void
  /** Makes the next binding answer with the draft and no read grant. */
  leaveNextGrantless(): void
  /** Makes the next binding's read grant name another file, or another insertion method. */
  giveNextGrantTo(change: { readonly transfer_id?: string; readonly insertion_method?: string }): void
  /** Sets how long a path stays valid from the moment it is given, in milliseconds. */
  setGrantLifetime(ms: number): void
}

/** The parameters of a binding, as the page sends them. */
export interface BindParams {
  readonly draft_id: string
  readonly expected_revision: string
  readonly transfer_id: string
  readonly contribution: { readonly insertion_method: string; readonly max_count: string }
}

/** The scripted host's drafts for files, and what a test controls of them. */
export interface ScriptedHostDrafts {
  readonly controls: FakeHostDrafts
  /** Records a file the host published, so that a binding can name it. */
  published(handle: AttachmentHandle): void
  /** Makes a draft, or refuses. */
  create(sessionId: string | null, instanceId: string | null): Settled
  /** Binds a published file to a draft, or refuses. */
  bind(params: BindParams): Settled
}

const ENVIRONMENT = '3f1a2c40-11aa-4b2c-9d3e-000000000001'
const FIRST_MS = 1_763_000_000_000

function refused(refusal: FakeRefusal): never {
  // eslint-disable-next-line @typescript-eslint/only-throw-error -- a refusal is data, as native code's is
  throw { code: refusal.code, message: refusal.message, user_action: 'nothing' }
}

/** The host's drafts for files. */
export function scriptedHostDrafts(): ScriptedHostDrafts {
  interface Held {
    readonly draftId: string
    readonly sessionId: string | null
    readonly instanceId: string | null
    revision: number
    readonly attachments: Map<string, unknown>
  }
  const drafts = new Map<string, Held>()
  const handles = new Map<string, AttachmentHandle>()
  const made: { draft_id: string; session_id: string | null; application_instance_id: string | null }[] = []
  const bound: {
    draft_id: string
    transfer_id: string
    expected_revision: string
    insertion_method: string
  }[] = []
  let binds: FakeRefusal | null = null
  let creates: FakeRefusal | null = null
  let unconfirmed: 'create' | 'bind' | null = null
  let grantless = false
  let grantChange: { transfer_id?: string; insertion_method?: string } | null = null
  let lifetime = 15 * 60_000
  let counter = 0

  const record = (held: Held) => ({
    application_instance_id: held.instanceId,
    attachments: [...held.attachments.values()],
    created_at_ms: String(FIRST_MS),
    device_id: null,
    draft_id: held.draftId,
    environment_id: ENVIRONMENT,
    revision: String(held.revision),
    session_id: held.sessionId,
    state: 'open',
    text: '',
    updated_at_ms: String(FIRST_MS)
  })
  const nothingSaid = (): Settled => ({ receipt: null, value: null, action_id: '00000000-0000-4000-8000-0000000000ff' })

  return {
    controls: {
      made,
      bound,
      refuseBinds: (refusal) => {
        binds = refusal
      },
      refuseCreates: (refusal) => {
        creates = refusal
      },
      leaveNextUnconfirmed: (what) => {
        unconfirmed = what
      },
      leaveNextGrantless: () => {
        grantless = true
      },
      giveNextGrantTo: (change) => {
        grantChange = change
      },
      setGrantLifetime: (ms) => {
        lifetime = ms
      }
    },
    published(handle) {
      handles.set(handle.transfer_id, handle)
    },
    create(sessionId, instanceId) {
      if (creates) refused(creates)
      counter += 1
      const held: Held = {
        draftId: `dddddddd-dddd-4ddd-8ddd-${String(counter).padStart(12, '0')}`,
        sessionId,
        instanceId,
        revision: 1,
        attachments: new Map()
      }
      drafts.set(held.draftId, held)
      made.push({
        draft_id: held.draftId,
        session_id: sessionId,
        application_instance_id: instanceId
      })
      if (unconfirmed === 'create') {
        unconfirmed = null
        return nothingSaid()
      }
      return { receipt: null, action_id: null, value: { draft: record(held) } }
    },
    bind(params) {
      bound.push({
        draft_id: params.draft_id,
        transfer_id: params.transfer_id,
        expected_revision: params.expected_revision,
        insertion_method: params.contribution.insertion_method
      })
      if (binds) refused(binds)
      // The host binds the manual path with no declaration, and no other: none can be declared.
      if (params.contribution.insertion_method !== 'manual_terminal_workflow') {
        refused({
          code: 'UNSUPPORTED_CAPABILITY',
          message: `no integration declared ${params.contribution.insertion_method} for this operation; only a manual_terminal_workflow can be bound`
        })
      }
      // As the host decides them: what the caller names, then the session, the count, and last the
      // revision it expects, which a binding's own first attempt can explain.
      const held = drafts.get(params.draft_id)
      const handle = handles.get(params.transfer_id)
      if (held === undefined || handle === undefined) {
        refused({ code: 'INVALID_ARGUMENT', message: 'That names nothing this caller owns.' })
      }
      if (
        handle.session_id !== null &&
        held.sessionId !== null &&
        handle.session_id !== held.sessionId
      ) {
        refused({
          code: 'INVALID_ARGUMENT',
          message: `This attachment belongs to session ${handle.session_id} and the draft targets ${held.sessionId}.`
        })
      }
      if (
        !held.attachments.has(params.transfer_id) &&
        held.attachments.size >= Number(params.contribution.max_count)
      ) {
        refused({
          code: 'INVALID_ARGUMENT',
          message: `This operation accepts ${params.contribution.max_count} attachments and the draft already holds ${String(held.attachments.size)}.`
        })
      }
      if (String(held.revision) !== params.expected_revision) {
        refused({
          code: 'DRAFT_CONFLICT',
          message: `This draft is at revision ${String(held.revision)} and the binding expects ${params.expected_revision}.`
        })
      }
      held.revision += 1
      const attachment = {
        external_destination: null,
        failure_detail: null,
        handle,
        insertion_method: params.contribution.insertion_method,
        read_grant: grantless
          ? null
          : {
              environment_id: ENVIRONMENT,
              expires_at_ms: String(Date.now() + lifetime),
              grant_id: `eeeeeeee-eeee-4eee-8eee-${String(counter).padStart(12, '0')}`,
              host_path: `/var/kalareach/attachments/${handle.transfer_id}/${handle.original_file_name}`,
              insertion_method: grantChange?.insertion_method ?? params.contribution.insertion_method,
              transfer_id: grantChange?.transfer_id ?? handle.transfer_id
            },
        state: 'recorded',
        upstream_evidence: null
      }
      grantless = false
      grantChange = null
      held.attachments.set(handle.transfer_id, attachment)
      if (unconfirmed === 'bind') {
        unconfirmed = null
        return nothingSaid()
      }
      return { receipt: null, action_id: null, value: { draft: record(held), attachment } }
    }
  }
}
