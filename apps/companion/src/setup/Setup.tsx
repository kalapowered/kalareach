/**
 * The first thing somebody sees, and the only screen in this product that has to earn trust from
 * nothing.
 *
 * One path, five steps, and each step answers one question. Which application is this, and is it
 * the one macOS will file a grant under? What does macOS have to allow, and where is each switch?
 * What can this machine actually do, and how is that known? How should KalaReach run here? And
 * what did any of this cost you?
 *
 * Three rules run through it.
 *
 * Progress never implies a grant. The rail counts established answers, and a capability nobody has
 * performed the operation for counts as unchecked rather than done, because a first-run flow that
 * reported four of four on a machine where nothing was established would be lying to somebody who
 * is about to rely on it.
 *
 * The ceiling is stated rather than hidden. This application cannot grant a permission and cannot
 * know one was granted without performing the operation it guards. Both sentences are on the
 * screen.
 *
 * And nothing here does something on the person's behalf that they did not press. Every control
 * either reads, or opens a settings pane, or records a choice for the installation to act on, or
 * (on the descriptions card) asks the host to change a setting or start or stop a fetch and then
 * shows what the host says it did, or (on the capabilities step) asks the host to perform the
 * disclosed checks. That one is asked for only from the button on the sheet that lists what each
 * check does, so nobody runs a check without having been shown it first.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from 'react'

import type { CapabilityRecord, EnvironmentCapabilitiesResult } from '@kalareach/protocol'

import { Badge, Banner, Button, Card, Sheet, Switch } from '../components/ui'
import { useApp } from '../app/state'
import { failureMessage, watch, type SetupIdentity, type SetupPlatform } from '../host/port'
import {
  INSTALLABLES,
  NO_ACCOUNT_NEEDED,
  PERSISTENCE_LABEL,
  PROFILE_LABEL,
  readableBytes,
  SLEEP_COMMAND,
  SLEEP_OFFERS,
  type Installable
} from './host'
import {
  costSentence,
  fetchedFraction,
  PAUSE_WORDS,
  statusOf,
  STATUS_LABEL,
  useDescriptionSetup,
  type DescriptionSetupState
} from './descriptions'
import {
  CEILING,
  categoriesFor,
  coreCategories,
  featureCategories,
  type PermissionCategory
} from './permissions'
import {
  checksNote,
  disclosedChecks,
  routeOf,
  runningLine,
  type DisclosedCheck
} from './disclosure'
import { grantWasOffered, guidesPermissions, headingFor, stepsFor } from './platform'
import {
  capabilityLabel,
  displayState,
  EVIDENCE_LABEL,
  INVALIDATION_LABEL,
  STATE_LABEL,
  stateMeaning,
  STATE_TONE,
  tally,
  tallyLine,
  type DisplayState
} from './states'
import './setup.css'

/**
 * How often the host is asked where the checks stand while they run.
 *
 * A run can take about two minutes, and the page does not hold a call open for it: asking starts
 * the run and answers at once, and the answer to this question is what says when it ended.
 */
export const CHECKS_POLL_MS = 2_000

/** What a person is told when a run established nothing, by the host's own word for why. */
const CHECKS_FAILURE: Readonly<Record<string, string>> = {
  no_session:
    "No session of the kind this host creates is running. The checks run inside a session's own " +
    'worker, which is the place an agent runs, so start a session and run them again.',
  worker_refused:
    "The session's worker answered with an error: it was already performing a run, could not " +
    'start one, or its run did not finish. Run the checks again.',
  worker_unreachable:
    "The session's worker did not answer in time, or could not be reached. Run the checks again.",
  worker_failed:
    "The session's worker answered with something this application cannot use. Run the checks " +
    'again.'
}

/**
 * One line of the host's own words, as a sentence.
 *
 * A reason arrives as a clause, because it is written to be read after "because". Put in front of
 * another sentence it needs a capital and a stop, or the two run together.
 */
function sentence(said: string): string {
  const trimmed = said.trim()
  if (trimmed.length === 0) return trimmed
  const capitalised = trimmed[0]?.toUpperCase() + trimmed.slice(1)
  return /[.!?]$/.test(capitalised) ? capitalised : `${capitalised}.`
}

/**
 * One reading of the machine, before any of it is put on the screen.
 *
 * The application and the host are read apart, so that one failing leaves the other's answer on
 * the screen. A part that could not be read is absent, and what the screen showed of it stays.
 */
interface Reading {
  /** What the application said of itself; absent when it could not be read. */
  readonly identity: SetupIdentity | undefined
  /** What the host said of this machine; null when no host answered, absent when it could not be read. */
  readonly capabilities: EnvironmentCapabilitiesResult | null | undefined
  readonly failure: string | null
}

/**
 * One record's own identity on this screen.
 *
 * A capability can have more than one record, because a record is about a subject: one tool, one
 * application, one terminal. Keying a card by the capability alone would collapse two answers into
 * one and lose exactly the attribution that keeps a tool-specific permission visible.
 */
function recordKey(record: CapabilityRecord): string {
  return [
    record.capability,
    record.subject.application ?? '',
    record.subject.terminal ?? '',
    record.subject.session_id ?? '',
    record.subject.desktop_session_id ?? '',
    record.identity.binary ?? ''
  ].join('|')
}

/**
 * Which grant refused this record, where the host named one.
 *
 * Two grants can stand behind one capability, and a card for either of them would otherwise show a
 * refusal that came from the other. The host writes the permission's own name into the reason, so
 * the row can say which one it was and stop a person granting the wrong thing twice.
 */
function refusedBy(record: CapabilityRecord): string | null {
  if (record.state !== 'permission_required') return null
  const reason = record.disabled_reason ?? ''
  return (
    categoriesFor(record.capability).find((category) => reason.includes(category.name))?.name ??
    null
  )
}

/** The check that reads the one file a person nominated: its record is about that file, and names no program. */
const FILE_READ = 'desktop.authorised_file_read'

/**
 * What an answer was established about, for the row of "how this is known": the program a check
 * ran, or, for the read of a nominated file, the one file it was given. A read that had no file,
 * or did not get as far as one, was about nothing, and its own reason says why, so it has no row.
 */
function establishedAbout(record: CapabilityRecord): string | null {
  if (record.capability !== FILE_READ) return record.identity.binary ?? 'nothing installed'
  const opened =
    record.evidence_source === 'disclosed_probe' &&
    (record.state === 'qualified_available' || record.state === 'permission_required')
  return opened ? 'the one file it was given' : null
}

/** What a record was established about, in one line, where it names something. */
function aboutLine(record: CapabilityRecord): string | null {
  const parts = [record.subject.application, record.subject.terminal, record.identity.binary]
    .filter((part): part is string => typeof part === 'string' && part.length > 0)
  return parts.length > 0 ? parts.join(' · ') : null
}

/** The setup assistant. */
export function Setup(): ReactNode {
  const { port, say } = useApp()
  const [step, setStep] = useState(0)
  const [identity, setIdentity] = useState<SetupIdentity | null>(null)
  // What this application runs on, from the first reading of it that succeeds and never from a
  // later one: an application does not change platform while it runs. Until that reading ends, or
  // when it never does, it is not known, and a platform that is not known shows nothing that
  // belongs to macOS.
  const [platform, setPlatform] = useState<SetupPlatform | null>(null)
  const [capabilities, setCapabilities] = useState<EnvironmentCapabilitiesResult | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [reading, setReading] = useState(false)
  // How many times the records have been read. A permission pane visited before the latest read is
  // what turns "permission required" into "restart required": the grant was given and the running
  // process still does not have it.
  const [reads, setReads] = useState(0)
  const [visited, setVisited] = useState<Readonly<Record<string, number>>>({})
  const [install, setInstall] = useState<Readonly<Record<string, boolean>>>({})
  const descriptions = useDescriptionSetup(port)
  const [effectsOpen, setEffectsOpen] = useState(false)
  // Whether the list of effects was opened to run the checks from it, or only to be read. It stays
  // as it was while the list leaves, so the buttons do not vanish from a sheet on its way out.
  const [effectsRunnable, setEffectsRunnable] = useState(false)
  // The request to run the checks is on its way to the host, and has not been answered yet.
  const [asking, setAsking] = useState(false)
  // The name of the file the application holds for the read check, which the next run reads and
  // uses up, or null when it holds none. The path is never here: native code keeps it. This is what
  // the application last said, read when the screen opens, after every dialog and every run, and
  // whenever the application says that what it holds changed, and the page keeps no choice of its
  // own: it cannot say that none is chosen while one is held. It is undefined while a read is out,
  // after one that failed, and while the application says that the platform's file dialog is open,
  // which a screen opened again meanwhile reads where the window does not wait for the dialog: its
  // answer may replace the file. The line says nothing and no run is allowed until a read answers
  // that no dialog is open.
  const [read, setRead] = useState<string | null | undefined>(undefined)
  // The page is registered to be told when what the application holds changes. Until it is, and
  // after a registration that failed, no answer the page reads is believed, a dialog's included: a
  // change could come that it would miss.
  const [listening, setListening] = useState(false)
  const chosen = listening ? read : undefined
  // Which read of the held file is the newest, so that an answer to an older one is dropped.
  const newestRead = useRef(0)
  // The platform's file dialog is open, and has not been answered yet.
  const [choosing, setChoosing] = useState(false)
  // The environment in which the host last said a run is going, until an answer says it is not. A
  // reading that finds no host leaves the page without records, and a run goes on in the host all
  // the same, so this is what keeps the page asking until the host answers again, whether the run
  // was started here or somewhere else.
  const [accepted, setAccepted] = useState<string | null>(null)

  /** One reading of everything this screen is about, with no state written in it. */
  const load = useCallback(async (): Promise<Reading> => {
    const state = await port.connectionState()
    const [who, what] = await Promise.allSettled([
      port.setupIdentity(),
      state.environment_id
        ? port.environmentCapabilities({ environment_id: state.environment_id })
        : Promise.resolve(null)
    ])
    let failure: string | null = null
    if (who.status === 'rejected') failure = failureMessage(who.reason)
    else if (what.status === 'rejected') failure = failureMessage(what.reason)
    // A loss with no reason says only that: no host answered, and nothing said why. It is not a
    // claim that this machine has no host.
    else if (what.value === null) failure = state.reason ?? 'No reason was given.'
    return {
      identity: who.status === 'fulfilled' ? who.value : undefined,
      capabilities: what.status === 'fulfilled' ? what.value : undefined,
      failure
    }
  }, [port])

  const apply = useCallback((reading: Reading) => {
    const { identity: who, capabilities: what } = reading
    if (who !== undefined) {
      setIdentity(who)
      setPlatform((known) => known ?? who.platform)
    }
    if (what !== undefined) {
      setCapabilities(what)
      // A host that answers says whether a run is going. One that does not answer says nothing.
      if (what !== null) {
        setAccepted(what.checks.state === 'running' ? what.environment_id : null)
      }
      setReads((count) => count + 1)
    }
    setFailure(reading.failure)
    setLoaded(true)
  }, [])

  const refuse = useCallback((error: unknown) => {
    setFailure(failureMessage(error))
    setLoaded(true)
  }, [])

  useEffect(() => {
    let watching = true
    load()
      .then((reading) => {
        if (watching) apply(reading)
      })
      .catch((error: unknown) => {
        if (watching) refuse(error)
      })
    return () => {
      watching = false
    }
  }, [load, apply, refuse])

  const reread = useCallback(() => {
    setReading(true)
    load()
      .then(apply)
      .catch(refuse)
      .finally(() => {
        setReading(false)
      })
  }, [load, apply, refuse])

  // Asks the application which file it holds. Only the newest read's answer is believed, since an
  // older one can arrive after the choice it did not see.
  const askChosen = useCallback(() => {
    newestRead.current += 1
    const mine = newestRead.current
    port
      .heldAuthorisedFile()
      .then((held) => {
        if (mine !== newestRead.current) return
        if (held.dialog_open) setRead(undefined)
        else setRead(held.file === null ? null : held.file.name)
      })
      .catch((error: unknown) => {
        if (mine === newestRead.current) say(failureMessage(error), 'danger')
      })
  }, [port, say])

  // Asks again after the application may have changed what it holds. What the page said before is
  // not known to stand while it is asked, and not after a failure to ask, so it is cleared at once.
  const readChosen = useCallback(() => {
    setRead(undefined)
    askChosen()
  }, [askChosen])

  // The application says when what it holds changed: a dialog opened or closed, in this window or
  // where the window did not wait for it, or a run took the file. What the page said before is not
  // known to stand, so it asks again, and a dialog that is still open leaves nothing said. The
  // listener is registered before the first read, so that no change falls between the two: when the
  // screen opens nothing is known yet.
  useEffect(() => {
    const watched = watch(
      [port.onAuthorisedFileChanged(readChosen)],
      () => {
        setListening(true)
        askChosen()
      },
      (failure: unknown) => {
        say(failureMessage(failure), 'danger')
      }
    )
    return () => {
      watched.stop()
      setListening(false)
    }
  }, [port, readChosen, askChosen, say])

  const environmentId = capabilities?.environment_id ?? null
  const watching = accepted
  const checking = watching !== null

  // What a check does depends on the platform, and the list a person reads before a run is worded
  // for it. So no run starts, and none can be asked for, while the platform is not known.
  const runnable = environmentId !== null && platform !== null

  // Asking starts the run and answers at once. The sheet closes on the press, so the card behind it
  // is the one that says the checks are running.
  const runChecks = useCallback(() => {
    if (!runnable || chosen === undefined || choosing) return
    setEffectsOpen(false)
    setAsking(true)
    port
      .environmentCapabilitiesCheck({ environment_id: environmentId })
      .then((settled) => {
        // What the host answered is where the run stands, and it is kept before anything is read
        // again: a read that fails next must not leave the page believing nothing was started.
        const started = settled.value
        if (started !== null) {
          setCapabilities((current) => (current ? { ...current, checks: started } : current))
          setAccepted(started.state === 'running' ? environmentId : null)
        }
      })
      .then(() => load())
      .then(apply)
      .catch((error: unknown) => {
        say(failureMessage(error), 'danger')
      })
      .finally(() => {
        setAsking(false)
        // Whether the run took the choice is the application's to say: a request it refused before
        // it took the file leaves the file held.
        readChosen()
      })
  }, [port, environmentId, runnable, chosen, choosing, load, apply, say, readChosen])

  // The platform's own dialog answers. Closing it with no choice leaves an earlier choice as it was,
  // and either way the line says what the application holds afterwards.
  const chooseFile = useCallback(() => {
    setChoosing(true)
    port
      .chooseAuthorisedFile()
      .catch((error: unknown) => {
        say(failureMessage(error), 'danger')
      })
      .finally(() => {
        setChoosing(false)
        readChosen()
      })
  }, [port, say, readChosen])

  // While the host says a run is going, ask where it stands. The interval is cleared the moment
  // the answer changes or the page goes, so nothing asks after the run has ended.
  useEffect(() => {
    if (watching === null) return undefined
    const ask = async (): Promise<void> => {
      try {
        // Only the host's answer about the checks is asked for. Reading the identity again, and
        // counting a reading of the records, are for a person who asked to read them.
        const answer = await port.environmentCapabilities({ environment_id: watching })
        setCapabilities(answer)
        setFailure(null)
        setAccepted(answer.checks.state === 'running' ? answer.environment_id : null)
      } catch (error: unknown) {
        refuse(error)
      }
    }
    const timer = window.setInterval(() => {
      void ask()
    }, CHECKS_POLL_MS)
    return () => {
      window.clearInterval(timer)
    }
  }, [watching, port, refuse])

  const openPane = useCallback(
    (category: PermissionCategory) => {
      port
        .openSettingsPane(category.pane)
        .then((opened) => {
          setVisited((current) => ({ ...current, [category.pane]: reads }))
          say(`Opened ${opened.route}`, 'success')
        })
        .catch((error: unknown) => {
          say(failureMessage(error), 'danger')
        })
    },
    [port, reads, say]
  )

  const steps = stepsFor(platform)
  const records = useMemo(() => capabilities?.desktop.records ?? [], [capabilities])
  const offered = useCallback(
    (capability: string) => grantWasOffered(platform, capability, visited, reads),
    [platform, visited, reads]
  )
  const counted = useMemo(
    () =>
      tally(
        records,
        // The tally is the whole report, so it asks the question once for the report rather than
        // per record: a rail that changed its count as one card's history changed would be a
        // different number from the one the cards add up to.
        { grantWasOffered: false }
      ),
    [records]
  )

  const current = steps[step] ?? steps[0]
  const route = routeOf(platform, capabilities?.desktop.desktop.display_server ?? null)
  const listed = disclosedChecks(route)

  // Nothing is worded for a platform before the application has been read, because nothing says
  // which platform that is.
  if (!loaded) {
    return (
      <div className="setup" data-testid="setup">
        <header className="setup-heading">
          <h1>{headingFor(null)}</h1>
        </header>
        <div data-testid="setup-panel-reading">
          <UnreadCard failure={failure} loaded={loaded} />
        </div>
      </div>
    )
  }

  return (
    <div className="setup" data-testid="setup">
      <header className="setup-heading">
        <h1>{headingFor(platform)}</h1>
        <p>{current.question}</p>
      </header>

      <ol className="setup-rail" aria-label="Setup steps">
        {steps.map((each, index) => (
          <li key={each.id}>
            <button
              type="button"
              className="setup-step"
              data-state={index === step ? 'current' : index < step ? 'passed' : 'ahead'}
              aria-current={index === step ? 'step' : undefined}
              data-testid={`setup-step-${each.id}`}
              onClick={() => {
                setStep(index)
              }}
            >
              <span className="setup-step-mark" aria-hidden="true">
                {index + 1}
              </span>
              <span className="setup-step-title">{each.title}</span>
              {each.id === 'capabilities' ? (
                <span className="setup-step-note" data-testid="setup-tally">
                  {tallyLine(counted)}
                </span>
              ) : null}
            </button>
          </li>
        ))}
      </ol>

      {failure !== null && step !== 0 ? (
        <Banner
          tone="warning"
          title="No host is answering on this machine"
          detail={
            guidesPermissions(platform)
              ? `${sentence(failure)} The steps below still say what this Mac will be asked for.`
              : sentence(failure)
          }
        />
      ) : null}

      <div className="setup-body" key={current.id} data-testid={`setup-panel-${current.id}`}>
        {current.id === 'identity' ? (
          <IdentityStep
            identity={identity}
            platform={platform}
            failure={failure}
            loaded={loaded}
          />
        ) : null}
        {current.id === 'permissions' && guidesPermissions(platform) ? (
          <PermissionsStep
            records={records}
            offered={offered}
            visited={visited}
            onOpenPane={openPane}
            onExplainChecks={() => {
              setEffectsRunnable(false)
              setEffectsOpen(true)
            }}
          />
        ) : null}
        {current.id === 'permissions' && !guidesPermissions(platform) ? (
          <ChecksStep
            identity={identity}
            failure={failure}
            loaded={loaded}
            listed={listed}
            records={records}
            offered={offered}
            platform={platform}
          />
        ) : null}
        {current.id === 'capabilities' ? (
          <CapabilitiesStep
            capabilities={capabilities}
            platform={platform}
            offered={offered}
            reading={reading}
            loaded={loaded}
            runnable={runnable}
            onRead={reread}
            onRunChecks={() => {
              setEffectsRunnable(true)
              setEffectsOpen(true)
            }}
          />
        ) : null}
        {current.id === 'host' ? (
          <HostStep
            capabilities={capabilities}
            install={install}
            onInstall={(id, next) => {
              setInstall((current) => ({ ...current, [id]: next }))
            }}
            descriptions={descriptions}
          />
        ) : null}
        {current.id === 'ready' ? (
          <ReadyStep records={records} install={install} descriptions={descriptions} />
        ) : null}
      </div>

      <div className="setup-controls">
        <Button
          disabled={step === 0}
          onClick={() => {
            setStep((index) => Math.max(0, index - 1))
          }}
          data-wraps
        >
          Back
        </Button>
        <Button
          tone="primary"
          disabled={step === steps.length - 1}
          data-testid="setup-next"
          onClick={() => {
            setStep((index) => Math.min(steps.length - 1, index + 1))
          }}
          data-wraps
        >
          Continue
        </Button>
      </div>

      <Sheet
        open={effectsOpen}
        title="What each check does"
        closeLabel="Close the list of checks"
        description="Every one of these is run in the same place an agent runs, and each says what it does before it does it."
        onClose={() => {
          setEffectsOpen(false)
        }}
        footer={
          effectsRunnable ? (
            <>
              <Button
                onClick={() => {
                  setEffectsOpen(false)
                }}
                data-testid="setup-checks-not-now"
              >
                Not now
              </Button>
              <Button
                tone="primary"
                onClick={runChecks}
                disabled={asking || checking || !runnable || chosen === undefined || choosing}
                data-testid="setup-checks-run"
              >
                {asking || checking ? 'Running…' : 'Run the checks'}
              </Button>
            </>
          ) : null
        }
      >
        <ul className="setup-effects" data-testid="setup-effects">
          {listed.map((check) => (
            <li key={check.name}>
              <strong>{check.name}</strong>
              <p>{check.performs}</p>
              <p className="faint small">{check.effect}</p>
              {check.chooses === true && effectsRunnable ? (
                <div className="setup-file">
                  <Button
                    onClick={chooseFile}
                    disabled={choosing || asking || checking}
                    data-testid="setup-checks-choose"
                  >
                    Choose a file
                  </Button>
                  <p className="faint small" data-testid="setup-checks-file" aria-live="polite">
                    {chosen === undefined
                      ? ''
                      : chosen === null
                        ? 'No file chosen. The read check will read nothing and say so.'
                        : `File chosen: ${chosen}. The next run reads it once.`}
                  </p>
                </div>
              ) : null}
            </li>
          ))}
        </ul>
        <p className="faint small" data-testid="setup-effects-note">
          {checksNote(platform)}
        </p>
      </Sheet>
    </div>
  )
}

/* ---- Step 1: the identity -------------------------------------------------------------------- */

/**
 * The signature on this application, in one line.
 *
 * The distinction that matters is not "signed or not": it is whether the signature is one the
 * operating system will recognise again tomorrow. An ad-hoc signature is real, and it is different
 * every build, so a grant given against it is given to a build that will not exist.
 */
function signatureLine(signature: SetupIdentity['signature']): string {
  if (!signature.read) return signature.refusal ?? 'not read'
  if (!signature.valid) return 'a signature the operating system would not verify'
  if (signature.ad_hoc || !signature.authority) {
    return `an ad-hoc signature${signature.identifier ? ` on ${signature.identifier}` : ''}`
  }
  return signature.team ? `${signature.authority} (${signature.team})` : signature.authority
}

/** What the page says while the application has not been read, or could not be. */
function UnreadCard({
  failure,
  loaded
}: {
  readonly failure: string | null
  readonly loaded: boolean
}): ReactNode {
  return (
    <Card>
      <div className="card-body">
        <p className="faint">
          {loaded ? (failure ?? 'This application could not be read.') : 'Reading this application…'}
        </p>
      </div>
    </Card>
  )
}

function IdentityStep({
  identity,
  platform,
  failure,
  loaded
}: {
  readonly identity: SetupIdentity | null
  readonly platform: SetupPlatform | null
  readonly failure: string | null
  readonly loaded: boolean
}): ReactNode {
  if (!identity) return <UnreadCard failure={failure} loaded={loaded} />
  // The signature, the bundle and what a grant is filed under are macOS's: on another platform no
  // grant is filed under this application, so the card says which application this is and no more.
  const filed = guidesPermissions(platform)
  return (
    <>
      <Card data-testid="setup-identity">
        <header className="card-header">
          <h2>{identity.application_id}</h2>
          {filed ? (
            <Badge tone={identity.stable ? 'success' : 'warning'}>
              {identity.stable ? 'Stable identity' : 'Identity moves between launches'}
            </Badge>
          ) : null}
        </header>
        <div className="card-body">
          {filed ? (
            <p>
              macOS files every permission under a signed application, not under you and not under
              a path. This is the application it would file them under.
            </p>
          ) : null}
          <dl className="detail-list">
            <div>
              <dt>Version</dt>
              <dd>{identity.application_version}</dd>
            </div>
            <div>
              <dt>Running from</dt>
              <dd className="mono small">{identity.executable ?? 'not known'}</dd>
            </div>
            {filed ? (
              <>
                <div>
                  <dt>Inside an application bundle</dt>
                  <dd>{identity.bundled ? 'yes' : 'no'}</dd>
                </div>
                <div>
                  <dt>Signed by</dt>
                  <dd data-testid="setup-signature">{signatureLine(identity.signature)}</dd>
                </div>
              </>
            ) : null}
          </dl>
          {filed && identity.instability ? (
            <Banner
              tone="warning"
              title="Grants given now would have to be given again"
              detail={identity.instability}
            />
          ) : null}
        </div>
      </Card>

      <Card data-testid="setup-helper">
        <header className="card-header">
          <h2>The host on this machine</h2>
          <Badge tone={identity.helper_build ? 'success' : 'neutral'}>
            {identity.helper_build ? 'In contact' : 'Not in contact'}
          </Badge>
        </header>
        <div className="card-body">
          <p>
            Sessions run in the host, not in this window. Permissions a tool needs are the host&rsquo;s
            to hold, and this is the one this window is talking to.
          </p>
          <dl className="detail-list">
            <div>
              <dt>Build</dt>
              <dd className="mono small">{identity.helper_build ?? 'no host yet'}</dd>
            </div>
            <div>
              <dt>Environment</dt>
              <dd className="mono small">{identity.helper_environment ?? '—'}</dd>
            </div>
          </dl>
        </div>
      </Card>

      {filed ? (
        <p className="faint small" data-testid="setup-ceiling-identity">
          {identity.unverified}
        </p>
      ) : null}
    </>
  )
}

/* ---- Step 2: the permissions ----------------------------------------------------------------- */

function PermissionsStep({
  records,
  offered,
  visited,
  onOpenPane,
  onExplainChecks
}: {
  readonly records: readonly CapabilityRecord[]
  readonly offered: (capability: string) => boolean
  readonly visited: Readonly<Record<string, number>>
  readonly onOpenPane: (category: PermissionCategory) => void
  readonly onExplainChecks: () => void
}): ReactNode {
  return (
    <>
      <Banner
        tone="accent"
        title="These are four separate permissions"
        detail={CEILING}
        action={
          <Button onClick={onExplainChecks} data-testid="setup-explain-checks" data-wraps>
            What the checks do
          </Button>
        }
      />
      {coreCategories().map((category) => (
        <PermissionCard
          key={category.name}
          category={category}
          records={records}
          offered={offered}
          visited={visited[category.pane] !== undefined}
          onOpenPane={onOpenPane}
        />
      ))}

      <h2 className="setup-group">Only for the features that use them</h2>
      <p className="faint small">
        Nothing asks for these until you use the feature behind them, and nothing here is worse off
        if you never do.
      </p>
      {featureCategories().map((category) => (
        <PermissionCard
          key={category.name}
          category={category}
          records={records}
          offered={offered}
          visited={visited[category.pane] !== undefined}
          onOpenPane={onOpenPane}
        />
      ))}
    </>
  )
}

function PermissionCard({
  category,
  records,
  offered,
  visited,
  onOpenPane
}: {
  readonly category: PermissionCategory
  readonly records: readonly CapabilityRecord[]
  readonly offered: (capability: string) => boolean
  readonly visited: boolean
  readonly onOpenPane: (category: PermissionCategory) => void
}): ReactNode {
  const governed = records.filter((record) => category.governs.includes(record.capability))
  return (
    <Card data-testid={`setup-permission-${category.pane}`}>
      <header className="card-header">
        <h2>{category.name}</h2>
        {category.onlyFor ? <Badge tone="neutral">for {category.onlyFor}</Badge> : null}
      </header>
      <div className="card-body">
        <p>{category.purpose}</p>
        {category.caveat ? (
          <p className="setup-caveat" data-testid={`setup-caveat-${category.pane}`}>
            {category.caveat}
          </p>
        ) : null}
        {governed.length > 0 ? (
          <ul className="setup-governs">
            {governed.map((record) => {
              const state = displayState(record, { grantWasOffered: offered(record.capability) })
              const about = aboutLine(record)
              const refused = refusedBy(record)
              return (
                <li key={recordKey(record)}>
                  <span>
                    {capabilityLabel(record.capability)}
                    {about ? (
                      <span
                        className="mono small faint setup-about"
                        data-testid={`setup-about-${record.capability}`}
                      >
                        {about}
                      </span>
                    ) : null}
                    {refused && refused !== category.name ? (
                      <span
                        className="small faint setup-about"
                        data-testid={`setup-refused-${record.capability}`}
                      >
                        refused by {refused}, not by this one
                      </span>
                    ) : null}
                  </span>
                  <Badge tone={STATE_TONE[state]}>{STATE_LABEL[state]}</Badge>
                </li>
              )
            })}
          </ul>
        ) : null}
      </div>
      <footer className="card-footer setup-route">
        <span className="small faint" data-testid={`setup-route-${category.pane}`}>
          {category.route} · this switch cannot be set from here
        </span>
        <Button
          onClick={() => {
            onOpenPane(category)
          }}
          data-testid={`setup-open-${category.pane}`}
          data-wraps
        >
          {visited ? 'Open it again' : 'Open System Settings'}
        </Button>
      </footer>
    </Card>
  )
}

/**
 * Step 2 where setup guides nobody through a permission pane: each check, what it does on this
 * desktop, and what the host says about the capability it is evidence for.
 *
 * Nothing here opens a settings pane and nothing is asked for. The host's reason is shown as it
 * was written, because it is what says whether this desktop has a route for the check at all; the
 * page does not read a route out of it.
 */
function ChecksStep({
  identity,
  failure,
  loaded,
  listed,
  records,
  offered,
  platform
}: {
  readonly identity: SetupIdentity | null
  readonly failure: string | null
  readonly loaded: boolean
  readonly listed: readonly DisclosedCheck[]
  readonly records: readonly CapabilityRecord[]
  readonly offered: (capability: string) => boolean
  readonly platform: SetupPlatform | null
}): ReactNode {
  if (!identity) return <UnreadCard failure={failure} loaded={loaded} />
  return (
    <>
      <p className="faint small" data-testid="setup-checks-note">
        {checksNote(platform)}
      </p>
      {listed.map((check) => {
        // A capability can have more than one record, one for each subject it was established
        // about, and the page says what the host said of each of them.
        const found = records.filter((each) => each.capability === check.capability)
        const only = found.length === 1 ? found[0] : undefined
        const stateOf = (record: CapabilityRecord): DisplayState =>
          displayState(record, { grantWasOffered: offered(check.capability) })
        return (
          <Card key={check.capability} data-testid={`setup-disclosed-${check.capability}`}>
            <header className="card-header">
              <h2>{check.name}</h2>
              {only ? (
                <Badge
                  tone={STATE_TONE[stateOf(only)]}
                  data-testid={`setup-disclosed-state-${check.capability}`}
                >
                  {STATE_LABEL[stateOf(only)]}
                </Badge>
              ) : null}
            </header>
            <div className="card-body">
              <p>{check.performs}</p>
              <p className="faint small">{check.effect}</p>
              {only?.disabled_reason ? (
                <p className="faint small" data-testid={`setup-disclosed-reason-${check.capability}`}>
                  {only.disabled_reason}
                </p>
              ) : null}
              {found.length > 1 ? (
                <ul className="setup-governs">
                  {found.map((record) => {
                    const about = aboutLine(record)
                    return (
                      <li key={recordKey(record)}>
                        <span>
                          {about ? <span className="mono small faint setup-about">{about}</span> : null}
                          {record.disabled_reason ? (
                            <span
                              className="small faint setup-about"
                              data-testid={`setup-disclosed-reason-${check.capability}`}
                            >
                              {record.disabled_reason}
                            </span>
                          ) : null}
                        </span>
                        <Badge
                          tone={STATE_TONE[stateOf(record)]}
                          data-testid={`setup-disclosed-state-${check.capability}`}
                        >
                          {STATE_LABEL[stateOf(record)]}
                        </Badge>
                      </li>
                    )
                  })}
                </ul>
              ) : null}
            </div>
          </Card>
        )
      })}
    </>
  )
}

/* ---- Step 3: what this machine can do -------------------------------------------------------- */

function CapabilitiesStep({
  capabilities,
  platform,
  offered,
  reading,
  loaded,
  runnable,
  onRead,
  onRunChecks
}: {
  readonly capabilities: EnvironmentCapabilitiesResult | null
  readonly platform: SetupPlatform | null
  readonly offered: (capability: string) => boolean
  readonly reading: boolean
  readonly loaded: boolean
  /** Whether a run can be asked for: it cannot while the platform is not known. */
  readonly runnable: boolean
  readonly onRead: () => void
  readonly onRunChecks: () => void
}): ReactNode {
  if (!capabilities) {
    return (
      <Card>
        <div className="card-body">
          <p className="faint">
            {loaded && !reading
              ? 'There is nothing to read until a host answers on this machine.'
              : 'Reading what this machine can do…'}
          </p>
        </div>
      </Card>
    )
  }
  const { desktop } = capabilities.desktop
  return (
    <>
      <Card data-testid="setup-desktop">
        <header className="card-header">
          <h2>This desktop</h2>
          <Badge tone={desktop.availability === 'available' ? 'success' : 'warning'}>
            {desktop.availability}
          </Badge>
        </header>
        <div className="card-body">
          <dl className="detail-list">
            <div>
              <dt>Logged in as</dt>
              <dd>{desktop.os_user}</dd>
            </div>
            <div>
              <dt>Display</dt>
              <dd>{desktop.compositor ?? desktop.display_server}</dd>
            </div>
            <div>
              <dt>Login session</dt>
              <dd className="mono small">{desktop.desktop_session_id ?? 'no desktop'}</dd>
            </div>
          </dl>
          <p className="faint small">
            Being in this desktop is not evidence that anything can be done on it. Each answer
            below was established on its own.
          </p>
          <ChecksLine checks={capabilities.checks} platform={platform} />
          {!runnable ? (
            <p className="faint small" id="setup-run-unavailable" data-testid="setup-run-unavailable">
              No run can start here until this application has read which system it runs on,
              because what the checks do depends on it. Use “Read again” to try once more.
            </p>
          ) : null}
        </div>
        <footer className="card-footer setup-route">
          <Button onClick={onRead} disabled={reading} data-testid="setup-recheck" data-wraps>
            {reading ? 'Reading…' : 'Read again'}
          </Button>
          <Button
            tone="primary"
            onClick={onRunChecks}
            disabled={!runnable}
            aria-describedby={runnable ? undefined : 'setup-run-unavailable'}
            data-testid="setup-run-checks"
            data-wraps
          >
            Run the checks…
          </Button>
        </footer>
      </Card>
      {capabilities.checks.state === 'stale' ? (
        <Banner
          tone="warning"
          title="The checks need running again"
          detail="Something they were run against has changed: a login, a session, an update or a tool. The answers below are the ones the system gives, not what the checks found."
        />
      ) : null}
      {capabilities.checks.state === 'failed' && capabilities.checks.failure ? (
        <Banner
          tone="warning"
          title="The checks did not run"
          detail={CHECKS_FAILURE[capabilities.checks.failure] ?? 'The host gave no reason.'}
        />
      ) : null}

      {capabilities.desktop.records.map((record) => (
        <CapabilityCard
          key={recordKey(record)}
          record={record}
          platform={platform}
          offered={offered(record.capability)}
        />
      ))}
    </>
  )
}

/** Where the checks stand, in one line under the desktop. */
function ChecksLine({
  checks,
  platform
}: {
  readonly checks: EnvironmentCapabilitiesResult['checks']
  readonly platform: SetupPlatform | null
}): ReactNode {
  let line: string
  switch (checks.state) {
    case 'not_run':
      return (
        <p
          className="faint small"
          data-testid="setup-checks-state"
          data-state="not_run"
          aria-live="polite"
        >
          The checks have not been run, so the answers below are what the system says.
        </p>
      )
    case 'running':
      line = runningLine(platform)
      break
    case 'current':
      line = `The checks ran at ${timeOf(checks.finished_at_ms)}.`
      break
    case 'stale':
      line = 'The checks were run before something changed.'
      break
    case 'failed':
      line = 'The latest run found nothing.'
      break
  }
  return (
    <p
      className="faint small"
      data-testid="setup-checks-state"
      data-state={checks.state}
      aria-live="polite"
    >
      {line}
    </p>
  )
}

/** A moment the host gave in milliseconds, as the person's own clock writes it. */
function timeOf(milliseconds: string | null): string {
  if (milliseconds === null) return 'a moment ago'
  const at = new Date(Number(milliseconds))
  return Number.isNaN(at.getTime()) ? 'a moment ago' : at.toLocaleTimeString()
}

function CapabilityCard({
  record,
  platform,
  offered
}: {
  readonly record: CapabilityRecord
  readonly platform: SetupPlatform | null
  readonly offered: boolean
}): ReactNode {
  const [showEvidence, setShowEvidence] = useState(false)
  const state = displayState(record, { grantWasOffered: offered })
  const about = aboutLine(record)
  const establishedFor = establishedAbout(record)
  const meaning = stateMeaning(state, record.evidence_source, platform, record.capability)
  return (
    <Card data-testid={`setup-capability-${record.capability}`}>
      <header className="card-header">
        <h2>{capabilityLabel(record.capability)}</h2>
        <Badge tone={STATE_TONE[state]} data-testid={`setup-state-${record.capability}`}>
          {STATE_LABEL[state]}
        </Badge>
      </header>
      <div className="card-body">
        {about ? (
          <p className="mono small faint" data-testid={`setup-card-about-${record.capability}`}>
            {about}
          </p>
        ) : null}
        {meaning ? <p>{meaning}</p> : null}
        {record.disabled_reason ? (
          <p className="faint small" data-testid={`setup-reason-${record.capability}`}>
            {record.disabled_reason}
          </p>
        ) : null}
        <button
          type="button"
          className="text-link setup-disclose"
          aria-expanded={showEvidence}
          data-testid={`setup-evidence-toggle-${record.capability}`}
          onClick={() => {
            setShowEvidence((open) => !open)
          }}
        >
          {showEvidence ? 'Hide how this is known' : 'How this is known'}
        </button>
        <div
          className="setup-evidence"
          data-open={showEvidence ? 'true' : 'false'}
          aria-hidden={showEvidence ? undefined : true}
          inert={!showEvidence}
        >
          <div>
            <dl className="detail-list">
              <div>
                <dt>Established by</dt>
                <dd>{EVIDENCE_LABEL[record.evidence_source]}</dd>
              </div>
              {establishedFor === null ? null : (
                <div>
                  <dt>About</dt>
                  <dd className="mono small">
                    {establishedFor}
                    {record.identity.version ? ` · ${record.identity.version}` : ''}
                  </dd>
                </div>
              )}
              <div>
                <dt>Under</dt>
                <dd>{record.identity.profile ?? 'no profile'}</dd>
              </div>
              <div>
                <dt>Checked again when</dt>
                <dd>
                  {record.invalidation
                    .map((trigger) => INVALIDATION_LABEL[trigger] ?? trigger)
                    .join(', ')}
                </dd>
              </div>
            </dl>
          </div>
        </div>
      </div>
    </Card>
  )
}

/* ---- Step 4: how KalaReach runs here ---------------------------------------------------------- */

/** What the host's sleep setting is doing, in one sentence. */
function sleepNow(power: EnvironmentCapabilitiesResult['power'] | undefined): string {
  if (!power) return 'What it is set to here is not known until a host answers.'
  if (power.setting === 'off') return 'It is off.'
  const held = power.active
    ? `An assertion is held right now${power.reason ? `, because ${power.reason}` : ''}.`
    : 'Nothing is held right now.'
  return `It is set to ${power.setting}. ${held}`
}

function HostStep({
  capabilities,
  install,
  onInstall,
  descriptions
}: {
  readonly capabilities: EnvironmentCapabilitiesResult | null
  readonly install: Readonly<Record<string, boolean>>
  readonly onInstall: (id: Installable['id'], next: boolean) => void
  readonly descriptions: DescriptionSetupState
}): ReactNode {
  const persistence = capabilities?.persistence ?? []
  const power = capabilities?.power
  return (
    <>
      <p>
        Four separate things, and you can take any of them without the others. Nothing on this
        screen installs anything: what you choose here is your answer, and the last step shows it
        back to you. Session descriptions, below them, are different: the buttons there ask this
        host to act, and say so.
      </p>
      {INSTALLABLES.map((item) => {
        const answer = persistence.find((each) => each.profile === item.profile)
        return (
          <Card key={item.id} data-testid={`setup-install-${item.id}`}>
            <header className="card-header">
              <h2>{item.name}</h2>
              <Switch
                checked={install[item.id] === true}
                label={`Install ${item.name}`}
                onChange={(next) => {
                  onInstall(item.id, next)
                }}
              />
            </header>
            <div className="card-body">
              <p>{item.purpose}</p>
              <p className="faint small">{item.installs}</p>
              {item.command ? (
                <p className="faint small">
                  Installed by <code className="mono">{item.command}</code>
                </p>
              ) : null}
              {answer ? (
                <p className="setup-persistence" data-testid={`setup-persistence-${item.id}`}>
                  <strong>
                    {PROFILE_LABEL[answer.profile]}: {PERSISTENCE_LABEL[answer.persistence]}.
                  </strong>{' '}
                  {answer.detail}
                </p>
              ) : null}
            </div>
          </Card>
        )
      })}

      <Card data-testid="setup-sleep">
        <header className="card-header">
          <h2>Staying awake while work runs</h2>
          <Badge tone={power?.active ? 'accent' : 'neutral'}>
            {power ? power.setting : 'not read'}
          </Badge>
        </header>
        <div className="card-body">
          <p data-testid="setup-sleep-now">
            This is your machine&rsquo;s own sleep policy, so KalaReach leaves it alone until you
            say otherwise. {sleepNow(power)} Setting up KalaReach does not change it.
          </p>
          <ul className="setup-choices">
            {SLEEP_OFFERS.map((offer) => (
              <li key={offer.setting} data-testid={`setup-sleep-${offer.setting}`}>
                <code className="mono small">
                  {`${SLEEP_COMMAND} ${offer.setting}`}
                  {power?.setting === offer.setting ? ' — set now' : ''}
                </code>
                <span>{offer.meaning}</span>
              </li>
            ))}
          </ul>
        </div>
      </Card>

      <DescriptionsCard descriptions={descriptions} />
    </>
  )
}

/**
 * Keeps a person where they are in a card whose controls come and go with the host's answers.
 *
 * Where an answer removes the control that has focus (a fetch that ends, a retry that succeeds,
 * a read that fails), focus would fall to the page. It goes to the first control the card still
 * has instead. Focus the person moved away themselves, by a press elsewhere or by Tab, is theirs
 * and is left alone.
 */
function useKeepFocusInCard(card: RefObject<HTMLElement | null>): void {
  const focused = useRef<Element | null>(null)
  useEffect(() => {
    const track = (event: Event): void => {
      const target = event.target as Node | null
      if (event.type === 'focusin') {
        if (target !== null && card.current?.contains(target) === true) focused.current = target as Element
        // Focus that falls to a container of the card is not the person going anywhere: WebKit
        // gives it to the page's main region when a button that takes no focus is pressed.
        else if (target === null || !target.contains(card.current)) focused.current = null
      } else if (focused.current?.contains(target) !== true) {
        // A press somewhere else takes the person's place. A press on the control they are already
        // on does not move focus, and so says nothing new.
        focused.current = null
      }
    }
    document.addEventListener('focusin', track)
    document.addEventListener('pointerdown', track)
    return () => {
      document.removeEventListener('focusin', track)
      document.removeEventListener('pointerdown', track)
    }
  }, [card])
  // After each answer the card is drawn from.
  useEffect(() => {
    const gone = focused.current
    if (gone === null || gone.isConnected) return
    // Focus has fallen to the page, or to a container of the card (a press on a button that takes
    // no focus, in WebKit, focuses the nearest ancestor that does). A control the person went to
    // themselves is theirs, and is left alone.
    const active = document.activeElement
    const inCard = card.current
    if (inCard === null) return
    if (active !== null && active !== document.body && !active.contains(inCard)) return
    focused.current = null
    // The first control the card has, or its heading where it has none (a host that offers
    // nothing): the person stays in the card, and the view is not moved to find it.
    const next =
      inCard.querySelector<HTMLElement>('[role="switch"], button') ??
      inCard.querySelector<HTMLElement>('h2')
    next?.focus({ preventScroll: true })
  })
}

/**
 * Session descriptions: what this host offers, what it costs before anything is fetched, and the
 * controls the host has.
 *
 * Every figure and state is the host's answer. Pressing a button asks the host to act, and the
 * card is shown again from what the host says afterwards. Nothing here chooses a model or an
 * address: the host selected the one profile it would fetch, and says where it would fetch it from.
 */
function DescriptionsCard({ descriptions }: { readonly descriptions: DescriptionSetupState }): ReactNode {
  const { setup, failure, refusal } = descriptions
  const card = useRef<HTMLElement>(null)
  useKeepFocusInCard(card)
  const status = setup === null ? null : statusOf(setup)
  const fraction = setup === null ? null : fetchedFraction(setup)
  const canStart =
    setup !== null &&
    setup.offered &&
    (setup.download === 'not_started' ||
      setup.download === 'cancelled' ||
      setup.download === 'failed')
  // One button for the fetch, whichever way it can go: starting it, or stopping it. The same
  // element stays in the footer as its words change, so a person on it, by keyboard or screen
  // reader, is still on it when the host's answer changes what it does.
  const fetchButton =
    setup?.can_cancel === true
      ? ({ action: 'cancel', label: 'Cancel the download', testId: 'setup-model-cancel' } as const)
      : canStart
        ? ({
            action: 'start',
            label: setup.download === 'failed' ? 'Try the download again' : 'Download it',
            testId: 'setup-model-download'
          } as const)
        : null
  return (
    <Card ref={card} data-testid="setup-model">
      <header className="card-header">
        <h2 tabIndex={-1}>Session descriptions</h2>
        {status ? (
          <Badge
            tone={status === 'on' ? 'success' : status === 'failed' || status === 'paused' ? 'warning' : 'neutral'}
            data-testid="setup-model-status"
          >
            {STATUS_LABEL[status]}
          </Badge>
        ) : null}
      </header>
      <div className="card-body">
        <p>
          A title and a line about what each session is doing, written on this machine by a small
          model, not somewhere else. Nothing about KalaReach needs it: without it, a session is
          named by its directory.
        </p>
        {/* A live region that is always on the card, so what is put in it is announced. */}
        <div role="status">
          {setup === null ? (
            <p className="faint small" data-testid="setup-model-unread">
              {failure
                ? `What this host offers could not be read. ${failure}`
                : 'Reading what this host offers…'}
            </p>
          ) : null}
        </div>
        {setup && !setup.offered ? (
          <p className="faint small" data-testid="setup-model-unavailable">
            This host offers no model. {setup.unavailable ?? 'It gave no reason.'}
          </p>
        ) : null}
        {setup && setup.offered ? (
          <>
            <p className="faint small" data-testid="setup-model-size">
              {costSentence(setup)}
            </p>
            <p className="faint small">
              Nothing is fetched until you ask
              {setup.needs_hosted_account ? '.' : ', and it needs no account.'}
            </p>
            {setup.download === 'running' ? (
              <p className="faint small" data-testid="setup-model-progress">
                <progress
                  aria-label="Download progress"
                  max={Number(setup.asset_bytes)}
                  value={Number(setup.fetched_bytes)}
                />{' '}
                {readableBytes(Number(setup.fetched_bytes))} of{' '}
                {readableBytes(Number(setup.asset_bytes))}
                {fraction === null ? '' : `, ${String(Math.floor(fraction * 100))}%`}
              </p>
            ) : null}
            {setup.download === 'failed' ? (
              <p className="faint small" data-testid="setup-model-failure" role="alert">
                The download failed. {setup.failure ?? 'The host gave no reason.'}
              </p>
            ) : null}
            {setup.download === 'cancelled' ? (
              <p className="faint small">The download was cancelled and nothing was kept.</p>
            ) : null}
            {setup.download === 'verified' ? (
              <p className="faint small">The files are here, and each one was checked.</p>
            ) : null}
            {status === 'paused' && setup.paused !== null ? (
              <p className="faint small" data-testid="setup-model-paused">
                No description is being made right now: {PAUSE_WORDS[setup.paused]}.
              </p>
            ) : null}
          </>
        ) : null}
        {refusal ? (
          <p className="faint small" data-testid="setup-model-refused" role="alert">
            {refusal}
          </p>
        ) : null}
      </div>
      {setup && setup.offered ? (
        <div className="card-body setup-model-settings">
          <label className="row">
            <span className="spacer">Describe my sessions</span>
            <Switch
              checked={setup.enabled}
              label="Describe my sessions"
              disabled={setup.enabled && !setup.can_disable}
              onChange={descriptions.enable}
            />
          </label>
          <label className="row">
            <span className="spacer">Keep going on battery power</span>
            <Switch
              checked={setup.on_battery}
              label="Keep going on battery power"
              onChange={descriptions.onBattery}
            />
          </label>
        </div>
      ) : null}
      <footer className="card-footer setup-route">
        {setup === null ? (
          <Button data-testid="setup-model-retry" onClick={descriptions.reload} data-wraps>
            Ask again
          </Button>
        ) : null}
        {fetchButton ? (
          <Button
            tone={fetchButton.action === 'start' ? 'primary' : 'default'}
            data-testid={fetchButton.testId}
            onClick={() => {
              descriptions.download(fetchButton.action)
            }}
            data-wraps
          >
            {fetchButton.label}
          </Button>
        ) : null}
      </footer>
    </Card>
  )
}

/* ---- Step 5: ready ---------------------------------------------------------------------------- */

function ReadyStep({
  records,
  install,
  descriptions
}: {
  readonly records: readonly CapabilityRecord[]
  readonly install: Readonly<Record<string, boolean>>
  readonly descriptions: DescriptionSetupState
}): ReactNode {
  const counted = tally(records, { grantWasOffered: false })
  const chosen = INSTALLABLES.filter((item) => install[item.id] === true)
  const described = descriptions.setup === null ? null : statusOf(descriptions.setup)
  // Descriptions count as chosen once the host is fetching the model or has them switched on.
  const describing = described === 'downloading' || described === 'on' || described === 'paused'
  return (
    <>
      <Card data-testid="setup-summary">
        <header className="card-header">
          <h2>Where this machine stands</h2>
          <Badge tone={counted.ready === counted.total && counted.total > 0 ? 'success' : 'neutral'}>
            {tallyLine(counted)}
          </Badge>
        </header>
        <div className="card-body">
          <ul className="setup-governs">
            {records.map((record) => {
              const state = displayState(record, { grantWasOffered: false })
              const about = aboutLine(record)
              return (
                <li key={recordKey(record)}>
                  <span>
                    {capabilityLabel(record.capability)}
                    {about ? (
                      <span className="mono small faint setup-about">{about}</span>
                    ) : null}
                  </span>
                  <Badge tone={STATE_TONE[state]}>{STATE_LABEL[state]}</Badge>
                </li>
              )
            })}
          </ul>
          <p className="faint small">
            A capability that has not been checked is not a failure. It means nothing has done the
            thing yet, which is different from knowing it cannot be done.
          </p>
        </div>
      </Card>

      <Card data-testid="setup-chosen">
        <header className="card-header">
          <h2>What you chose</h2>
        </header>
        <div className="card-body">
          <ul className="setup-governs">
            {INSTALLABLES.map((item) => (
              <li key={item.id}>
                <span>{item.name}</span>
                <Badge tone={install[item.id] === true ? 'success' : 'neutral'}>
                  {install[item.id] === true ? 'install' : 'skip'}
                </Badge>
              </li>
            ))}
            <li data-testid="setup-chosen-descriptions">
              <span>Session descriptions</span>
              <Badge tone={describing ? 'success' : 'neutral'}>
                {described === null ? 'Not read' : STATUS_LABEL[described]}
              </Badge>
            </li>
          </ul>
          {chosen.length === 0 && !describing ? (
            <p className="faint small" data-testid="setup-nothing-chosen">
              Nothing at all, which is a complete answer. KalaReach works from here without any of
              it.
            </p>
          ) : (
            <div className="setup-commands" data-testid="setup-commands">
              {chosen.length > 0 ? (
                <>
                  <p className="faint small">
                    Nothing on this screen installed anything. These are the answers it has, and
                    what carries each one out:
                  </p>
                  <ul className="setup-choices">
                    {chosen.map((item) => (
                      <li key={item.id}>
                        <span>{item.name}</span>
                        <span className="faint small">
                          {item.command ? (
                            <code className="mono">{item.command}</code>
                          ) : (
                            'the installer, when you run it'
                          )}
                        </span>
                      </li>
                    ))}
                  </ul>
                </>
              ) : null}
              {describing ? (
                <p className="faint small" data-testid="setup-descriptions-asked">
                  Session descriptions are the host&rsquo;s to do, and you asked it to: it is
                  fetching the model or has it switched on.
                </p>
              ) : null}
            </div>
          )}
        </div>
      </Card>

      <Banner tone="accent" title="No account, and nothing signed up" detail={NO_ACCOUNT_NEEDED} />
    </>
  )
}
