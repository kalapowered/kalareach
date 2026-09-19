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
 * And nothing here is a switch that does something on the person's behalf. Every control either
 * reads, or opens a settings pane, or records a choice for the installation to act on.
 */

import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'

import type { CapabilityRecord, EnvironmentCapabilitiesResult } from '@kalareach/protocol'

import { Badge, Banner, Button, Card, Sheet, Switch } from '../components/ui'
import { useApp } from '../app/state'
import { failureMessage, type SetupIdentity } from '../host/port'
import {
  DEFAULT_MODEL,
  DOWNLOAD_LABEL,
  INSTALLABLES,
  NO_ACCOUNT_NEEDED,
  PERSISTENCE_LABEL,
  PROFILE_LABEL,
  readableBytes,
  SLEEP_COMMAND,
  SLEEP_OFFERS,
  type DownloadState,
  type Installable
} from './host'
import {
  CEILING,
  categoriesFor,
  coreCategories,
  featureCategories,
  type PermissionCategory
} from './permissions'
import {
  capabilityLabel,
  displayState,
  EVIDENCE_LABEL,
  INVALIDATION_LABEL,
  STATE_LABEL,
  STATE_MEANING,
  STATE_TONE,
  tally,
  tallyLine
} from './states'
import './setup.css'

/** The checks, and exactly what each one does, shown before any of them is asked for. */
const DISCLOSED_CHECKS: readonly {
  readonly name: string
  readonly performs: string
  readonly effect: string
}[] = [
  {
    name: 'Read a file you authorised',
    performs: 'Opens the file you nominated and reads the first few thousand bytes of it.',
    effect: 'Reads that file. Writes nothing.'
  },
  {
    name: 'Take a screen image',
    performs: 'Takes one image of the desktop and measures it.',
    effect: "Writes the image into the check's own directory and removes it before answering."
  },
  {
    name: 'Find an element',
    performs: 'Asks the accessibility tree for the name of one element.',
    effect: 'Reads the tree. Selects nothing, moves nothing, clicks nothing.'
  },
  {
    name: 'Open an application',
    performs: 'Starts one new background instance of an application and ends the one it started.',
    effect: 'Touches nothing you already have open.'
  },
  {
    name: 'Send a keystroke',
    performs: 'Delivers one keystroke.',
    effect:
      'This one changes something, so it runs only inside a test context of its own. Without ' +
      'one it is not run at all, and nothing is claimed about it either way.'
  }
]

/** The five steps, in order. */
const STEPS = [
  { id: 'identity', title: 'This application', question: 'Which application is macOS granting to?' },
  { id: 'permissions', title: 'Permissions', question: 'What does macOS have to allow?' },
  { id: 'capabilities', title: 'What this machine can do', question: 'And how is that known?' },
  { id: 'host', title: 'How KalaReach runs here', question: 'What should be installed?' },
  { id: 'ready', title: 'Ready', question: 'What did this cost you?' }
] as const

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

/** One reading of the machine, before any of it is put on the screen. */
interface Reading {
  readonly identity: SetupIdentity
  readonly capabilities: EnvironmentCapabilitiesResult | null
  readonly failure: string | null
}

/** The setup assistant. */
export function Setup(): ReactNode {
  const { port, say } = useApp()
  const [step, setStep] = useState(0)
  const [identity, setIdentity] = useState<SetupIdentity | null>(null)
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
  const [download, setDownload] = useState<DownloadState>('offered')
  const [effectsOpen, setEffectsOpen] = useState(false)

  /** One reading of everything this screen is about, with no state written in it. */
  const load = useCallback(async (): Promise<Reading> => {
    const state = await port.connectionState()
    const [who, what] = await Promise.all([
      port.setupIdentity(),
      state.environment_id
        ? port.environmentCapabilities({ environment_id: state.environment_id })
        : Promise.resolve(null)
    ])
    return {
      identity: who,
      capabilities: what,
      failure: what ? null : (state.reason ?? 'There is no host on this machine yet.')
    }
  }, [port])

  const apply = useCallback((reading: Reading) => {
    setIdentity(reading.identity)
    setCapabilities(reading.capabilities)
    setFailure(reading.failure)
    setReads((count) => count + 1)
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

  const records = useMemo(() => capabilities?.desktop.records ?? [], [capabilities])
  const offered = useCallback(
    (capability: string) =>
      categoriesFor(capability).some((category) => {
        const at = visited[category.pane]
        return at !== undefined && at < reads
      }),
    [visited, reads]
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

  const current = STEPS[step] ?? STEPS[0]

  return (
    <div className="setup" data-testid="setup">
      <header className="setup-heading">
        <h1>Set up KalaReach on this Mac</h1>
        <p>{current.question}</p>
      </header>

      <ol className="setup-rail" aria-label="Setup steps">
        {STEPS.map((each, index) => (
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

      {failure && step !== 0 ? (
        <Banner
          tone="warning"
          title="No host is answering on this machine"
          detail={`${sentence(failure)} The steps below still say what this Mac will be asked for.`}
        />
      ) : null}

      <div className="setup-body" key={current.id} data-testid={`setup-panel-${current.id}`}>
        {current.id === 'identity' ? (
          <IdentityStep identity={identity} failure={failure} loaded={loaded} />
        ) : null}
        {current.id === 'permissions' ? (
          <PermissionsStep
            records={records}
            offered={offered}
            visited={visited}
            onOpenPane={openPane}
            onExplainChecks={() => {
              setEffectsOpen(true)
            }}
          />
        ) : null}
        {current.id === 'capabilities' ? (
          <CapabilitiesStep
            capabilities={capabilities}
            offered={offered}
            reading={reading}
            loaded={loaded}
            onRead={reread}
            onExplainChecks={() => {
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
            download={download}
            onDownload={setDownload}
          />
        ) : null}
        {current.id === 'ready' ? (
          <ReadyStep records={records} install={install} download={download} />
        ) : null}
      </div>

      <div className="setup-controls">
        <Button
          disabled={step === 0}
          onClick={() => {
            setStep((index) => Math.max(0, index - 1))
          }}
        >
          Back
        </Button>
        <span className="spacer" />
        <Button
          tone="primary"
          disabled={step === STEPS.length - 1}
          data-testid="setup-next"
          onClick={() => {
            setStep((index) => Math.min(STEPS.length - 1, index + 1))
          }}
        >
          Continue
        </Button>
      </div>

      <Sheet
        open={effectsOpen}
        title="What each check does"
        description="Every one of these is run in the same place an agent runs, and each says what it does before it does it."
        onClose={() => {
          setEffectsOpen(false)
        }}
      >
        <ul className="setup-effects" data-testid="setup-effects">
          {DISCLOSED_CHECKS.map((check) => (
            <li key={check.name}>
              <strong>{check.name}</strong>
              <p>{check.performs}</p>
              <p className="faint small">{check.effect}</p>
            </li>
          ))}
        </ul>
        <p className="faint small">
          None of them sends input to an application you did not ask about, and none of them
          changes anything you own.
        </p>
      </Sheet>
    </div>
  )
}

/* ---- Step 1: the identity -------------------------------------------------------------------- */

function IdentityStep({
  identity,
  failure,
  loaded
}: {
  readonly identity: SetupIdentity | null
  readonly failure: string | null
  readonly loaded: boolean
}): ReactNode {
  if (!identity) {
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
  return (
    <>
      <Card data-testid="setup-identity">
        <header className="card-header">
          <h2>{identity.application_id}</h2>
          <Badge tone={identity.stable ? 'success' : 'warning'}>
            {identity.stable ? 'Stable identity' : 'Identity moves between launches'}
          </Badge>
        </header>
        <div className="card-body">
          <p>
            macOS files every permission under a signed application, not under you and not under a
            path. This is the application it would file them under.
          </p>
          <dl className="detail-list">
            <div>
              <dt>Version</dt>
              <dd>{identity.application_version}</dd>
            </div>
            <div>
              <dt>Running from</dt>
              <dd className="mono small">{identity.executable ?? 'not known'}</dd>
            </div>
            <div>
              <dt>Inside an application bundle</dt>
              <dd>{identity.bundled ? 'yes' : 'no'}</dd>
            </div>
          </dl>
          {identity.instability ? (
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

      <p className="faint small" data-testid="setup-ceiling-identity">
        {identity.unverified}
      </p>
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
          <Button onClick={onExplainChecks} data-testid="setup-explain-checks">
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
              return (
                <li key={record.capability}>
                  <span>{capabilityLabel(record.capability)}</span>
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
        >
          {visited ? 'Open it again' : 'Open System Settings'}
        </Button>
      </footer>
    </Card>
  )
}

/* ---- Step 3: what this machine can do -------------------------------------------------------- */

function CapabilitiesStep({
  capabilities,
  offered,
  reading,
  loaded,
  onRead,
  onExplainChecks
}: {
  readonly capabilities: EnvironmentCapabilitiesResult | null
  readonly offered: (capability: string) => boolean
  readonly reading: boolean
  readonly loaded: boolean
  readonly onRead: () => void
  readonly onExplainChecks: () => void
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
        </div>
        <footer className="card-footer setup-route">
          <Button onClick={onExplainChecks}>What the checks do</Button>
          <Button tone="primary" onClick={onRead} disabled={reading} data-testid="setup-recheck">
            {reading ? 'Checking…' : 'Check again'}
          </Button>
        </footer>
      </Card>

      {capabilities.desktop.records.map((record) => (
        <CapabilityCard
          key={record.capability}
          record={record}
          offered={offered(record.capability)}
        />
      ))}
    </>
  )
}

function CapabilityCard({
  record,
  offered
}: {
  readonly record: CapabilityRecord
  readonly offered: boolean
}): ReactNode {
  const [showEvidence, setShowEvidence] = useState(false)
  const state = displayState(record, { grantWasOffered: offered })
  return (
    <Card data-testid={`setup-capability-${record.capability}`}>
      <header className="card-header">
        <h2>{capabilityLabel(record.capability)}</h2>
        <Badge tone={STATE_TONE[state]} data-testid={`setup-state-${record.capability}`}>
          {STATE_LABEL[state]}
        </Badge>
      </header>
      <div className="card-body">
        <p>{STATE_MEANING[state]}</p>
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
        <div className="setup-evidence" data-open={showEvidence ? 'true' : 'false'}>
          <div>
            <dl className="detail-list">
              <div>
                <dt>Established by</dt>
                <dd>{EVIDENCE_LABEL[record.evidence_source]}</dd>
              </div>
              <div>
                <dt>About</dt>
                <dd className="mono small">
                  {record.identity.binary ?? 'nothing installed'}
                  {record.identity.version ? ` · ${record.identity.version}` : ''}
                </dd>
              </div>
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

function HostStep({
  capabilities,
  install,
  onInstall,
  download,
  onDownload
}: {
  readonly capabilities: EnvironmentCapabilitiesResult | null
  readonly install: Readonly<Record<string, boolean>>
  readonly onInstall: (id: Installable['id'], next: boolean) => void
  readonly download: DownloadState
  readonly onDownload: (next: DownloadState) => void
}): ReactNode {
  const persistence = capabilities?.persistence ?? []
  const power = capabilities?.power
  return (
    <>
      <p>
        Three separate things, and you can take any of them without the others. Nothing is
        installed until you finish this step.
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
            {power ? power.setting : 'off'}
          </Badge>
        </header>
        <div className="card-body">
          <p>
            This is your machine&rsquo;s own sleep policy, so KalaReach leaves it alone until you say
            otherwise. It is off, and setting up KalaReach does not change that.
          </p>
          <ul className="setup-choices">
            {SLEEP_OFFERS.map((offer) => (
              <li key={offer.setting} data-testid={`setup-sleep-${offer.setting}`}>
                <code className="mono small">
                  {offer.setting === 'off' ? 'off (now)' : `${SLEEP_COMMAND} ${offer.setting}`}
                </code>
                <span>{offer.meaning}</span>
              </li>
            ))}
          </ul>
        </div>
      </Card>

      <Card data-testid="setup-model">
        <header className="card-header">
          <h2>{DEFAULT_MODEL.name}</h2>
          <Badge tone={download === 'installed' ? 'success' : 'neutral'}>
            {DOWNLOAD_LABEL[download]}
          </Badge>
        </header>
        <div className="card-body">
          <p>{DEFAULT_MODEL.purpose}</p>
          <p className="faint small" data-testid="setup-model-size">
            {readableBytes(DEFAULT_MODEL.bytes)} to download.
          </p>
        </div>
        <footer className="card-footer setup-route">
          {download === 'downloading' ? (
            <Button
              data-testid="setup-model-cancel"
              onClick={() => {
                onDownload('cancelled')
              }}
            >
              Cancel the download
            </Button>
          ) : (
            <Button
              data-testid="setup-model-decline"
              onClick={() => {
                onDownload('declined')
              }}
            >
              Don&rsquo;t download it
            </Button>
          )}
          <Button
            tone="primary"
            disabled={download === 'downloading'}
            data-testid="setup-model-download"
            onClick={() => {
              onDownload('downloading')
            }}
          >
            Download it
          </Button>
        </footer>
      </Card>
    </>
  )
}

/* ---- Step 5: ready ---------------------------------------------------------------------------- */

function ReadyStep({
  records,
  install,
  download
}: {
  readonly records: readonly CapabilityRecord[]
  readonly install: Readonly<Record<string, boolean>>
  readonly download: DownloadState
}): ReactNode {
  const counted = tally(records, { grantWasOffered: false })
  const chosen = INSTALLABLES.filter((item) => install[item.id] === true)
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
              return (
                <li key={record.capability}>
                  <span>{capabilityLabel(record.capability)}</span>
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
            <li>
              <span>{DEFAULT_MODEL.name}</span>
              <Badge tone={download === 'installed' ? 'success' : 'neutral'}>
                {DOWNLOAD_LABEL[download]}
              </Badge>
            </li>
          </ul>
          {chosen.length === 0 ? (
            <p className="faint small" data-testid="setup-nothing-chosen">
              Nothing at all, which is a complete answer. KalaReach works from here without any of
              it.
            </p>
          ) : null}
        </div>
      </Card>

      <Banner tone="accent" title="No account, and nothing signed up" detail={NO_ACCOUNT_NEEDED} />
    </>
  )
}
