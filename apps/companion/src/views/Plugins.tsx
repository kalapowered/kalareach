/**
 * Installed, Catalogue and Repositories.
 *
 * The host holds the whole signed catalogue index, so search here is a filter over what is already
 * on the machine: it works with no network and says so. A package whose payload is not cached and
 * cannot be fetched is shown as exactly that, never as a capability that is quietly unavailable.
 */

import { useCallback, useEffect, useState, type ReactNode } from 'react'

import { Badge, Banner, Button, Card, Segmented } from '../components/ui'
import { ENVIRONMENT_ID, useApp } from '../app/state'
import { failureMessage } from '../host/port'
import type { PackageViews } from '../model/pending'

type Tab = 'installed' | 'catalogue' | 'repositories'

/** The three package views. */
export function Plugins(): ReactNode {
  const { port } = useApp()
  const [views, setViews] = useState<PackageViews | null>(null)
  const [tab, setTab] = useState<Tab>('installed')
  const [query, setQuery] = useState('')
  const [failure, setFailure] = useState<string | null>(null)

  const load = useCallback(() => {
    port
      .pluginList(ENVIRONMENT_ID, {})
      .then((result) => {
        setViews(result as PackageViews)
        setFailure(null)
      })
      .catch((error: unknown) => {
        setFailure(failureMessage(error))
      })
  }, [port])

  useEffect(load, [load])

  const needle = query.trim().toLowerCase()
  const matches = (haystack: readonly string[]) =>
    needle.length === 0 || haystack.some((value) => value.toLowerCase().includes(needle))

  return (
    <>
      <header className="page-heading">
        <div>
          <p className="eyebrow">Plugins</p>
          <h1>Packages</h1>
          <p>What is installed, what is available, and where it comes from.</p>
        </div>
        <div className="page-actions">
          <Segmented
            label="Package view"
            value={tab}
            options={[
              { value: 'installed', label: 'Installed' },
              { value: 'catalogue', label: 'Catalogue' },
              { value: 'repositories', label: 'Repositories' }
            ]}
            onChange={setTab}
          />
        </div>
      </header>

      {failure ? (
        <Banner
          tone="warning"
          title="This host is not answering"
          detail={failure}
          action={<Button onClick={load}>Try again</Button>}
        />
      ) : null}

      <div className="toolbar">
        <label className="search-field">
          <span className="visually-hidden">Search packages</span>
          <input
            type="search"
            value={query}
            data-testid="catalogue-search"
            placeholder="Search the catalogue"
            onChange={(event) => {
              setQuery(event.target.value)
            }}
          />
        </label>
        {views?.index_complete ? (
          <span className="small faint" data-testid="offline-search-note">
            The whole index is on this host, so search works with no network.
          </span>
        ) : null}
      </div>

      {tab === 'installed' ? (
        <div className="card-grid" data-testid="installed-list">
          {(views?.installed ?? [])
            .filter((entry) => matches([entry.name, entry.publisher, entry.package_id]))
            .map((entry) => (
              <Card key={entry.package_id}>
                <div className="card-header">
                  <div className="spacer">
                    <h2>{entry.name}</h2>
                    <p className="muted small">
                      {entry.publisher} · {entry.version}
                    </p>
                  </div>
                  <Badge tone={entry.enabled ? 'success' : 'neutral'}>
                    {entry.enabled ? 'Enabled' : 'Disabled'}
                  </Badge>
                </div>
                <div className="card-body">
                  <ul className="capability-list">
                    {entry.capabilities.map((capability) => (
                      <li key={capability}>
                        <code>{capability}</code>
                      </li>
                    ))}
                  </ul>
                  {entry.pinned_generation ? (
                    <p className="small faint">Pinned at generation {entry.pinned_generation}.</p>
                  ) : null}
                </div>
              </Card>
            ))}
        </div>
      ) : null}

      {tab === 'catalogue' ? (
        <div className="card-grid" data-testid="catalogue-list">
          {(views?.catalogue ?? [])
            .filter((entry) => matches([entry.name, entry.publisher, entry.summary, entry.package_id]))
            .map((entry) => (
              <Card key={entry.package_id}>
                <div className="card-header">
                  <div className="spacer">
                    <h2>{entry.name}</h2>
                    <p className="muted small">
                      {entry.publisher} · {entry.version}
                    </p>
                  </div>
                  {entry.installed ? <Badge tone="success">Installed</Badge> : null}
                </div>
                <div className="card-body">
                  <p>{entry.summary}</p>
                  {!entry.payload_available_offline ? (
                    <p className="small warning-text" data-testid="payload-offline">
                      Its payload is not on this host. Installing it needs a connection to{' '}
                      {entry.repository_id}.
                    </p>
                  ) : null}
                </div>
              </Card>
            ))}
        </div>
      ) : null}

      {tab === 'repositories' ? (
        <Card data-testid="repository-list">
          <div className="card-body">
            {(views?.repositories ?? []).map((repository) => (
              <div className="divided-row" key={repository.repository_id}>
                <div className="spacer">
                  <strong>{repository.label}</strong>
                  <p className="muted small mono">{repository.origin}</p>
                  <p className="muted small">
                    {repository.publisher} · generation {repository.generation}
                  </p>
                </div>
                <span className="row wrap">
                  <Badge tone="neutral">{repository.kind}</Badge>
                  {repository.automatic_matching ? (
                    <Badge tone="accent">Matches automatically</Badge>
                  ) : null}
                  {repository.pinned ? <Badge tone="neutral">Pinned</Badge> : null}
                  {repository.metadata_expired ? (
                    <Badge tone="warning">
                      Metadata expired · installed packages still work
                    </Badge>
                  ) : null}
                </span>
              </div>
            ))}
          </div>
        </Card>
      ) : null}
    </>
  )
}
