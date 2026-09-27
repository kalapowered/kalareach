/**
 * Installed, Catalogue and Repositories.
 *
 * The host keeps each repository's whole signed catalogue index and its installed packages on the
 * machine, so what this screen lists is read from the host alone and its search is a filter over
 * what is already here: it works with no network, and says so. A package the admissions leave out
 * says why in the host's words, and a release a live binding still holds after an upgrade stays
 * listed until its bindings close.
 */

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'

import type { CatalogueListResult, PluginListResult } from '@kalareach/protocol'

import { Badge, Banner, Button, Card, Segmented } from '../components/ui'
import { useApp } from '../app/state'
import { failureMessage, watch, type Watch } from '../host/port'
import { ask } from '../mobile/model/call'

type Tab = 'installed' | 'catalogue' | 'repositories'

/** A digest as a person compares one: its first twelve characters. */
function short(digest: string): string {
  return digest.slice(0, 12)
}

/** A size in the units a person reads one in. */
function bytes(count: string): string {
  const value = Number(count)
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(value % 1024 ** 3 === 0 ? 0 : 1)} GiB`
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(value % 1024 ** 2 === 0 ? 0 : 1)} MiB`
  if (value >= 1024) return `${Math.round(value / 1024)} KiB`
  return `${value} bytes`
}

/** When something happened, as a local date and time. */
function when(ms: string): string {
  return new Date(Number(ms)).toLocaleString()
}

/** The three package views. */
export function Plugins(): ReactNode {
  const { port } = useApp()
  const [installed, setInstalled] = useState<PluginListResult | null>(null)
  const [catalogues, setCatalogues] = useState<CatalogueListResult | null>(null)
  const [tab, setTab] = useState<Tab>('installed')
  const [query, setQuery] = useState('')
  const [failure, setFailure] = useState<string | null>(null)
  // Every read, on opening and on a retry, is made under one watch with no listeners, so only the
  // newest read's answer is shown, and none once the screen closes.
  const reads = useRef<Watch | null>(null)

  const load = useCallback(() => {
    const current = reads.current?.read() ?? null
    if (current === null) return
    ask(async () => {
      // The environment is the one this connection belongs to, as the host stamped it.
      const connection = await port.connectionState()
      const environment = connection.environment_id
      if (environment === null) {
        throw new Error(connection.reason ?? 'This application is not in contact with a host.')
      }
      return await Promise.all([
        port.pluginList({ environment_id: environment }),
        port.catalogueList({ environment_id: environment })
      ])
    })
      .then(([plugins, enrolled]) => {
        if (!current()) return
        setInstalled(plugins)
        setCatalogues(enrolled)
        setFailure(null)
      })
      .catch((error: unknown) => {
        if (!current()) return
        setFailure(failureMessage(error))
      })
  }, [port])

  useEffect(() => {
    const reading = watch([], load)
    reads.current = reading
    return () => {
      reading.stop()
      if (reads.current === reading) reads.current = null
    }
  }, [load])

  const needle = query.trim().toLowerCase()
  const matches = (haystack: readonly string[]) =>
    needle.length === 0 || haystack.some((value) => value.toLowerCase().includes(needle))

  const plugins = (installed?.plugins ?? []).filter((plugin) =>
    matches([plugin.plugin_id, plugin.catalogue_id, plugin.version])
  )
  const live = (installed?.live_releases ?? []).filter((release) =>
    matches([release.plugin_id, release.catalogue_id, release.version])
  )
  const enrolled = (catalogues?.catalogues ?? []).filter((catalogue) =>
    matches([catalogue.catalogue_id, catalogue.kind, catalogue.metadata_url, ...catalogue.ceiling])
  )

  return (
    <>
      <header className="page-heading">
        <div>
          <p className="eyebrow">Plugins</p>
          <h1>Packages</h1>
          <p>What is installed, what each repository offers, and where it comes from.</p>
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
            placeholder="Search packages and repositories"
            onChange={(event) => {
              setQuery(event.target.value)
            }}
          />
        </label>
        <span className="small faint" data-testid="offline-search-note">
          Search looks through what this host holds, so it works with no network.
        </span>
      </div>

      {tab === 'installed' ? (
        <div className="stack">
          <div className="card-grid" data-testid="installed-list">
            {plugins.map((plugin) => (
              <Card key={plugin.plugin_id} data-plugin={plugin.plugin_id}>
                <div className="card-header">
                  <div className="spacer">
                    <h2>{plugin.plugin_id}</h2>
                    <p className="muted small">
                      {plugin.version} · from {plugin.catalogue_id}
                    </p>
                  </div>
                  <span className="row wrap">
                    {plugin.revoked ? <Badge tone="danger">Revoked</Badge> : null}
                    <Badge tone={plugin.enabled ? 'success' : 'neutral'}>
                      {plugin.enabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                    {plugin.pinned ? <Badge tone="neutral">Pinned</Badge> : null}
                  </span>
                </div>
                <div className="card-body">
                  <p className="small muted mono">Package {short(plugin.package_digest)}</p>
                  <p className="small muted">
                    {plugin.live_bindings === null
                      ? 'Not every session has reported whether it uses this.'
                      : `${plugin.live_bindings} live ${plugin.live_bindings === '1' ? 'binding' : 'bindings'}`}
                  </p>
                  {plugin.admission?.state === 'left_out' ? (
                    <p className="small warning-text" data-testid="left-out">
                      New sessions do not use it: {plugin.admission.detail}
                    </p>
                  ) : null}
                  {plugin.revoked ? (
                    <p className="small warning-text">
                      Its repository revoked this release. Sessions already using it keep it until
                      they end.
                    </p>
                  ) : null}
                </div>
              </Card>
            ))}
          </div>
          {installed !== null && plugins.length === 0 ? (
            <p className="muted small">
              {needle.length > 0 ? 'Nothing installed matches that.' : 'Nothing is installed.'}
            </p>
          ) : null}
          {live.length > 0 ? (
            <Card data-testid="live-releases">
              <div className="card-body">
                <h2>Still in use</h2>
                <p className="muted small">
                  Releases that live sessions still hold after an upgrade, a move or a removal. Each
                  stays until its sessions end.
                </p>
                {live.map((release) => (
                  <div className="divided-row" key={`${release.plugin_id}-${release.package_digest}`}>
                    <span className="spacer">
                      <strong>{release.plugin_id}</strong> {release.version}
                      <span className="faint small mono"> {short(release.package_digest)}</span>
                    </span>
                    {release.ending ? <Badge tone="neutral">Ending</Badge> : null}
                    {release.revoked ? <Badge tone="danger">Revoked</Badge> : null}
                  </div>
                ))}
              </div>
            </Card>
          ) : null}
        </div>
      ) : null}

      {tab === 'catalogue' ? (
        <div className="card-grid" data-testid="catalogue-list">
          {enrolled.map((catalogue) => (
            <Card key={catalogue.catalogue_id} data-catalogue={catalogue.catalogue_id}>
              <div className="card-header">
                <div className="spacer">
                  <h2>{catalogue.catalogue_id}</h2>
                  <p className="muted small">
                    {Number(catalogue.entries).toLocaleString()} packages in its index
                    {catalogue.generation === null ? '' : ` · generation ${catalogue.generation}`}
                  </p>
                </div>
                <Badge tone="neutral">{catalogue.kind}</Badge>
              </div>
              <div className="card-body">
                <p className="small muted">
                  {catalogue.budgets.full_offline_mirror
                    ? 'Every package it lists is kept on this host.'
                    : 'A package is fetched when it is installed, and kept once it is.'}
                </p>
                <p className="small">Its packages may, without a further grant:</p>
                <ul className="capability-list">
                  {catalogue.ceiling.map((capability) => (
                    <li key={capability}>
                      <code>{capability}</code>
                    </li>
                  ))}
                </ul>
              </div>
            </Card>
          ))}
          {catalogues !== null && enrolled.length === 0 ? (
            <p className="muted small">
              {needle.length > 0 ? 'No repository matches that.' : 'No repository is enrolled.'}
            </p>
          ) : null}
        </div>
      ) : null}

      {tab === 'repositories' ? (
        <Card data-testid="repository-list">
          <div className="card-body">
            {enrolled.map((catalogue) => (
              <div className="divided-row" key={catalogue.catalogue_id}>
                <div className="spacer">
                  <strong>{catalogue.catalogue_id}</strong>
                  <p className="muted small mono">{catalogue.metadata_url}</p>
                  <p className="muted small">
                    Trust root {short(catalogue.root_digest)} ·{' '}
                    {catalogue.synced_at_ms === null
                      ? 'not synchronised'
                      : `synchronised ${when(catalogue.synced_at_ms)}`}
                  </p>
                  <p className="muted small">
                    Up to {bytes(catalogue.budgets.metadata_bytes)} of metadata and{' '}
                    {bytes(catalogue.budgets.payload_cache_bytes)} of packages
                  </p>
                </div>
                <span className="row wrap">
                  <Badge tone="neutral">{catalogue.kind}</Badge>
                  {catalogue.pinned_generation !== null ? (
                    <Badge tone="neutral">Pinned at {catalogue.pinned_generation}</Badge>
                  ) : null}
                </span>
              </div>
            ))}
            {catalogues !== null && enrolled.length === 0 ? (
              <p className="muted small">
                {needle.length > 0 ? 'No repository matches that.' : 'No repository is enrolled.'}
              </p>
            ) : null}
          </div>
        </Card>
      ) : null}
    </>
  )
}
