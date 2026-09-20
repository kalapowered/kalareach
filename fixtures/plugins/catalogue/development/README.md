# The development catalogue generation

A copy of the development catalogue release the KalaReach plugins repository publishes, held here
so the host's catalogue client is tested against a generation a real pipeline signed rather than
against one a test made up.

| | |
| --- | --- |
| Source | `kalareach-plugins`, `snapshots/development/` |
| Commit | `44084fc058106bca25bfb4f2118cc349187419df` |
| Generation | 1 |
| Metadata valid to | 2036-09-12 |
| Packages | seven, at 0.1.0 |

## What it is

One immutable generation, exactly as a host receives one:

```text
root.json          the trust root, adopted out of band
metadata/          root, timestamp, snapshot and targets metadata
targets/           index.json and every package payload, by target name
```

The signing keys' private halves are not here and never will be. This copy carries public metadata
and package files only, which is everything a client needs to verify a generation and nothing that
could sign one.

## How it changes

By a deliberate re-copy, and no other way. Nothing in this repository writes into this directory,
and no test regenerates it: a fixture a test can rewrite proves whatever the test decided rather
than what the pipeline published. Replacing it means copying the new generation from a named commit
of the plugins repository and changing the commit in the table above in the same change.

The metadata expires in 2036. A test that verifies this generation with expiry enforced will start
failing then, and the fix is a fresh generation from the pipeline rather than a test that stops
checking expiry.
