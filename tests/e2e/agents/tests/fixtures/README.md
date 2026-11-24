# Build list fixture

`builds.json` is the plugin repository's build list (`fixtures/agents/builds.json`) as committed at `d2e9695015dee78b3c4636a17769415773d7e2cf`, byte for byte. Its SHA-256 is `a932388a696a98100f75744be887e731bada6858e540e69c8e0b307cf8c5efaa`.

The cases that read it show what the driver makes of the eight entries as committed: the subject each gives, the fields each lacks and what a real start refuses. When the list changes, copy the new file here, change the commit and the digest above, and correct the cases that read an entry that changed.

`codex-config-with-provider.toml` and `codex-config-without-provider.toml` are the `config.toml` that the Codex entry's switches make, for a run in `/run` and a working folder `/work`, with and without the provider the entry routes the build to.
