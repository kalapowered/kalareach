# Records an earlier build wrote

A device's `hosts.json` and `attempt.json`, byte for byte as the build at `1f2d55fe68e5` wrote
them through its own paired-host store, which named approvals in a proposed grant by an upstream's
text identifier. This build names them by the broker's resource identity and reads no other shape.

| Directory | The proposed grant names |
| --- | --- |
| `empty` | no approval, as every build wrote it |
| `named` | the approval `1`, by that text |
| `uuid` | the approval `52525252-5252-5252-5252-525252525252`, text that happens to be a UUID |

Each directory holds one paired host, `0f0f…`, and one waiting attempt, for invitation `1111…`.
Nothing regenerates these files: they change only by a deliberate re-writing at a named commit.
