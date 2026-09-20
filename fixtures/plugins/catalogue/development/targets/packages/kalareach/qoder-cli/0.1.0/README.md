# kalareach/qoder-cli

Recognises Qoder CLI and names the session after it.

## What it does

The package carries one match rule and one document node. KalaReach matches the `qoder` executable,
labels the session, and runs Qoder CLI through its ordinary terminal path, exactly as it would run any
other program.

The match rule reports `inferred` confidence: it recognises the executable by name, which is a
reasonable guess rather than proof of which program is running. An explicit application selection by
the user always wins over it.

## What it asks for

Two capabilities, both inside the ceiling a newly enrolled repository already permits: metadata
matching and declarative presentation. It registers no actions, so there is nothing for a control to
invoke and nothing for the broker to dispatch.

## What it does not carry

There is no `connector.json` in this package. The declarative native-proxy table is what lets
KalaReach read Qoder CLI's own protocol: the framing, the request identifiers, the response
correlation, the routing, and the classification of each method as observation, mutation, credential
or unsupported. Without that table the gateway has nothing qualified to interpret, so the package
claims no semantic events, no upstream actions and no approval handling. Its capability list says
the same thing.
