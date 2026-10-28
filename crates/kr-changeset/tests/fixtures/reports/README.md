# Recorded test reports

Each file is what the named tool wrote, recorded on one machine and committed as it was, so that
the reader of reports is held to real output and not to a description of it. The only edits are
the machine name in a `hostname` attribute (`localhost`) and the directory a path was recorded
under (made relative to the project).

| File | Tool and version | Command |
| --- | --- | --- |
| `nextest-0.9.146.junit.xml` | cargo-nextest 0.9.146 | `cargo nextest run --profile ci --no-fail-fast`, with `retries = 2`, `report-skipped = "all"` and a `junit` path in the `ci` profile; one failing assertion, one panic, one test that passes on its third attempt and one ignored test |
| `vitest-5.0.5.junit.xml` | Vitest 5.0.5 | `vitest run --reporter=junit --outputFile=junit.xml`; a failing assertion, a skipped test, a todo and a table of two with one failing |
| `pytest-9.2.0.junit.xml` | pytest 9.2.0 | `pytest -q --junitxml=junit.xml`; a failing assertion, a skipped test, a table of two with one failing, an error in a fixture and an expected failure |
| `go-1.27.1.pass-fail-skip.json` | Go 1.27.1 | `go test -json ./ok/...`; a pass, a failure, a skip, and a table of two subtests with one failing |
| `go-1.27.1.build-failure.json` | Go 1.27.1 | `go test -json ./broken/... ./ok/...`; a package that does not build, whose build events come first, then the package above |
