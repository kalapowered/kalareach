#!/usr/bin/env python3
"""Holds the register of triaged upstream changes to what the shells' upstreams publish.

The register (docs/shell-integration/upstream.md) says which sources each shell package watches
and records what was made of every security-relevant change. Nothing read those sources until
this script. It reads them and fails on a change the register has no row for:

  * the security advisories of the fish, PowerShell, PSReadLine and PCRE2 repositories (fish
    links PCRE2, so a PCRE2 advisory is a fish advisory);
  * the issues of PowerShell/Announcements labelled Security, which is where Microsoft publishes
    the advisories that reach PowerShell, the .NET ones included;
  * the stable releases of fish and PowerShell, the tags of zsh and the releases and patches of
    bash that are newer than what the packages pin. Neither zsh nor bash publishes a machine
    readable advisory feed, so a new release or patch is the only signal either gives;
  * the RustSec advisories against the crates in fish's Cargo.lock, read from a cargo-audit
    report.

A change needs a row when it was first published on or after the day the register started, or
when its affected range includes what the package pins (a RustSec advisory against the lock needs
one whatever its date). A row covers it when the row names the package and names the change by
its identifier, its status is one the register defines, a `scheduled` row is not past its target,
and, for an advisory with an affected range, the row quotes the range as the source gives it, so
that a range which changes later is a new fact and not an old row. A change with no row passes
for one working day after it was published, which is the time the register allows for triage, and
fails after it.

Every source is public. The run's own read-only token is used for api.github.com only, to lift
the rate limit. A source that cannot be read, or answers with nothing where it must have
something, fails the run and names itself; nothing passes silently.

  check-shell-advisories.py check [--root DIR] [--facts DIR] [--audit FILE] [--now YYYY-MM-DD]
  check-shell-advisories.py facts --out DIR [--prefix DIR]
  check-shell-advisories.py self-test
"""

import argparse
import datetime
import hashlib
import http.server
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

REGISTER = "docs/shell-integration/upstream.md"
STARTED = datetime.date(2026, 9, 20)
STATUSES = ("released", "scheduled", "flagged", "not-affected")
GITHUB = "https://api.github.com"
GNU_BASH = "https://ftp.gnu.org/gnu/bash"
RETRIES = 3
RETRY_DELAY = 2.0
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class SourceError(Exception):
    """A source that could not be read, or that answered with nothing it must have."""


# ---- reading the sources -------------------------------------------------------------------------


def fetch(url, token=None):
    """The body at url, after up to three tries. The token goes to api.github.com only."""
    headers = {"User-Agent": "kalareach-shell-advisories", "Accept": "application/vnd.github+json"}
    if token and urllib.parse.urlparse(url).hostname == "api.github.com":
        headers["Authorization"] = "Bearer " + token
    last = None
    for attempt in range(RETRIES):
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read()
        except (urllib.error.URLError, OSError) as error:
            last = error
            time.sleep(RETRY_DELAY * (attempt + 1))
    raise SourceError("%s: %s" % (url, last))


def fetch_pages(url, token, must_hold_something=True):
    """Every item of a paginated GitHub list, as one list."""
    items = []
    for page in range(1, 30):
        separator = "&" if "?" in url else "?"
        body = fetch("%s%sper_page=100&page=%d" % (url, separator, page), token)
        try:
            chunk = json.loads(body)
        except ValueError as error:
            raise SourceError("%s: the answer is not JSON (%s)" % (url, error))
        if not isinstance(chunk, list):
            raise SourceError("%s: the answer is not a list" % url)
        items.extend(chunk)
        if len(chunk) < 100:
            break
    if must_hold_something and not items:
        raise SourceError("%s: the answer holds nothing" % url)
    return items


def day(text):
    return datetime.date.fromisoformat(text[:10]) if text else None


def numbers(text):
    return tuple(int(part) for part in re.findall(r"\d+", text))


def in_range(range_text, version):
    """Whether a version is inside a range such as '>= 10.32, <= 10.47'. An unreadable range
    counts as inside it, because the safe mistake is a row too many."""
    wanted = numbers(version)
    span = re.match(r"\s*([0-9][0-9.]*)\s*-\s*([0-9][0-9.]*)\s*$", range_text)
    if span:
        return numbers(span.group(1)) <= wanted <= numbers(span.group(2))
    for comparator in range_text.split(","):
        match = re.match(r"\s*(<=|>=|<|>|=)?\s*([0-9][0-9.]*)\s*$", comparator)
        if not match:
            return True
        operator, bound = match.group(1) or "=", numbers(match.group(2))
        held = {
            "<=": wanted <= bound,
            ">=": wanted >= bound,
            "<": wanted < bound,
            ">": wanted > bound,
            "=": wanted == bound,
        }[operator]
        if not held:
            return False
    return True


def finding(source, package, identifier, aliases, published, range_text=None, needs_row=True):
    return {
        "source": source,
        "package": package,
        "id": identifier,
        "aliases": [identifier] + [alias for alias in aliases if alias],
        "published": published,
        "range": range_text,
        "needs_row": needs_row,
    }


def repository_advisories(api, token, repository, package, pinned, may_be_empty=False):
    """The security advisories of one repository. `pinned` is the version of what the package
    pins from it, or None where only the date decides. A repository that has published none
    is the one case of a source that may answer with nothing."""
    source = "%s security advisories" % repository
    items = fetch_pages(
        "%s/repos/%s/security-advisories" % (api, repository),
        token,
        must_hold_something=not may_be_empty,
    )
    found = []
    for item in items:
        published = day(item.get("published_at"))
        range_text = None
        affects = False
        for vulnerability in item.get("vulnerabilities") or []:
            text = vulnerability.get("vulnerable_version_range")
            if text and pinned and in_range(text, pinned):
                range_text, affects = text, True
        recent = published is not None and published >= STARTED
        found.append(
            finding(
                source,
                package,
                item["ghsa_id"],
                [item.get("cve_id")],
                published,
                range_text if affects else None,
                needs_row=recent or affects,
            )
        )
    return found


def announcements(api, token):
    """The advisories Microsoft publishes for PowerShell, the .NET ones that reach it included."""
    url = "%s/repos/PowerShell/Announcements/issues?labels=Security&state=all" % api
    found = []
    for item in fetch_pages(url, token):
        cves = re.findall(r"CVE-\d{4}-\d{4,}", item.get("title") or "")
        identifier = cves[0] if cves else "PowerShell/Announcements#%d" % item["number"]
        created, updated = day(item.get("created_at")), day(item.get("updated_at"))
        recent = (created is not None and created >= STARTED) or (
            updated is not None and updated >= STARTED
        )
        found.append(
            finding(
                "PowerShell/Announcements",
                "psreadline",
                identifier,
                ["https://github.com/PowerShell/Announcements/issues/%d" % item["number"]],
                created,
                needs_row=recent,
            )
        )
    return found


def powershell_releases(api, token, floors):
    """Stable PowerShell releases above the first fixed release of their series, and every stable
    release of a series above the newest series the register's advisories list."""
    found = []
    newest = max(floors) if floors else (0, 0)
    for item in fetch_pages("%s/repos/PowerShell/PowerShell/releases" % api, token):
        if item.get("prerelease") or item.get("draft"):
            continue
        tag = item["tag_name"]
        version = numbers(tag)
        if len(version) < 3:
            continue
        series = version[:2]
        newer = (series in floors and version > floors[series]) or series > newest
        if newer:
            found.append(
                finding(
                    "PowerShell/PowerShell releases",
                    "psreadline",
                    tag,
                    [],
                    day(item.get("published_at")),
                )
            )
    return found


def fish_releases(api, token, pinned):
    found = []
    for item in fetch_pages("%s/repos/fish-shell/fish-shell/releases" % api, token):
        if item.get("prerelease") or item.get("draft"):
            continue
        if numbers(item["tag_name"]) > numbers(pinned):
            found.append(
                finding(
                    "fish-shell releases",
                    "fish",
                    "fish-" + item["tag_name"],
                    [],
                    day(item.get("published_at")),
                )
            )
    return found


def zsh_tags(api, token, pinned):
    found = []
    for item in fetch_pages("%s/repos/zsh-users/zsh/tags" % api, token):
        match = re.fullmatch(r"zsh-(\d+(?:\.\d+){1,2})", item["name"])
        if match and numbers(match.group(1)) > numbers(pinned):
            found.append(finding("zsh tags", "zsh", item["name"], [], None))
    return found


def bash_releases(ftp, pinned):
    """Releases of a series newer than the pinned one, and patches of the pinned series above
    the pinned patch. The 5.2 series gets no patch after the pinned one once its successor is out,
    so a release of the next series is the signal that matters."""
    found = []
    listing = fetch(ftp + "/").decode("utf-8", "replace")
    names = re.findall(r'href="(bash-(\d+\.\d+(?:\.\d+)?)\.tar\.gz)"', listing)
    if not names:
        raise SourceError("%s/: the listing holds no release" % ftp)
    for _, version in names:
        if numbers(version) > numbers(pinned):
            found.append(finding("bash releases", "bash", "bash-" + version, [], None))
    series = "%d%d" % numbers(pinned)[:2]
    patches = fetch("%s/bash-%d.%d-patches/" % (ftp, *numbers(pinned)[:2])).decode("utf-8", "replace")
    names = re.findall(r'href="(bash%s-(\d+))"' % series, patches)
    if not names:
        raise SourceError("%s/bash-%d.%d-patches/: the listing holds no patch" % (ftp, *numbers(pinned)[:2]))
    for name, number in names:
        if int(number) > numbers(pinned)[2]:
            found.append(finding("bash patches", "bash", name, [], None))
    return found


def audited_lock(path):
    """The RustSec advisories against fish's lock, from a cargo-audit report."""
    try:
        with open(path) as report:
            data = json.load(report)
        vulnerabilities = data["vulnerabilities"]["list"]
        warnings = data["warnings"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SourceError("%s: the cargo-audit report cannot be read (%s)" % (path, error))
    advisories = [entry["advisory"] for entry in vulnerabilities]
    for kind, entries in warnings.items():
        if kind == "yanked":
            continue
        advisories.extend(entry["advisory"] for entry in entries if entry.get("advisory"))
    return [
        finding("RustSec, fish's Cargo.lock", "fish", advisory["id"], [], day(advisory.get("date")))
        for advisory in advisories
    ]


# ---- the register -------------------------------------------------------------------------------


def block(text, marker):
    open_marker, close_marker = "<!-- kr:%s -->" % marker, "<!-- /kr:%s -->" % marker
    start = text.find(open_marker)
    end = text.find(close_marker)
    if start < 0 or end < start:
        raise SourceError("%s has no <!-- kr:%s --> block" % (REGISTER, marker))
    return text[start + len(open_marker) : end]


def triage_rows(text):
    rows = []
    for line in block(text, "triage").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        rows.append(cells)
    rows = rows[2:]
    parsed = []
    for cells in rows:
        if len(cells) != 6:
            raise SourceError("a triage row has %d cells: %s" % (len(cells), cells))
        parsed.append(
            {
                "date": cells[0],
                "change": cells[1],
                "packages": cells[2].split(", "),
                "assessment": cells[3],
                "target": cells[4],
                "status": cells[5],
            }
        )
    return parsed


def figure_within(text, unit):
    words = " ".join(text.split())
    position = 0
    spelled = (
        "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen "
        "fifteen"
    ).split()
    while True:
        at = words.find("within ", position)
        if at < 0:
            return None
        rest = words[at + len("within ") :]
        word, _, after = rest.partition(" ")
        if after.startswith(unit):
            word = word.strip(".,;:").lower()
            if word in spelled:
                return spelled.index(word)
            if word.isdigit():
                return int(word)
        position = at + len("within ")


def mentions(text, aliases):
    for alias in aliases:
        if re.search(r"(?<![\w.-])%s(?![\w-]|\.\d)" % re.escape(alias), text):
            return True
    return False


def working_days_between(start, end):
    """The working days after `start` up to and including `end`."""
    days, cursor = 0, start
    while cursor < end:
        cursor += datetime.timedelta(days=1)
        if cursor.weekday() < 5:
            days += 1
    return days


def judge(findings, rows, now, triage_days):
    """What is wrong with the register for these findings, and what is only waiting out its
    allowance."""
    problems, waiting = [], []
    for item in findings:
        if not item["needs_row"]:
            continue
        label = "%s (%s)" % (item["id"], item["source"])
        covering = [
            row
            for row in rows
            if item["package"] in row["packages"] and mentions(row["change"], item["aliases"])
        ]
        if not covering:
            published = item["published"]
            if published is not None and working_days_between(published, now) <= triage_days:
                waiting.append("%s was published %s and is inside its triage allowance" % (label, published))
            else:
                problems.append("%s has no triage row for %s" % (label, item["package"]))
            continue
        row = covering[0]
        if row["status"] not in STATUSES:
            problems.append("%s: its row says %r, which is not a status the register defines" % (label, row["status"]))
        try:
            target = datetime.date.fromisoformat(row["target"])
        except ValueError:
            problems.append("%s: its row has no target date (%r)" % (label, row["target"]))
            continue
        if row["status"] == "scheduled" and target < now:
            problems.append("%s: its row is still scheduled and its target %s has passed" % (label, target))
        if item["range"] and item["range"] not in row["change"]:
            problems.append(
                "%s: the source now gives the affected range %r, which its row does not quote"
                % (label, item["range"])
            )
    return problems, waiting


# ---- the whole check ------------------------------------------------------------------------------


def pinned_versions(root):
    def manifest(name):
        with open(os.path.join(root, "shells", name, "manifest.json")) as handle:
            return json.load(handle)

    floors = {}
    for advisory in manifest("psreadline")["qualified"]["powershell_advisories"]:
        for series, fixed in advisory["first_fixed"].items():
            key = numbers(series)
            floors[key] = max(floors.get(key, ()), numbers(fixed))
    return {
        "fish": manifest("fish")["upstream"]["version"],
        "zsh": manifest("zsh")["upstream"]["version"],
        "bash": manifest("bash")["upstream"]["version"],
        "floors": floors,
    }


def collect(root, api, ftp, token, facts, audit):
    pins = pinned_versions(root)
    pcre2 = None
    if facts:
        with open(os.path.join(facts, "facts.json")) as handle:
            pcre2 = json.load(handle)["pcre2"]
    if not pcre2:
        raise SourceError("the bundled PCRE2 version is not known: run the facts command first")
    found = []
    found += repository_advisories(api, token, "fish-shell/fish-shell", "fish", pins["fish"])
    found += repository_advisories(api, token, "PCRE2Project/pcre2", "fish", pcre2)
    found += repository_advisories(api, token, "PowerShell/PowerShell", "psreadline", None)
    found += repository_advisories(api, token, "PowerShell/PSReadLine", "psreadline", None, may_be_empty=True)
    found += announcements(api, token)
    found += powershell_releases(api, token, pins["floors"])
    found += fish_releases(api, token, pins["fish"])
    found += zsh_tags(api, token, pins["zsh"])
    found += bash_releases(ftp, pins["bash"])
    found += audited_lock(audit)
    return found


def check(args, register_text=None):
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if register_text is None:
        with open(os.path.join(args.root, REGISTER)) as handle:
            register_text = handle.read()
    now = datetime.date.fromisoformat(args.now) if args.now else datetime.date.today()
    triage_days = figure_within(block(register_text, "target"), "working day")
    if triage_days is None:
        raise SourceError("%s states no time within which a change is triaged" % REGISTER)
    findings = collect(args.root, args.github_api, args.gnu_bash, token, args.facts, args.audit)
    problems, waiting = judge(findings, triage_rows(register_text), now, triage_days)
    return findings, problems, waiting


def run_check(args):
    try:
        findings, problems, waiting = check(args)
    except SourceError as error:
        print("check-shell-advisories: FAILED to read a source: %s" % error, file=sys.stderr)
        return 1
    for line in waiting:
        print("check-shell-advisories: waiting: " + line)
    for line in problems:
        print("check-shell-advisories: " + line, file=sys.stderr)
    needing = sum(1 for item in findings if item["needs_row"])
    print(
        "check-shell-advisories: %d changes read, %d need a row, %d problems"
        % (len(findings), needing, len(problems))
    )
    return 1 if problems else 0


# ---- the facts the check needs from a build --------------------------------------------------------


def default_prefix():
    if os.environ.get("KR_SHELL_PREFIX"):
        return os.environ["KR_SHELL_PREFIX"]
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Caches/kalareach/shells")
    return os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "kalareach/shells")


def pcre2_version(header):
    major = re.search(r"#define PCRE2_MAJOR\s+(\d+)", header)
    minor = re.search(r"#define PCRE2_MINOR\s+(\d+)", header)
    if not (major and minor):
        raise SourceError("the PCRE2 header names no version")
    return "%s.%s" % (major.group(1), minor.group(1))


def run_facts(args):
    """Writes fish's Cargo.lock out of the pinned archive and the version of the PCRE2 fish
    builds with, after the sources have been placed by scripts/place-shell-sources.sh --fish."""
    prefix = os.path.join(args.prefix or default_prefix(), "sources")
    with open(os.path.join(args.root, "shells/fish/manifest.json")) as handle:
        manifest = json.load(handle)
    upstream = manifest["upstream"]
    archive = os.path.join(prefix, upstream["archive"])
    with open(archive, "rb") as handle:
        data = handle.read()
    if hashlib.sha256(data).hexdigest() != upstream["sha256"]:
        raise SourceError("%s is not the archive the manifest pins" % archive)
    os.makedirs(args.out, exist_ok=True)
    wanted = "%s/Cargo.lock" % upstream["directory"]
    with tarfile.open(archive) as tar:
        member = tar.getmember(wanted)
        if not member.isfile():
            raise SourceError("%s in the archive is not a plain file" % wanted)
        lock = tar.extractfile(member).read()
    with open(os.path.join(args.out, "Cargo.lock"), "wb") as handle:
        handle.write(lock)
    repository = next(entry for entry in manifest["cargo"]["git"] if entry["name"] == "rust-pcre2")
    bundle = os.path.join(prefix, "rust-pcre2-%s.bundle" % repository["revision"][:12])
    with tempfile.TemporaryDirectory() as scratch:
        subprocess.run(["git", "clone", "--quiet", bundle, scratch + "/pcre2"], check=True)
        header = subprocess.run(
            ["git", "-C", scratch + "/pcre2", "show", "%s:pcre2-sys/upstream/include/pcre2.h" % repository["revision"]],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    version = pcre2_version(header)
    with open(os.path.join(args.out, "facts.json"), "w") as handle:
        json.dump({"fish": upstream["version"], "pcre2": version}, handle)
    print("check-shell-advisories: fish %s links PCRE2 %s; its lock is in %s" % (upstream["version"], version, args.out))
    return 0


# ---- the self-test --------------------------------------------------------------------------------

FIXTURES = os.path.join(ROOT, "fixtures", "shells", "advisories")


def fixture(name):
    with open(os.path.join(FIXTURES, name), "rb") as handle:
        return handle.read()


def routes():
    """What the public sources answered when the fixtures were recorded, by path."""
    table = {}
    for repository, name in (
        ("fish-shell/fish-shell", "fish"),
        ("PowerShell/PowerShell", "powershell"),
        ("PowerShell/PSReadLine", "psreadline"),
        ("PCRE2Project/pcre2", "pcre2"),
    ):
        table["/repos/%s/security-advisories" % repository] = fixture("github-%s-security-advisories.json" % name)
    table["/repos/PowerShell/Announcements/issues"] = fixture("github-announcements-security-issues.json")
    table["/repos/fish-shell/fish-shell/releases"] = fixture("github-fish-releases.json")
    table["/repos/PowerShell/PowerShell/releases"] = fixture("github-powershell-releases.json")
    table["/repos/zsh-users/zsh/tags"] = fixture("github-zsh-tags.json")
    table["/gnu/bash/"] = fixture("gnu-bash-listing.html")
    table["/gnu/bash/bash-5.2-patches/"] = fixture("gnu-bash-5.2-patches.html")
    return table


class Server:
    def __init__(self, table):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                page = urllib.parse.parse_qs(parsed.query).get("page", ["1"])[0]
                outer.requests.append(self.path)
                answer = outer.table.get(parsed.path)
                if answer is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                if page != "1":
                    answer = b"[]"
                self.send_response(200)
                self.end_headers()
                self.wfile.write(answer)

            def log_message(self, *_):
                pass

        self.table, self.requests = table, []
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def __exit__(self, *_):
        self.httpd.shutdown()
        self.httpd.server_close()


def run_self_test():
    global RETRY_DELAY
    RETRY_DELAY = 0.0
    with open(os.path.join(ROOT, REGISTER)) as handle:
        register = handle.read()
    audit = os.path.join(FIXTURES, "cargo-audit-fish-4.9.3.json")
    results = []

    def expect(name, condition, detail=""):
        results.append(name)
        if not condition:
            print("check-shell-advisories self-test: FAILED %s %s" % (name, detail), file=sys.stderr)
            sys.exit(1)

    with tempfile.TemporaryDirectory() as scratch:
        with open(os.path.join(scratch, "facts.json"), "w") as handle:
            json.dump({"fish": "4.9.3", "pcre2": "10.43"}, handle)

        def attempt(table, now="2026-10-24", text=None, report=audit):
            with Server(table) as base:
                args = argparse.Namespace(
                    root=ROOT, facts=scratch, audit=report, now=now,
                    github_api=base, gnu_bash=base + "/gnu/bash",
                )
                try:
                    return check(args, text if text is not None else register)
                except SourceError as error:
                    return error

        def without(*needles):
            kept = []
            for line in register.splitlines(keepends=True):
                if line.startswith("| 20") and any(needle in line for needle in needles):
                    continue
                kept.append(line)
            return "".join(kept)

        def says(outcome, *words):
            if isinstance(outcome, SourceError):
                return all(word in str(outcome) for word in words)
            _, problems, _ = outcome
            return any(all(word in problem for word in words) for problem in problems)

        # The figures the check reads.
        expect("one working day", figure_within("triaged within one working day of it", "working day") == 1)
        expect("fourteen days", figure_within("published within fourteen days of that", "days") == 14)
        expect(
            "a range",
            in_range(">= 10.32, <= 10.47", "10.43")
            and not in_range("<= 10.47", "10.48")
            and not in_range("3.1.0-3.3.1", "4.9.3")
            and in_range("3.1.0-3.3.1", "3.2"),
        )

        # The control: the committed register covers every change the recorded sources hold.
        outcome = attempt(routes())
        expect("the control reads", not isinstance(outcome, SourceError), str(outcome))
        findings, problems, waiting = outcome
        expect("the control passes", not problems, "; ".join(problems))
        needing = [item["id"] for item in findings if item["needs_row"]]
        for identifier in (
            "GHSA-r9hj-j2rw-4q3m", "RUSTSEC-2026-0204", "RUSTSEC-2026-0253", "v7.6.7", "zsh-5.9.2", "bash-5.3",
        ):
            expect("the control reads " + identifier, identifier in needing, str(needing))

        # Each mutation takes away a row the recorded data needs, and the check names the change.
        for needle, name in (
            ("GHSA-r9hj-j2rw-4q3m", "PCRE2 JIT stack row"),
            ("RUSTSEC-2026-0253", "RustSec row"),
            ("v7.6.7", "PowerShell release row"),
            ("issues/101", "Announcements row"),
            ("zsh-5.9.2", "zsh tag row"),
            ("bash-5.3", "bash release row"),
        ):
            outcome = attempt(routes(), text=without(needle))
            expect("without the " + name, says(outcome, "no triage row"), str(outcome))

        # A row that is still scheduled after its target.
        lines = []
        for line in register.splitlines(keepends=True):
            if "RUSTSEC-2026-0204" in line and line.startswith("| 20"):
                cells = line.rstrip("\n").strip("|").split("|")
                cells[4], cells[5] = " 2026-10-01 ", " scheduled "
                line = "|" + "|".join(cells) + "|\n"
            lines.append(line)
        outcome = attempt(routes(), text="".join(lines))
        expect("a scheduled row past its target", says(outcome, "RUSTSEC-2026-0204", "target"), str(outcome))

        # A range that changed after the row was written is not covered by the old row.
        table = routes()
        advisories = json.loads(table["/repos/PCRE2Project/pcre2/security-advisories"])
        for advisory in advisories:
            if advisory["ghsa_id"] == "GHSA-r9hj-j2rw-4q3m":
                advisory["vulnerabilities"][0]["vulnerable_version_range"] = "<= 10.49"
        table["/repos/PCRE2Project/pcre2/security-advisories"] = json.dumps(advisories).encode()
        outcome = attempt(table)
        expect("a changed range", says(outcome, "GHSA-r9hj-j2rw-4q3m", "<= 10.49"), str(outcome))

        # The allowance: a change published a working day ago waits, two days ago it fails.
        text = without("GHSA-r9hj-j2rw-4q3m")
        outcome = attempt(routes(), now="2026-09-29", text=text)
        expect("inside the allowance", not isinstance(outcome, SourceError) and not says(outcome, "GHSA-r9hj"), str(outcome))
        outcome = attempt(routes(), now="2026-09-30", text=text)
        expect("past the allowance", says(outcome, "GHSA-r9hj-j2rw-4q3m"), str(outcome))

        # A source that cannot be read fails, and names itself.
        table = routes()
        del table["/repos/PowerShell/PowerShell/releases"]
        outcome = attempt(table)
        expect("a missing source", isinstance(outcome, SourceError) and "PowerShell/PowerShell/releases" in str(outcome), str(outcome))
        table = routes()
        table["/repos/zsh-users/zsh/tags"] = b"{not json"
        outcome = attempt(table)
        expect("a malformed source", isinstance(outcome, SourceError) and "zsh-users/zsh/tags" in str(outcome), str(outcome))
        table = routes()
        table["/repos/PCRE2Project/pcre2/security-advisories"] = b"[]"
        outcome = attempt(table)
        expect("an empty list of advisories", isinstance(outcome, SourceError) and "PCRE2Project/pcre2" in str(outcome), str(outcome))
        table = routes()
        table["/repos/PowerShell/PSReadLine/security-advisories"] = b"[]"
        outcome = attempt(table)
        expect("a repository with no advisory", not isinstance(outcome, SourceError), str(outcome))
        table = routes()
        table["/repos/fish-shell/fish-shell/releases"] = b"[]"
        outcome = attempt(table)
        expect("an empty list of releases", isinstance(outcome, SourceError) and "fish-shell/fish-shell/releases" in str(outcome), str(outcome))
        outcome = attempt(routes(), report=os.path.join(scratch, "no-such-report.json"))
        expect("a missing audit report", isinstance(outcome, SourceError) and "cargo-audit report" in str(outcome), str(outcome))

        # Pagination: the next page is asked for when a page was full, and not otherwise.
        full = json.dumps([{"name": "zsh-0.%d" % number} for number in range(100)]).encode()
        server = Server({"/full": full, "/short": b'[{"name": "zsh-0.1"}]'})
        with server as base:
            expect("a full page", len(fetch_pages(base + "/full", None)) == 100)
            expect("a short page", len(fetch_pages(base + "/short", None)) == 1)
        asked = [path for path in server.requests if path.startswith("/full")]
        expect("the next page is asked for", len(asked) == 2 and "page=2" in asked[1], str(asked))
        expect("a short page ends the list", len([p for p in server.requests if p.startswith("/short")]) == 1)
    print("check-shell-advisories self-test: %d checks passed" % len(results))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    checking = commands.add_parser("check")
    checking.add_argument("--root", default=ROOT)
    checking.add_argument("--facts", required=True)
    checking.add_argument("--audit", required=True)
    checking.add_argument("--now")
    checking.add_argument("--github-api", default=GITHUB)
    checking.add_argument("--gnu-bash", default=GNU_BASH)
    reading = commands.add_parser("facts")
    reading.add_argument("--root", default=ROOT)
    reading.add_argument("--out", required=True)
    reading.add_argument("--prefix")
    commands.add_parser("self-test")
    args = parser.parse_args()
    try:
        if args.command == "check":
            return run_check(args)
        if args.command == "facts":
            return run_facts(args)
        return run_self_test()
    except SourceError as error:
        print("check-shell-advisories: FAILED: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
