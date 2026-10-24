#!/usr/bin/env python3
"""Holds the register of triaged upstream changes to what the shells' upstreams publish.

The register (docs/shell-integration/upstream.md) says which sources each shell package watches
and records what was made of every security-relevant change. Nothing read those sources until
this script. It reads them and fails on a change the register has no row for:

  * the security advisories of the fish, PowerShell, PSReadLine and PCRE2 repositories (fish
    links PCRE2, so a PCRE2 advisory is a fish advisory);
  * the issues of PowerShell/Announcements that are security advisories, which is where Microsoft
    publishes the advisories that reach PowerShell, the .NET ones included (the Security label,
    or a title that says so or names a CVE on an issue a member of the organisation opened);
  * the stable releases of fish and PowerShell, the tags of zsh and the releases and patches of
    bash that are newer than what the packages pin. Neither zsh nor bash publishes a machine
    readable advisory feed, so a new release or patch is the only signal either gives;
  * the RustSec advisories against the crates in fish's Cargo.lock, read from a cargo-audit
    report.

A change needs a row when it was first published on or after the day the register started, or
when its affected range includes what the package pins (a RustSec advisory against the lock needs
one whatever its date). The newest row that names the package and the change by its identifier
covers it, when its status is one the register defines, it is not `scheduled` past its target, it
quotes every affected range the source gives as the source gives it, and it is dated on or after
the day the source last revised the change, so that a revision is a new fact and not an old row.
A change with no row passes for one working day after it was published or last revised, which is
the time the register allows for triage, and fails after it. A RustSec advisory has no such
allowance, because the report carries no date on which it reached the database.

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


def fetch(url, token=None, missing_ok=False):
    """The body at url and the Link header of the answer, after up to three tries. The token goes
    to api.github.com only. A page that is not there is None where the caller says it may be
    missing."""
    headers = {"User-Agent": "kalareach-shell-advisories", "Accept": "application/vnd.github+json"}
    if token and urllib.parse.urlparse(url).hostname == "api.github.com":
        headers["Authorization"] = "Bearer " + token
    last = None
    for attempt in range(RETRIES):
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read(), response.headers.get("Link") or ""
        except urllib.error.HTTPError as error:
            if error.code == 404 and missing_ok:
                return None, ""
            last = error
        except (urllib.error.URLError, OSError) as error:
            last = error
        time.sleep(RETRY_DELAY * (attempt + 1))
    raise SourceError("%s: %s" % (url, last))


def fetch_pages(url, token, must_hold_something=True):
    """Every item of a paginated GitHub list, as one list. GitHub says where the next page is in
    the Link header, and some lists (the security advisories) take a cursor and ignore a page
    number, so the header is followed and a page number is never guessed."""
    items = []
    separator = "&" if "?" in url else "?"
    next_url = "%s%sper_page=100" % (url, separator)
    for _ in range(30):
        body, link = fetch(next_url, token)
        try:
            chunk = json.loads(body)
        except ValueError as error:
            raise SourceError("%s: the answer is not JSON (%s)" % (next_url, error))
        if not isinstance(chunk, list):
            raise SourceError("%s: the answer is not a list" % next_url)
        for item in chunk:
            if not isinstance(item, dict):
                raise SourceError("%s: an item of the list is not an object" % next_url)
        items.extend(chunk)
        following = re.findall(r'<([^>]+)>\s*;\s*rel="next"', link)
        if not following:
            break
        next_url = following[0]
    else:
        raise SourceError("%s: the list has more than 30 pages" % url)
    if must_hold_something and not items:
        raise SourceError("%s: the answer holds nothing" % url)
    return items


def day(text):
    return datetime.date.fromisoformat(text[:10]) if text else None


def numbers(text):
    return tuple(int(part) for part in re.findall(r"\d+", text))


def in_range(range_text, version):
    """Whether a version is inside a range such as '>= 10.32, <= 10.47' or '3.1.0-3.3.1'. A range
    that cannot be read in full counts as inside it, because the safe mistake is a row too many."""
    wanted = numbers(version)
    span = re.match(r"\s*([0-9][0-9.]*)\s*-\s*([0-9][0-9.]*)\s*$", range_text)
    if span:
        return numbers(span.group(1)) <= wanted <= numbers(span.group(2))
    tests = []
    for comparator in range_text.split(","):
        match = re.match(r"\s*(<=|>=|<|>|=)?\s*([0-9][0-9.]*)\s*$", comparator)
        if not match:
            return True
        tests.append((match.group(1) or "=", numbers(match.group(2))))
    for operator, bound in tests:
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


def finding(source, package, identifier, aliases, published, updated=None, ranges=(), needs_row=True,
            allowance=True):
    """One change an upstream published. `published` and `updated` are the days it first appeared
    and was last revised, where the source says; `ranges` are the affected ranges the source gives,
    as it gives them."""
    return {
        "source": source,
        "package": package,
        "id": identifier,
        "aliases": [identifier] + [alias for alias in aliases if alias],
        "published": published,
        "updated": updated,
        "ranges": list(ranges),
        "needs_row": needs_row,
        "allowance": allowance,
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
        published, updated = day(item.get("published_at")), day(item.get("updated_at"))
        texts = [
            text
            for vulnerability in item.get("vulnerabilities") or []
            for text in [vulnerability.get("vulnerable_version_range")]
            if text
        ]
        affects = bool(pinned) and any(in_range(text, pinned) for text in texts)
        recent = published is not None and published >= STARTED
        found.append(
            finding(
                source,
                package,
                item["ghsa_id"],
                [item.get("cve_id")],
                published,
                updated,
                texts,
                needs_row=recent or affects,
            )
        )
    return found


MONTHS = {name: number for number, name in enumerate(
    "January February March April May June July August September October November December".split(), 1)}


def revised_day(body, created):
    """The day an Announcements advisory was last revised, from the revision list and the
    "Last Updated" line Microsoft writes into its body. A comment on the issue moves `updated_at`
    and revises nothing, so that field is not used. An issue that carries neither line was never
    revised after it was opened."""
    days = []
    for match in re.finditer(r"V\d+\.\d+ \((\w+) (\d{1,2}), (\d{4})\)", body or ""):
        month = MONTHS.get(match.group(1))
        if month:
            days.append(datetime.date(int(match.group(3)), month, int(match.group(2))))
    for match in re.finditer(r"Last Updated\s*(\d{4}-\d{2}-\d{2})", body or ""):
        days.append(datetime.date.fromisoformat(match.group(1)))
    return max(days + [created]) if created else (max(days) if days else None)


def announcements(api, token):
    """The advisories Microsoft publishes for PowerShell, the .NET ones that reach it included.
    An issue is an advisory when it carries the Security label, or when its title says it is one or
    names a CVE and a member of the organisation opened it: not every advisory is labelled, and
    anyone can open an issue. Pull requests are not issues."""
    url = "%s/repos/PowerShell/Announcements/issues?state=all" % api
    found = []
    for item in fetch_pages(url, token):
        title = item.get("title") or ""
        cves = re.findall(r"CVE-\d{4}-\d{4,}", title)
        labelled = "Security" in [
            label if isinstance(label, str) else (label or {}).get("name") for label in item.get("labels") or []
        ]
        titled = bool(cves or re.search(r"Security Advisory", title, re.I)) and item.get(
            "author_association"
        ) in ("MEMBER", "OWNER", "COLLABORATOR")
        if "pull_request" in item or not (labelled or titled):
            continue
        identifier = cves[0] if cves else "PowerShell/Announcements#%d" % item["number"]
        created = day(item.get("created_at"))
        revised = revised_day(item.get("body"), created)
        recent = (created is not None and created >= STARTED) or (revised is not None and revised >= STARTED)
        found.append(
            finding(
                "PowerShell/Announcements",
                "psreadline",
                identifier,
                ["github.com/PowerShell/Announcements/issues/%d" % item["number"]],
                created,
                revised,
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
            commit, _ = fetch("%s/repos/zsh-users/zsh/commits/%s" % (api, item["name"]), token)
            try:
                published = day(json.loads(commit)["commit"]["committer"]["date"])
            except (ValueError, KeyError, TypeError) as error:
                raise SourceError("the commit of %s cannot be read (%s)" % (item["name"], error))
            found.append(finding("zsh tags", "zsh", item["name"], [], published))
    return found


def bash_listing(ftp, path, pattern, missing_ok=False):
    """The entries of a directory listing on ftp.gnu.org that match `pattern`, with the day each
    was put there. The pattern has one group, the entry's name."""
    body, _ = fetch("%s/%s" % (ftp, path), None, missing_ok=missing_ok)
    if body is None:
        return []
    listing = body.decode("utf-8", "replace")
    entries = []
    for line in listing.splitlines():
        match = re.search(r'href="(%s)"[^\n]*?(\d{4}-\d{2}-\d{2})' % pattern, line)
        if match:
            entries.append((match.group(1), day(match.group(2))))
    return entries


PATCH_GRACE_DAYS = 60


def bash_releases(ftp, pinned, now):
    """Releases of a series newer than the pinned one, the newest patch of each such series (bash
    fixes land in the newest series, and a patch to it that fixes a defect the pinned series also
    has gets no other announcement), and the patches of the pinned series above the pinned patch.
    The pinned series' patch directory must be there. A newer series gets its first patches within
    weeks of its release, so its directory may be missing or empty for sixty days after the release
    and not after: a directory that stays missing is a source that failed."""
    found = []
    pin = numbers(pinned)
    releases = bash_listing(ftp, "", r"bash-(?:\d+\.\d+(?:\.\d+)?)\.tar\.gz")
    if not releases:
        raise SourceError("%s/: the listing holds no release" % ftp)
    series = {}
    for name, published in releases:
        version = numbers(name.replace(".tar.gz", ""))
        if version > pin:
            found.append(finding("bash releases", "bash", name.replace(".tar.gz", ""), [], published))
        if version[:2] > pin[:2]:
            first = series.get(version[:2])
            series[version[:2]] = min(first, published) if first and published else (first or published)
    pinned_patches = "bash-%d.%d-patches/" % pin[:2]
    patches = bash_listing(ftp, pinned_patches, r"bash%d%d-\d+" % pin[:2])
    if not patches:
        raise SourceError("%s/%s: the listing holds no patch" % (ftp, pinned_patches))
    for name, published in patches:
        if int(name.rsplit("-", 1)[1]) > pin[2]:
            found.append(finding("bash patches", "bash", name, [], published))
    for (major, minor), released in sorted(series.items()):
        directory = "bash-%d.%d-patches/" % (major, minor)
        newer = bash_listing(ftp, directory, r"bash%d%d-\d+" % (major, minor), True)
        if newer:
            name, published = max(newer, key=lambda entry: int(entry[0].rsplit("-", 1)[1]))
            found.append(finding("bash patches", "bash", name, [], published))
        elif released is None or (now - released).days > PATCH_GRACE_DAYS:
            raise SourceError(
                "%s/%s: the listing of a series released %s holds no patch" % (ftp, directory, released)
            )
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
        finding(
            "RustSec, fish's Cargo.lock", "fish", advisory["id"], [], day(advisory.get("date")), allowance=False
        )
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
    for index, cells in enumerate(rows):
        if len(cells) != 6:
            raise SourceError("a triage row has %d cells: %s" % (len(cells), cells))
        try:
            written = datetime.date.fromisoformat(cells[0])
        except ValueError:
            raise SourceError("a triage row has no date: %s" % cells)
        parsed.append(
            {
                "index": index,
                "written": written,
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


def date_after(text, label):
    """The day written `YYYY-MM-DD` right after `label` in `text`, or None."""
    match = re.search(re.escape(label) + r"(\d{4}-\d{2}-\d{2})", text)
    return datetime.date.fromisoformat(match.group(1)) if match else None


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
    allowance. The newest row that names a change is the assessment that stands; the rows before
    it are the record of what was thought earlier."""
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
            dates = [value for value in (item["published"], item["updated"]) if value is not None]
            arrived = max(dates) if dates else None
            if item["allowance"] and arrived is not None and working_days_between(arrived, now) <= triage_days:
                waiting.append("%s arrived %s and is inside its triage allowance" % (label, arrived))
            else:
                problems.append("%s has no triage row for %s" % (label, item["package"]))
            continue
        row = max(covering, key=lambda candidate: (candidate["written"], candidate["index"]))
        if row["status"] not in STATUSES:
            problems.append("%s: its row says %r, which is not a status the register defines" % (label, row["status"]))
        try:
            target = datetime.date.fromisoformat(row["target"])
        except ValueError:
            problems.append("%s: its row has no target date (%r)" % (label, row["target"]))
            continue
        if row["status"] == "scheduled" and target < now:
            problems.append("%s: its row is still scheduled and its target %s has passed" % (label, target))
        for text in item["ranges"]:
            if text not in row["change"]:
                problems.append(
                    "%s: the source gives the affected range %r, which its newest row does not quote"
                    % (label, text)
                )
        if item["updated"] is not None and item["updated"] > row["written"]:
            arrived = item["updated"]
            if item["allowance"] and working_days_between(arrived, now) <= triage_days:
                waiting.append("%s was revised %s and is inside its triage allowance" % (label, arrived))
            else:
                problems.append(
                    "%s: the source was revised %s, after its newest row of %s" % (label, arrived, row["date"])
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


def collect(root, api, ftp, token, facts, audit, now):
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
    found += bash_releases(ftp, pins["bash"], now)
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
    findings = collect(args.root, args.github_api, args.gnu_bash, token, args.facts, args.audit, now)
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
    table["/repos/PowerShell/Announcements/issues"] = fixture("github-announcements-issues.json")
    table["/repos/fish-shell/fish-shell/releases"] = fixture("github-fish-releases.json")
    table["/repos/PowerShell/PowerShell/releases"] = fixture("github-powershell-releases.json")
    table["/repos/zsh-users/zsh/tags"] = fixture("github-zsh-tags.json")
    for tag in ("zsh-5.9.1", "zsh-5.9.2"):
        table["/repos/zsh-users/zsh/commits/" + tag] = fixture("github-zsh-commit-%s.json" % tag)
    table["/gnu/bash/"] = fixture("gnu-bash-listing.html")
    table["/gnu/bash/bash-5.2-patches/"] = fixture("gnu-bash-5.2-patches.html")
    table["/gnu/bash/bash-5.3-patches/"] = fixture("gnu-bash-5.3-patches.html")
    return table


class Server:
    """A local stand-in for the public sources. A route holds the answer, or a list of answers
    that GitHub-style Link headers chain together, the first asked for with no cursor."""

    def __init__(self, table):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                cursor = urllib.parse.parse_qs(parsed.query).get("after", ["0"])[0]
                outer.requests.append(self.path)
                answer = outer.table.get(parsed.path)
                if answer is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                link = None
                if isinstance(answer, list):
                    position = int(cursor)
                    if position + 1 < len(answer):
                        link = '<http://127.0.0.1:%d%s?per_page=100&after=%d>; rel="next"' % (
                            outer.httpd.server_address[1], parsed.path, position + 1,
                        )
                    answer = answer[position]
                self.send_response(200)
                if link:
                    self.send_header("Link", link)
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
            print("check-shell-advisories self-test: FAILED %s %s" % (name, str(detail)[:600]), file=sys.stderr)
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

        def with_row(row):
            marker = "<!-- /kr:triage -->"
            return register.replace(marker, row + "\n" + marker)

        def says(outcome, *words):
            if isinstance(outcome, SourceError):
                return all(word in str(outcome) for word in words)
            _, problems, _ = outcome
            return any(all(word in problem for word in words) for problem in problems)

        def edited(table, path, change):
            table = dict(table)
            table[path] = json.dumps(change(json.loads(table[path]))).encode()
            return table

        issues = "/repos/PowerShell/Announcements/issues"
        pcre2 = "/repos/PCRE2Project/pcre2/security-advisories"

        # The figures and the ranges the check reads.
        expect("one working day", figure_within("triaged within one working day of it", "working day") == 1)
        expect("fourteen days", figure_within("published within fourteen days of that", "days") == 14)
        expect(
            "ranges",
            in_range(">= 10.32, <= 10.47", "10.43")
            and not in_range("<= 10.47", "10.48")
            and not in_range("3.1.0-3.3.1", "4.9.3")
            and in_range("3.1.0-3.3.1", "3.2")
            and in_range(">= 10.44, < 10.48 || <= 10.43", "10.43"),
        )
        expect("the start day is the register's", date_after(register, "published from ") == STARTED)

        # The control: the committed register covers every change the recorded sources hold.
        outcome = attempt(routes())
        expect("the control reads", not isinstance(outcome, SourceError), str(outcome))
        findings, problems, waiting = outcome
        expect("the control passes", not problems, "; ".join(problems))
        needing = [item["id"] for item in findings if item["needs_row"]]
        for identifier in (
            "GHSA-r9hj-j2rw-4q3m", "RUSTSEC-2026-0204", "RUSTSEC-2026-0253", "v7.6.8", "zsh-5.9.2", "bash-5.3",
            "bash53-020",
        ):
            expect("the control reads " + identifier, identifier in needing, str(needing))
        # The releases at the module's bound are the ones it accepts, and only a release above one needs a row.
        expect("a release at the bound needs no row", not {"v7.4.21", "v7.5.12", "v7.6.7"} & set(needing), str(needing))

        # Each mutation takes away a row the recorded data needs, and the check names the change. It is read
        # on a day after every triage allowance has passed, since v7.6.8 (2026-10-22) is still inside its own on the day the recorded sources were taken.
        for needle, name in (
            ("GHSA-r9hj-j2rw-4q3m", "PCRE2 JIT stack row"),
            ("RUSTSEC-2026-0253", "RustSec row"),
            ("v7.6.8", "PowerShell release row"),
            ("zsh-5.9.2", "zsh tag row"),
            ("bash-5.3", "bash release row"),
        ):
            outcome = attempt(routes(), now="2026-11-02", text=without(needle))
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

        # An advisory Microsoft published without the Security label still needs its row.
        def unlabelled(items):
            return items + [{
                "number": 9001, "title": "Microsoft Security Advisory CVE-2026-99999: PowerShell Remote Code Execution",
                "created_at": "2026-10-20T10:00:00Z", "updated_at": "2026-10-20T10:00:00Z", "state": "open", "labels": [],
                "author_association": "MEMBER", "body": "",
            }]
        outcome = attempt(edited(routes(), issues, unlabelled))
        expect("an advisory with no label", says(outcome, "CVE-2026-99999", "no triage row"), str(outcome))
        def chatter(items):
            return items + [{
                "number": 9002, "title": "PowerShell 7.4 end of support", "created_at": "2026-10-20T10:00:00Z",
                "updated_at": "2026-10-20T10:00:00Z", "state": "open", "labels": [],
            }]
        outcome = attempt(edited(routes(), issues, chatter))
        expect("an announcement that is no advisory", not isinstance(outcome, SourceError) and not says(outcome, "9002"), str(outcome))

        # A revision Microsoft dates in the advisory after the newest row is a new fact, and a newer
        # row answers it. A comment moves `updated_at` and revises nothing.
        def revised(items):
            for item in items:
                if item["number"] == 101:
                    item["body"] += "V1.1 (October 30, 2026): Affected versions revised.\n"
                    item["updated_at"] = "2026-10-30T09:00:00Z"
            return items
        def commented(items):
            for item in items:
                if item["number"] == 101:
                    item["updated_at"] = "2026-10-30T09:00:00Z"
            return items
        outcome = attempt(edited(routes(), issues, revised), now="2026-11-10")
        expect("a revised advisory", says(outcome, "CVE-2026-69806", "revised 2026-10-30"), str(outcome))
        outcome = attempt(edited(routes(), issues, commented), now="2026-11-10")
        expect("a comment on an advisory", not isinstance(outcome, SourceError) and not says(outcome, "CVE-2026-69806"), str(outcome))
        def spam(items):
            return items + [{
                "number": 9003, "title": "Advisory: CVE-2026-77777 PowerShell Remote Code Execution", "labels": [],
                "created_at": "2026-10-20T10:00:00Z", "updated_at": "2026-10-20T10:00:00Z", "state": "closed",
                "author_association": "NONE", "body": "",
            }]
        outcome = attempt(edited(routes(), issues, spam), now="2026-11-10")
        expect("an advisory-shaped issue from outside the organisation", not isinstance(outcome, SourceError) and not says(outcome, "CVE-2026-77777"), str(outcome))
        def labelled_only(items):
            return items + [{
                "number": 9004, "title": "OpenSSL 4.0 Security Release", "labels": ["Security", "PowerShell"],
                "created_at": "2026-10-20T10:00:00Z", "updated_at": "2026-10-20T10:00:00Z", "state": "open",
                "author_association": "MEMBER", "body": "",
            }]
        outcome = attempt(edited(routes(), issues, labelled_only), now="2026-11-10")
        expect("a labelled security issue with no CVE", says(outcome, "Announcements#9004", "no triage row"), str(outcome))
        answer = with_row(
            "| 2026-11-02 | CVE-2026-69806, revised again at github.com/PowerShell/Announcements/issues/101; released 2026-09-11 "
            "| psreadline | The revision was read and the bound still covers it. | 2026-09-25 | not-affected |"
        )
        outcome = attempt(edited(routes(), issues, revised), now="2026-11-10", text=answer)
        expect("a revision answered by a newer row", not isinstance(outcome, SourceError) and not says(outcome, "CVE-2026-69806"), str(outcome))
        outcome = attempt(edited(routes(), issues, revised), now="2026-10-30")
        expect("a revision inside its allowance", not isinstance(outcome, SourceError) and not says(outcome, "CVE-2026-69806"), str(outcome))

        # A range that changed after the row was written is not covered by the old row, and a newer
        # row that quotes the new range covers it. A range is read for an advisory with no pin too.
        def widened(items):
            for item in items:
                if item["ghsa_id"] == "GHSA-r9hj-j2rw-4q3m":
                    item["vulnerabilities"][0]["vulnerable_version_range"] = "<= 10.49"
            return items
        outcome = attempt(edited(routes(), pcre2, widened))
        expect("a changed range", says(outcome, "GHSA-r9hj-j2rw-4q3m", "<= 10.49"), str(outcome))
        row = (
            "| 2026-10-25 | PCRE2 CVE-2026-103111 (GHSA-r9hj-j2rw-4q3m), affected `<= 10.49`, fixed in 10.50; released 2026-09-28 "
            "| fish | The wider range was read and the bundled PCRE2 is built without JIT. | 2026-10-12 | not-affected |"
        )
        outcome = attempt(edited(routes(), pcre2, widened), text=with_row(row), now="2026-10-26")
        expect("a newer row for the new range", not isinstance(outcome, SourceError) and not says(outcome, "GHSA-r9hj"), str(outcome))
        def powershell_advisory(items):
            return items + [{
                "ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": "CVE-2026-88888", "published_at": "2026-10-20T10:00:00Z",
                "updated_at": "2026-10-20T10:00:00Z", "severity": "high", "summary": "x",
                "vulnerabilities": [{"package": {"name": "PowerShell"}, "vulnerable_version_range": "< 7.6.8", "patched_versions": "7.6.8"}],
            }]
        outcome = attempt(edited(routes(), "/repos/PowerShell/PowerShell/security-advisories", powershell_advisory))
        expect("a PowerShell advisory", says(outcome, "GHSA-aaaa-bbbb-cccc", "no triage row"), str(outcome))

        # The allowance: a change that arrived a working day ago waits, two working days ago it
        # fails. GHSA-r9hj was published on 2026-09-28 and last revised on Thursday 2026-10-01.
        text = without("GHSA-r9hj-j2rw-4q3m")
        outcome = attempt(routes(), now="2026-10-02", text=text)
        expect("inside the allowance", not isinstance(outcome, SourceError) and not says(outcome, "GHSA-r9hj"), str(outcome))
        outcome = attempt(routes(), now="2026-10-05", text=text)
        expect("past the allowance", says(outcome, "GHSA-r9hj-j2rw-4q3m"), str(outcome))
        # A zsh tag and a bash patch are dated by their sources, and a RustSec advisory has no allowance.
        outcome = attempt(routes(), now="2026-07-13", text=without("zsh-5.9.2"))
        expect("a zsh tag inside its allowance", not isinstance(outcome, SourceError) and not says(outcome, "zsh-5.9.2"), str(outcome))
        table = routes()
        table["/gnu/bash/bash-5.3-patches/"] = table["/gnu/bash/bash-5.3-patches/"] + (
            b'<tr><td><a href="bash53-021">bash53-021</a></td><td align="right">2026-10-23 10:00  </td></tr>\n'
        )
        outcome = attempt(table, now="2026-10-28")
        expect("a patch of the newer bash series", says(outcome, "bash53-021", "no triage row"), str(outcome))
        table = routes()
        del table["/gnu/bash/bash-5.3-patches/"]
        outcome = attempt(table)
        expect("a patch directory that went missing", isinstance(outcome, SourceError) and "bash-5.3-patches" in str(outcome), str(outcome))
        table = routes()
        table["/gnu/bash/bash-5.3-patches/"] = b"<html>no listing</html>"
        outcome = attempt(table)
        expect("a patch listing with nothing in it", isinstance(outcome, SourceError) and "bash-5.3-patches" in str(outcome), str(outcome))
        table = routes()
        del table["/gnu/bash/bash-5.2-patches/"]
        outcome = attempt(table)
        expect("the pinned series' patch directory missing", isinstance(outcome, SourceError) and "bash-5.2-patches" in str(outcome), str(outcome))
        table = routes()
        table["/gnu/bash/"] += b'<a href="bash-5.4.tar.gz">bash-5.4.tar.gz</a> 2026-10-20 10:00  11M\n'
        outcome = attempt(table, now="2026-10-24", text=with_row(
            "| 2026-10-24 | bash-5.4, the series after 5.3; released 2026-10-20 | bash | Read. | 2026-11-03 | not-affected |"))
        expect("a new series with no patch yet", not isinstance(outcome, SourceError) and not says(outcome, "bash-5.4"), str(outcome))
        outcome = attempt(table, now="2026-10-26")
        expect("a new patch inside its allowance", not isinstance(outcome, SourceError) and not says(outcome, "bash53-021"), str(outcome))
        with open(audit) as handle:
            report = json.load(handle)
        report["warnings"]["unsound"].append({
            "kind": "unsound", "package": {"name": "x", "version": "1.0.0"},
            "advisory": {"id": "RUSTSEC-2026-9999", "package": "x", "title": "t", "date": "2026-10-24"},
        })
        with open(os.path.join(scratch, "report.json"), "w") as handle:
            json.dump(report, handle)
        outcome = attempt(routes(), report=os.path.join(scratch, "report.json"))
        expect("a new RustSec advisory has no allowance", says(outcome, "RUSTSEC-2026-9999", "no triage row"), str(outcome))

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
        table[pcre2] = b"[]"
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
        table = routes()
        table["/repos/zsh-users/zsh/tags"] = b'["zsh-5.9.1"]'
        outcome = attempt(table)
        expect("an item that is no object", isinstance(outcome, SourceError) and "zsh-users/zsh/tags" in str(outcome), str(outcome))
        table = routes()
        table["/repos/zsh-users/zsh/tags"] = b'{"message": "rate limit"}'
        outcome = attempt(table)
        expect("an object where a list is expected", isinstance(outcome, SourceError) and "not a list" in str(outcome), str(outcome))
        outcome = attempt(routes(), report=os.path.join(scratch, "no-such-report.json"))
        expect("a missing audit report", isinstance(outcome, SourceError) and "cargo-audit report" in str(outcome), str(outcome))

        # Pagination follows the Link header and never guesses a page number.
        pages = [
            json.dumps([{"name": "zsh-0.%d" % number} for number in range(100)]).encode(),
            b'[{"name": "zsh-0.100"}]',
        ]
        server = Server({"/paged": pages, "/single": b'[{"name": "zsh-0.1"}]'})
        with server as base:
            expect("a list of two pages", len(fetch_pages(base + "/paged", None)) == 101)
            expect("a list of one page", len(fetch_pages(base + "/single", None)) == 1)
        asked = [path for path in server.requests if path.startswith("/paged")]
        expect("the next page is the one the header names", len(asked) == 2 and "after=1" in asked[1], str(asked))
        expect("a single page is asked for once", len([p for p in server.requests if p.startswith("/single")]) == 1)
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
