#!/usr/bin/env python3
"""Shows that the Android driver reads a service's address in the form the page exposes it in.

    python3 -I scripts/lib/pairing-android-check.py

The pairing screen draws an address as it is written and hides that from the accessibility tree,
which holds the address as words in its place (`ServiceAddress` in the companion's page): the
screen of the phone names "127 dot 0 dot 0 dot 1", never "127.0.0.1". The driver's waits for an
address therefore ask for the words, by the page's own rule.

The page's rule is `spokenAddress`, and its own cases hold it to a table of written addresses and
what is said for each (`apps/companion/test/service-address.test.ts`): a name, a name with a port, an
IPv4 address, and an IPv6 literal, each with or without a port. This holds the driver's rule to the
same table, read from that file, so that neither can change without the other.
"""

import importlib.util
import re
import sys
import unittest
from pathlib import Path

# Loading the driver by path must leave no compiled copy beside it.
sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

_spec = importlib.util.spec_from_file_location("pairing_android", HERE / "pairing-android.py")
pairing = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pairing)


def table_in(source: str) -> dict[str, str]:
    """The addresses the page's cases say as words, as the page's test file writes them.

    A row is a line that opens with `[` at the table's indent. Every such row must be read as a pair
    of single-quoted strings, so a row written another way (a comment inside it, double quotes, a
    trailing comma) stops the run and is never dropped."""
    table = source[source.index("const SAID") : source.index("describe(")]
    pairs = re.findall(r"\[\s*'([^']*)',\s*'([^']*)'\s*\]", table)
    rows = len(re.findall(r"^  \[", table, flags=re.MULTILINE))
    if rows != len(pairs):
        raise SystemExit(f"the page's table has {rows} rows and {len(pairs)} were read as pairs of strings")
    return dict(pairs)


def pages_table() -> dict[str, str]:
    return table_in((ROOT / "apps" / "companion" / "test" / "service-address.test.ts").read_text(encoding="utf-8"))


class SpokenAddress(unittest.TestCase):
    def test_every_address_the_page_says_is_said_as_it_says_it(self):
        table = pages_table()
        # A table that was read as empty would pass for nothing: the four kinds are in it.
        for written in ("reach.kala.to", "sync.example.org:8443", "192.0.2.1", "[2001:db8::1]:8443", "::1"):
            self.assertIn(written, table)
        for written, said in table.items():
            with self.subTest(written=written):
                self.assertEqual(pairing.spoken_address(written), said)

    def test_the_addresses_the_release_leg_waits_for_are_the_words_the_phone_shows(self):
        # The pairing screen of the release build, as `uiautomator` dumped it: "Codes go through",
        # then the address as words, then "Change", and no node that holds the address as written.
        self.assertEqual(pairing.spoken_address("127.0.0.1"), "127 dot 0 dot 0 dot 1")
        self.assertEqual(pairing.spoken_address(pairing.DEPLOYED_HOST), "reach dot kala dot to")


if __name__ == "__main__":
    unittest.main()
