"""Applies one named mutation to the store's source, in place. Exits 2 when the text it replaces is not there once."""
import sys

WINDOWS = "crates/kr-ipc/src/install/windows.rs"
INSTALL = "crates/kr-ipc/src/install.rs"

FIRST_TAG_CHECK = """    if reparse_tag(&looked)? != Some(IO_REPARSE_TAG_MOUNT_POINT) {
        return Ok(Pointed::NotAJunction);
    }
"""

SECOND_TAG_CHECK = """    if reparse_tag(&directory)? != Some(IO_REPARSE_TAG_MOUNT_POINT) {
        return Ok(Pointed::NotAJunction);
    }
"""

CHANGE_OPEN = """    let directory = match open_to_change(link) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Pointed::NotAJunction),
        Err(error) => return Err(error),
    };
"""

VERDICT = """    Ok(if identity(&named)? == identity(&directory)? {
        Pointed::Done
    } else {
        Pointed::Moved
    })
"""

MUTANTS = {
    # The junction is never pointed in place: the rename replaces it, as before.
    "M1": [(WINDOWS, "pub(super) fn point_junction(link: &Path, target: &Path) -> io::Result<Pointed> {\n",
            "pub(super) fn point_junction(link: &Path, target: &Path) -> io::Result<Pointed> {\n    return Ok(Pointed::NotAJunction);\n")],
    # The object the change is made through is not checked to be a junction again.
    "M2": [(WINDOWS, SECOND_TAG_CHECK, "    let _ = reparse_tag(&directory)?;\n")],
    # The target is set through the name and not through the handle that was checked.
    "M3": [(WINDOWS, "    set_reparse_data(&directory, &data)?;\n    at(Moment::JunctionPointed, link);",
            "    set_junction(link, &data)?;\n    at(Moment::JunctionPointed, link);")],
    # The change is not flushed.
    "M4": [(WINDOWS, "    directory.sync_all()?;\n    let named", "    let named")],
    # The target is not set at all, and the switch says it was.
    "M5": [(WINDOWS, "    set_reparse_data(&directory, &data)?;\n    at(Moment::JunctionPointed, link);",
            "    let _ = (&directory, &data);\n    at(Moment::JunctionPointed, link);")],
    # Where there is no junction the switch says it is done and changes nothing.
    "M6": [(INSTALL, "            windows::Pointed::NotAJunction => {}\n",
            "            windows::Pointed::NotAJunction => return Ok(()),\n")],
    # A name that was replaced while it was pointed is not told.
    "M7": [(WINDOWS, VERDICT, "    let _ = (identity(&named)?, identity(&directory)?);\n    Ok(Pointed::Done)\n")],
    # What is not a junction on the first look is said to be done.
    "M8": [(WINDOWS, FIRST_TAG_CHECK, FIRST_TAG_CHECK.replace("NotAJunction", "Done"))],
    # A junction that cannot be opened to be changed is replaced by a rename.
    "M9": [(WINDOWS, CHANGE_OPEN, CHANGE_OPEN.replace("        Err(error) => return Err(error),\n", "        Err(_) => return Ok(Pointed::NotAJunction),\n"))],
}


def main() -> int:
    name = sys.argv[1]
    for path, old, new in MUTANTS[name]:
        with open(path, encoding="utf-8", newline="") as handle:
            text = handle.read()
        if text.count(old) != 1:
            print(f"MUTATION-ERROR {name}: the text to replace is not there once in {path}")
            return 2
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(text.replace(old, new))
    print(f"MUTATION-APPLIED {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
